"""HTTP API on stdlib http.server. No framework, no wheels to compile.

THREE DISTINCT TRUST DOMAINS, and keeping them apart is the whole security
model of this service:

  1. Agent  (`Authorization: Bearer sk_agent_...`)  -- may SPEND, under limits.
     May never read or write policy, approve a payout, or see another agent.
  2. User   (`Authorization: Bearer sess_...`)      -- the human account holder.
     Sets the limits, funds wallets, approves payouts, creates agents.
  3. Admin  (`X-Admin-Key`)                          -- platform operator.
     Pricing, settlement funding, cross-tenant reads.

An agent token presented to a user-domain route is rejected before any handler
runs: `_user()` only accepts a session token, and sessions are only issued by
password login. That is what makes "the human sets the limits and the agent
merely follows them" an enforced property rather than a convention.
"""
from __future__ import annotations

import json
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import fees as F
from . import users as U
from .bank import Bank, BankError, NotFound, PolicyDenied, _require_secret
from .flutterwave import verify_webhook
from .ledger import LedgerError, InsufficientFunds, DuplicateIdempotencyKey
from .money import MoneyError
from .totp import TotpError

SECRET_HASH = os.environ.get("FLW_SECRET_HASH", "")

STATIC_DIR = Path(__file__).resolve().parent / "static"

# The dashboard holds a live banking session, so the page is locked down rather
# than merely trusted: no external origin may be fetched, no plugin may load,
# and the page may not be framed (clickjacking an "Approve" button is exactly
# the attack that matters here). `unsafe-inline` is present for style/script
# because the dashboard is deliberately one self-contained file with no build
# step -- which is also why there is no third-party origin to allow.
CSP = ("default-src 'none'; "
       "script-src 'self' 'unsafe-inline'; "
       "style-src 'self' 'unsafe-inline'; "
       "connect-src 'self'; "
       "img-src 'self' data:; "
       "base-uri 'none'; "
       "form-action 'none'; "
       "frame-ancestors 'none'")

_ADMIN_KEY: str | None = None


class SessionInvalid(PermissionError):
    """The SESSION token is missing, expired or revoked.

    Distinct from every other 401 because the client must react differently. A
    dashboard treats 401 as "my session died, sign out" -- correct when the
    token is dead, catastrophic when the real meaning was "the password or
    one-time code you just typed was wrong": a single typo in the 2FA field
    would eject the user to the sign-in screen mid-enrolment.

    So the session-level failure gets a machine-readable code of its own and
    everything else stays an ordinary auth failure the page can show inline.
    """

# Read once at import, because this is a deployment-shape assertion rather
# than a per-request decision: either the service is reachable only through a
# proxy or it is not. See Handler._client_ip for why it must be opt-in.
_TRUST_PROXY = os.environ.get("AIBANK_TRUSTED_PROXY", "").strip() in ("1", "true", "yes")


def admin_key() -> str:
    """Fail closed, like FLW_SECRET_HASH already did.

    The old default `"admin-dev-key"` meant a deployment that forgot to set
    this had a publicly known admin credential and no error to warn anyone.
    """
    global _ADMIN_KEY
    if _ADMIN_KEY is None:
        _ADMIN_KEY = _require_secret("AIBANK_ADMIN_KEY", "admin-dev-key")
    return _ADMIN_KEY


def make_handler(bank: Bank):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "aibank/0.2"

        def log_message(self, fmt, *args):
            print(f"[api] {self.address_string()} {fmt % args}")

        # -- plumbing --
        def _send(self, code: int, obj):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)

        def _security_headers(self):
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            # A banking response must never be cached by a proxy or left in a
            # shared browser cache for the next person at the machine.
            self.send_header("Cache-Control", "no-store")

        def _send_static(self, name: str):
            """Serve the dashboard. One fixed allowlist, no path arithmetic.

            Traversal is impossible by construction rather than by sanitising:
            the request path is matched against a dict of known routes, and the
            filename never comes from user input.
            """
            allowed = {"dashboard.html": "text/html; charset=utf-8"}
            ctype = allowed.get(name)
            if ctype is None:
                return self._send(404, {"error": "not found"})
            path = STATIC_DIR / name
            try:
                body = path.read_bytes()
            except OSError:
                return self._send(500, {"error": "dashboard asset missing"})
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)

        def _raw(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            # A body this large is either a mistake or an attempt to exhaust
            # memory on a phone-sized host. Refuse it before reading.
            if n > 1_000_000:
                raise BankError("request body too large")
            return self.rfile.read(n) if n else b""

        def _json(self, raw: bytes) -> dict:
            if not raw:
                return {}
            try:
                parsed = json.loads(raw)
            except ValueError:
                raise BankError("body is not valid JSON")
            if not isinstance(parsed, dict):
                raise BankError("body must be a JSON object")
            return parsed

        def _bearer(self) -> str:
            auth = self.headers.get("Authorization", "")
            return auth[7:].strip() if auth.lower().startswith("bearer ") else ""

        def _client_ip(self) -> str:
            """The address the throttles are keyed on.

            Behind a reverse proxy every connection arrives from the proxy, so
            `client_address` is the SAME value for every user on the internet.
            Keying the per-address login throttle on that would put the whole
            world in one bucket: the first sprayer to trip it would lock out
            every legitimate user, turning our own defence into the outage.

            `X-Forwarded-For` fixes that, and is a header the CLIENT can set,
            so trusting it unconditionally is worse than ignoring it -- an
            attacker would just rotate the header and get an unlimited number
            of fresh buckets, defeating the throttle entirely while also being
            able to frame any address they like in the audit log.

            So it is opt-in: only when the operator asserts
            `AIBANK_TRUSTED_PROXY=1` -- meaning the service is genuinely
            unreachable except through a proxy that OVERWRITES the header (see
            deploy/nginx.conf) -- and even then only the leftmost entry is
            taken, since anything a proxy appends sits to the right of what the
            client sent.
            """
            direct = self.client_address[0] if self.client_address else "?"
            if not _TRUST_PROXY:
                return direct
            fwd = self.headers.get("X-Forwarded-For") or ""
            first = fwd.split(",")[0].strip()
            return first or direct

        def _agent(self) -> str:
            """Authenticate an AGENT. Rejects session tokens by construction."""
            agent_id = bank.authenticate(self._bearer())
            if not agent_id:
                raise PermissionError("invalid or missing agent API key")
            return agent_id

        def _user(self) -> dict:
            """Authenticate a HUMAN via dashboard session."""
            sess = U.authenticate_session(bank, self._bearer())
            if not sess:
                raise SessionInvalid("invalid or expired session")
            return sess

        def _admin(self):
            key = self.headers.get("X-Admin-Key") or ""
            import hmac
            if not hmac.compare_digest(key, admin_key()):
                raise PermissionError("admin key required")

        def _query(self, path: str) -> dict:
            return {k: v[0] for k, v in parse_qs(urlparse(path).query).items()}

        # -- routes --
        def do_GET(self):
            self._route("GET", self.path, b"")

        def do_POST(self):
            self._route("POST", self.path, self._raw())

        def _route(self, method: str, raw_path: str, raw: bytes):
            path = urlparse(raw_path).path
            q = self._query(raw_path)
            try:
                # ---------------- public ----------------
                if path in ("/", "/dashboard") and method == "GET":
                    return self._send_static("dashboard.html")

                if path == "/health":
                    return self._send(200, {"ok": True, "service": "aibank",
                                            "schema": bank.schema_version()})

                if path == "/v1/webhooks/flutterwave" and method == "POST":
                    if not verify_webhook(raw, dict(self.headers), SECRET_HASH):
                        return self._send(401, {"error": "invalid signature"})
                    return self._send(200, bank.handle_webhook(self._json(raw)))

                # ---------------- auth ----------------
                if path == "/v1/auth/register" and method == "POST":
                    b = self._json(raw)
                    return self._send(201, U.create_user(
                        bank, b["email"], b["password"], b.get("display_name")))

                if path == "/v1/auth/login" and method == "POST":
                    b = self._json(raw)
                    out = U.login(
                        bank, b["email"], b["password"], client_ip=self._client_ip(),
                        user_agent=self.headers.get("User-Agent"))
                    # 200 with a challenge rather than 401: the credentials were
                    # correct and the client has a next step to take. A 401 here
                    # would make every client treat a successful password as a
                    # failure.
                    return self._send(200, out)

                if path == "/v1/auth/mfa/verify" and method == "POST":
                    b = self._json(raw)
                    return self._send(200, U.complete_mfa(
                        bank, b["challenge_token"], b["code"],
                        client_ip=self._client_ip(),
                        user_agent=self.headers.get("User-Agent")))

                if path == "/v1/auth/logout" and method == "POST":
                    self._user()
                    return self._send(200, {"logged_out": U.logout(bank, self._bearer())})

                if path == "/v1/auth/password" and method == "POST":
                    s = self._user()
                    b = self._json(raw)
                    U.change_password(bank, s["user_id"], b["current_password"],
                                      b["new_password"])
                    return self._send(200, {"ok": True, "sessions_revoked": True})

                # ------------- second factor (user session + password) -------------
                # Every route here is user-session only, exactly like the policy
                # route: an agent key must not be able to read, enrol, or remove
                # the factor that guards the limits it spends under.
                if path == "/v1/auth/mfa/enrol" and method == "POST":
                    s = self._user()
                    b = self._json(raw)
                    return self._send(200, U.begin_totp_enrolment(
                        bank, s["user_id"], b["current_password"]))

                if path == "/v1/auth/mfa/confirm" and method == "POST":
                    s = self._user()
                    b = self._json(raw)
                    return self._send(200, U.confirm_totp_enrolment(
                        bank, s["user_id"], b["code"]))

                if path == "/v1/auth/mfa" and method == "GET":
                    s = self._user()
                    return self._send(200, {
                        "enabled": U.is_mfa_enrolled(bank, s["user_id"]),
                        "recovery_codes_remaining": U.count_recovery_codes(
                            bank, s["user_id"])})

                if path == "/v1/auth/mfa/disable" and method == "POST":
                    s = self._user()
                    b = self._json(raw)
                    U.disable_totp(bank, s["user_id"], b["current_password"],
                                   b.get("code"))
                    return self._send(200, {"enabled": False,
                                            "sessions_revoked": True})

                if path == "/v1/auth/mfa/recovery-codes" and method == "POST":
                    s = self._user()
                    b = self._json(raw)
                    return self._send(200, {"recovery_codes":
                                            U.regenerate_recovery_codes(
                                                bank, s["user_id"],
                                                b["current_password"])})

                # ---------------- dashboard (user session) ----------------
                if path == "/v1/me" and method == "GET":
                    # Dual-domain by design: an agent key describes the agent,
                    # a session describes the human.
                    if self._bearer().startswith("sess_"):
                        s = self._user()
                        return self._send(200, {"kind": "user",
                                                **(U.get_user(bank, s["user_id"]) or {})})
                    agent_id = self._agent()
                    row = bank.conn.execute(
                        "SELECT id, name, status, user_id FROM agents WHERE id=?",
                        (agent_id,)).fetchone()
                    return self._send(200, {"kind": "agent", **dict(row)})

                if path == "/v1/dashboard" and method == "GET":
                    s = self._user()
                    return self._send(200, bank.dashboard(s["user_id"],
                                                          q.get("currency", "NGN")))

                if path == "/v1/wallet" and method == "GET":
                    s = self._user()
                    return self._send(200, bank.user_balance(
                        s["user_id"], q.get("currency", "NGN")))

                if path == "/v1/wallet/deposit" and method == "POST":
                    # Stand-in for a real collection/virtual-account callback.
                    # Admin-gated precisely because crediting a wallet from
                    # nothing is not something a customer may do for themselves.
                    self._admin()
                    b = self._json(raw)
                    entry = bank.deposit_to_user(
                        b["user_id"], b["amount"], b.get("currency", "NGN"),
                        idempotency_key=b.get("idempotency_key"))
                    return self._send(201, {"entry_id": entry,
                                            "balance": bank.user_balance(
                                                b["user_id"], b.get("currency", "NGN"))})

                if path == "/v1/agents" and method == "GET":
                    s = self._user()
                    return self._send(200, {"agents": bank.list_agents(s["user_id"])})

                if path == "/v1/agents" and method == "POST":
                    # A user creates their OWN agent; admin may create an
                    # unowned one for platform/bootstrap use.
                    b = self._json(raw)
                    if self._bearer().startswith("sess_"):
                        s = self._user()
                        owner = s["user_id"]
                    else:
                        self._admin()
                        owner = b.get("user_id")
                    return self._send(201, bank.create_agent(
                        name=b.get("name", "agent"), currency=b.get("currency", "NGN"),
                        user_id=owner,
                        per_txn_max=b.get("per_txn_max"), daily_max=b.get("daily_max"),
                        monthly_max=b.get("monthly_max"),
                        allowlist_only=bool(b.get("allowlist_only", False)),
                        require_approval_above=b.get("require_approval_above"),
                        max_payouts_per_day=b.get("max_payouts_per_day"),
                        tz_offset_minutes=b.get("tz_offset_minutes")))

                if path.startswith("/v1/agents/"):
                    rest = path[len("/v1/agents/"):].split("/")
                    agent_id = rest[0]
                    tail = rest[1] if len(rest) > 1 else ""
                    s = self._user()
                    bank.require_agent_owner(s["user_id"], agent_id, s["role"])

                    if tail == "policy" and method == "GET":
                        return self._send(200, bank.get_policy(agent_id) or {})

                    if tail == "policy" and method == "POST":
                        # THE central invariant: this route is user-session only.
                        # An agent key cannot reach it, so an agent can never
                        # raise its own ceiling.
                        b = self._json(raw)
                        bank.set_policy(
                            agent_id, currency=b.get("currency", "NGN"),
                            per_txn_max=b.get("per_txn_max"),
                            daily_max=b.get("daily_max"),
                            monthly_max=b.get("monthly_max"),
                            allowlist_only=bool(b.get("allowlist_only", False)),
                            require_approval_above=b.get("require_approval_above"),
                            max_payouts_per_day=b.get("max_payouts_per_day"),
                            tz_name=b.get("tz_name"),
                            tz_offset_minutes=b.get("tz_offset_minutes"),
                            user_id=s["user_id"])
                        return self._send(200, bank.get_policy(agent_id) or {})

                    if tail == "freeze" and method == "POST":
                        b = self._json(raw)
                        return self._send(200, bank.freeze_agent(
                            agent_id, frozen=bool(b.get("frozen", True)),
                            user_id=s["user_id"]))

                    if tail == "allocate" and method == "POST":
                        b = self._json(raw)
                        return self._send(201, bank.allocate_to_agent(
                            s["user_id"], agent_id, b["amount"],
                            b.get("currency", "NGN"),
                            idempotency_key=b.get("idempotency_key")))

                    if tail == "withdraw" and method == "POST":
                        b = self._json(raw)
                        return self._send(201, bank.withdraw_from_agent(
                            s["user_id"], agent_id, b["amount"],
                            b.get("currency", "NGN"),
                            idempotency_key=b.get("idempotency_key")))

                    if tail == "keys" and method == "GET":
                        return self._send(200, {"keys": bank.list_api_keys(agent_id)})

                    if tail == "keys" and method == "POST":
                        b = self._json(raw)
                        if b.get("revoke"):
                            ok = bank.revoke_api_key(agent_id, b["revoke"],
                                                     user_id=s["user_id"])
                            return self._send(200 if ok else 404, {"revoked": ok})
                        return self._send(201, bank.issue_api_key(
                            agent_id, b.get("label"), user_id=s["user_id"]))

                    if tail == "statement" and method == "GET":
                        return self._send(200, bank.statement(
                            agent_id, q.get("currency", "NGN"),
                            limit=int(q.get("limit", 100)),
                            offset=int(q.get("offset", 0))))

                    if tail == "" and method == "GET":
                        return self._send(200, bank.agent_detail(agent_id))

                    return self._send(404, {"error": "not found", "path": path})

                if path == "/v1/approvals" and method == "GET":
                    s = self._user()
                    return self._send(200, {"pending": bank.pending_approvals(s["user_id"])})

                # ---------------- admin ----------------
                if path == "/v1/fund" and method == "POST":
                    self._admin()
                    b = self._json(raw)
                    entry = bank.fund_agent(b["agent_id"], b["amount"],
                                            b.get("currency", "NGN"),
                                            idempotency_key=b.get("idempotency_key"))
                    return self._send(201, {"entry_id": entry,
                                            "balance": bank.balance(
                                                b["agent_id"], b.get("currency", "NGN"))})

                if path == "/v1/fees" and method == "GET":
                    self._admin()
                    return self._send(200, F.get_schedule(bank.conn,
                                                          q.get("currency", "NGN")))

                if path == "/v1/fees" and method == "POST":
                    self._admin()
                    b = self._json(raw)
                    with bank.db.write() as conn:
                        F.set_schedule(conn, b.get("currency", "NGN"),
                                       flat_minor=int(b.get("flat_minor", 0)),
                                       bps=int(b.get("bps", 0)),
                                       min_minor=int(b.get("min_minor", 0)),
                                       cap_minor=b.get("cap_minor"))
                    return self._send(200, F.get_schedule(bank.conn,
                                                          b.get("currency", "NGN")))

                if path == "/v1/admin/sweep-holds" and method == "POST":
                    self._admin()
                    return self._send(200, bank.sweep_expired_holds())

                if path == "/v1/admin/trial-balance" and method == "GET":
                    self._admin()
                    return self._send(200, bank.trial_balance(q.get("currency")))

                # ---------------- agent-facing ----------------
                if path.startswith("/v1/balance") and method == "GET":
                    agent_id = self._agent()
                    return self._send(200, bank.balance(agent_id,
                                                        q.get("currency", "NGN")))

                if path == "/v1/payees" and method == "GET":
                    agent_id = self._agent()
                    return self._send(200, {"payees": bank.list_payees(agent_id)})

                if path == "/v1/payees" and method == "POST":
                    agent_id = self._agent()
                    b = self._json(raw)
                    pid = bank.add_payee(agent_id, b["label"], b["bank_code"],
                                         b["account_number"], b.get("currency", "NGN"))
                    return self._send(201, {"payee_id": pid})

                if path == "/v1/quote" and method == "GET":
                    agent_id = self._agent()
                    cur = q.get("currency", "NGN")
                    from .money import to_minor
                    minor = to_minor(q.get("amount", "0"), cur)
                    fee = F.quote(bank.conn, minor, cur)
                    return self._send(200, {"amount_minor": minor, "fee_minor": fee,
                                            "total_minor": minor + fee,
                                            "currency": cur})

                if path == "/v1/payouts" and method == "POST":
                    agent_id = self._agent()
                    b = self._json(raw)
                    idem = self.headers.get("Idempotency-Key") or b.get("idempotency_key")
                    out = bank.request_payout(
                        agent_id, b["amount"], b.get("currency", "NGN"),
                        payee_id=b.get("payee_id"), bank_code=b.get("bank_code"),
                        account_number=b.get("account_number"),
                        narration=b.get("narration", ""),
                        idempotency_key=idem)
                    return self._send(201, out)

                if path == "/v1/payouts" and method == "GET":
                    # Scoped by whichever credential was presented.
                    if self._bearer().startswith("sess_"):
                        s = self._user()
                        rows = bank.list_payouts(user_id=s["user_id"],
                                                 status=q.get("status"),
                                                 limit=int(q.get("limit", 50)),
                                                 offset=int(q.get("offset", 0)))
                    else:
                        agent_id = self._agent()
                        rows = bank.list_payouts(agent_id=agent_id,
                                                 status=q.get("status"),
                                                 limit=int(q.get("limit", 50)),
                                                 offset=int(q.get("offset", 0)))
                    return self._send(200, {"payouts": rows})

                if path.startswith("/v1/payouts/"):
                    rest = path[len("/v1/payouts/"):].split("/")
                    payout_id = rest[0]
                    tail = rest[1] if len(rest) > 1 else ""

                    # Human decisions: session only. An agent approving its own
                    # payout would void the approval threshold entirely.
                    if tail in ("approve", "reject", "refund") and method == "POST":
                        s = self._user()
                        bank.get_payout(payout_id, user_id=s["user_id"])  # ownership
                        b = self._json(raw)
                        if tail == "approve":
                            return self._send(200, bank.approve_payout(
                                payout_id, narration=b.get("narration", ""),
                                user_id=s["user_id"], reason=b.get("reason")))
                        if tail == "reject":
                            return self._send(200, bank.reject_payout(
                                payout_id, user_id=s["user_id"],
                                reason=b.get("reason", "rejected by account holder")))
                        return self._send(200, bank.refund_payout(
                            payout_id, user_id=s["user_id"],
                            reason=b.get("reason", "refund")))

                    if tail == "reconcile" and method == "POST":
                        s = self._user()
                        bank.get_payout(payout_id, user_id=s["user_id"])
                        return self._send(200, bank.reconcile(payout_id))

                    if tail == "" and method == "GET":
                        # TIER 1 FIX: scope the read. Previously any agent key
                        # could fetch any agent's payout by id.
                        if self._bearer().startswith("sess_"):
                            s = self._user()
                            return self._send(200, bank.get_payout(
                                payout_id, user_id=s["user_id"]))
                        agent_id = self._agent()
                        return self._send(200, bank.get_payout(
                            payout_id, agent_id=agent_id))

                return self._send(404, {"error": "not found", "path": path})

            except SessionInvalid as exc:
                # Checked BEFORE PermissionError, which it subclasses. The
                # stable code is what lets the dashboard sign the user out on a
                # dead session without doing so for a mistyped one-time code.
                self._send(401, {"error": "session_invalid", "reason": str(exc)})
            except PermissionError as exc:
                self._send(401, {"error": str(exc)})
            except U.LockedOut as exc:
                self._send(429, {"error": "locked_out", "reason": str(exc)})
            except U.AuthError as exc:
                self._send(401, {"error": "auth_failed", "reason": str(exc)})
            except TotpError as exc:
                # Reaching here means a SEALED SECRET would not open: the key
                # pepper changed, or a row was edited outside the application.
                # That is an operator fault, not a user one, so it must not be
                # reported as "invalid code" -- that would send the user round
                # a retry loop that can never succeed. Detail is logged, not
                # returned.
                print(f"[api] SEAL FAILURE: {exc}")
                self._send(500, {"error": "mfa_unavailable",
                                 "reason": "the second-factor secret could not be "
                                           "read; check AIBANK_KEY_PEPPER"})
            except NotFound as exc:
                self._send(404, {"error": "not_found", "reason": str(exc)})
            except PolicyDenied as exc:
                self._send(403, {"error": "policy_denied", "reason": str(exc)})
            except InsufficientFunds as exc:
                self._send(402, {"error": "insufficient_funds", "reason": str(exc)})
            except DuplicateIdempotencyKey as exc:
                self._send(409, {"error": "duplicate", "entry_id": exc.existing_entry_id})
            except (MoneyError, LedgerError, BankError, ValueError) as exc:
                self._send(400, {"error": type(exc).__name__, "reason": str(exc)})
            except KeyError as exc:
                # A missing required field used to surface as
                # {"error": "KeyError", "reason": "'user_id'"} -- a Python
                # exception class name and a quoted dict key, which tells an
                # integrator nothing about what to send. Under a self-hosted
                # shape the HTTP surface IS the product's documentation, so a
                # 400 has to name the field in words.
                field = exc.args[0] if exc.args else "?"
                self._send(400, {"error": "missing_field",
                                 "reason": f"required field missing: {field}",
                                 "field": field})
            except Exception as exc:  # noqa: BLE001
                # Log the detail, return none of it: a stack-trace string in a
                # response body is a free schema disclosure.
                traceback.print_exc()
                self._send(500, {"error": "internal"})

    return Handler


def serve(db_path: str = "aibank.db", host: str = "127.0.0.1", port: int = 8000):
    # migrate_on_open=False: the service must NEVER alter a production schema
    # as a side effect of a deploy. Starting a new binary against an old
    # database is exactly when an unreviewed, unbacked-up ALTER is most
    # dangerous, so it refuses to boot and names the command instead. `python
    # -m aibank.cli migrate` is the deliberate, auditable upgrade step.
    bank = Bank(db_path, migrate_on_open=False)
    admin_key()  # fail fast at boot rather than on the first admin request
    httpd = ThreadingHTTPServer((host, port), make_handler(bank))
    print(f"aibank listening on http://{host}:{port}  (db={db_path})")
    print(f"  dashboard: http://{host}:{port}/")
    if host not in ("127.0.0.1", "localhost", "::1"):
        # The dashboard posts a password and carries a session token. Over
        # plain HTTP on a routable interface both are readable on the wire.
        print("  WARNING: bound to a non-loopback address over plain HTTP. "
              "Put a TLS-terminating reverse proxy in front of this before "
              "anyone signs in from another machine.")
    httpd.serve_forever()


if __name__ == "__main__":
    serve(os.environ.get("AIBANK_DB", "aibank.db"),
          os.environ.get("AIBANK_HOST", "127.0.0.1"),
          int(os.environ.get("AIBANK_PORT", "8000")))
