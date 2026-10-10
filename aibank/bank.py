"""The Bank service: agents, keys, funding, payouts, webhooks.

Payout lifecycle (the part that makes this safe for autonomous agents):

  request -> policy check -> HOLD funds -> submit to Flutterwave
          -> webhook says SUCCESSFUL -> capture hold + post ledger entry
          -> webhook says FAILED     -> release hold, money never left

The hold is what stops a looping agent from spending the same naira twice
while the provider is still thinking.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone

from . import fees as F
from . import ledger as L
from . import policy as P
from . import users as U
from .db import Database
from .flutterwave import FlutterwaveClient, FlutterwaveError, dedupe_key
from .money import check_currency, to_major, to_minor

# A working default for a secret is a production vulnerability with a friendly
# face: the service boots, every test passes, and the pepper protecting every
# API key hash is a string published in this file. `FLW_SECRET_HASH` already
# failed closed; these now match it.
DEV_FALLBACK = os.environ.get("AIBANK_ALLOW_DEV_SECRETS") == "1"


def _require_secret(name: str, dev_value: str) -> str:
    v = os.environ.get(name)
    if v:
        return v
    if DEV_FALLBACK:
        return dev_value
    raise RuntimeError(
        f"{name} is not set. Set it, or export AIBANK_ALLOW_DEV_SECRETS=1 for"
        " local development only -- never in production.")


# Read lazily so importing the module (e.g. to run `--help`) does not explode.
_PEPPER: str | None = None


def key_pepper() -> str:
    global _PEPPER
    if _PEPPER is None:
        _PEPPER = _require_secret("AIBANK_KEY_PEPPER", "dev-pepper-change-me")
    return _PEPPER


# How long a hold survives without a provider callback before the sweeper
# releases it. Funds must not be hostage to a webhook that never arrives.
HOLD_TTL_MINUTES = int(os.environ.get("AIBANK_HOLD_TTL_MINUTES", 120))


def hash_key(plaintext: str) -> str:
    return hashlib.sha256((key_pepper() + plaintext).encode()).hexdigest()


class BankError(Exception):
    pass


class PolicyDenied(BankError):
    pass


class NotFound(BankError):
    """Requested object does not exist, or does not belong to the caller.

    Deliberately one class for both cases: telling an attacker apart
    "no such payout" from "someone else's payout" is itself a disclosure.
    """


def _mask_account(num: str | None) -> str | None:
    """Last four digits only. Full account numbers are not display data.

    `get_payout` and the dashboard return these rows to a browser and into
    logs; a complete account number in that path is a disclosure with no
    upside, since nothing in the UI needs more than enough to recognise it.
    """
    if not num:
        return None
    s = str(num)
    return ("*" * max(0, len(s) - 4)) + s[-4:]


def _payout_view(row, currency: str | None = None) -> dict:
    """The API representation of a payout row."""
    d = dict(row)
    cur = currency or d.get("currency") or "NGN"
    d["amount"] = to_major(d["amount_minor"], cur)
    d["fee"] = to_major(d["fee_minor"], cur)
    acct = d.pop("dest_account_number", None)
    d["destination"] = _mask_account(acct)
    return d


class Bank:
    def __init__(self, db_path: str = "aibank.db", flw: FlutterwaveClient | None = None,
                 callback_url: str | None = None, migrate_on_open: bool = True):
        self.db = Database(db_path, migrate_on_open=migrate_on_open)
        self.flw = flw or FlutterwaveClient()
        self.callback_url = callback_url or os.environ.get("AIBANK_CALLBACK_URL")

    @property
    def conn(self):
        """Per-thread connection -- safe under the threaded HTTP server."""
        return self.db.conn

    def write(self):
        """Expose the write transaction so Bank satisfies the same minimal
        interface as Database (`.conn` + `.write()`).

        The `users` module is written against that interface, which lets both
        `users.login(bank, ...)` and `users.login(database, ...)` work. Without
        this, callers would have to know whether they hold a Bank or a Database
        and reach into `.db` accordingly -- a distinction nothing outside this
        class should care about.
        """
        return self.db.write()

    def close(self):
        return self.db.close()

    # ---------- agents & auth ----------
    def create_agent(self, name: str, currency: str = "NGN", user_id: str | None = None,
                     **policy_kwargs) -> dict:
        """Create an agent owned by a human.

        `user_id` is optional ONLY so the admin path and the existing tests can
        still mint an unowned agent. In the dashboard model every agent has an
        owner, and `policy.evaluate` checks that owner's status on every spend.
        """
        currency = check_currency(currency)
        if user_id is not None and U.get_user(self, user_id) is None:
            raise NotFound("unknown user")
        agent_id = L.new_id("agent")
        raw_key = "sk_agent_" + secrets.token_urlsafe(32)
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO agents (id, name, status, user_id, created_at)"
                " VALUES (?,?,'active',?,?)",
                (agent_id, name, user_id, L.now_iso()),
            )
            wallet = L.get_or_create_account(conn, agent_id, "agent_wallet", currency)
            conn.execute(
                "INSERT INTO api_keys (id, agent_id, key_prefix, key_hash, label, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (L.new_id("key"), agent_id, raw_key[:16], hash_key(raw_key),
                 "initial", L.now_iso()),
            )
            L.audit(conn, agent_id, "agent.create", "ok", {"name": name}, user_id=user_id)
            self._write_policy(conn, agent_id, currency=currency, **policy_kwargs)
        return {"agent_id": agent_id, "name": name, "wallet_account_id": wallet,
                "currency": currency, "user_id": user_id, "api_key": raw_key}

    def authenticate(self, api_key: str) -> str | None:
        row = self.conn.execute(
            "SELECT agent_id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
            (hash_key(api_key or ""),),
        ).fetchone()
        return row["agent_id"] if row else None

    def owns_agent(self, user_id: str, agent_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM agents WHERE id = ? AND user_id = ?",
            (agent_id, user_id)).fetchone()
        return row is not None

    def require_agent_owner(self, user_id: str, agent_id: str, role: str = "user") -> None:
        """Authorise a dashboard action on an agent. Admins bypass ownership."""
        if role == "admin":
            if self.conn.execute("SELECT 1 FROM agents WHERE id=?", (agent_id,)).fetchone():
                return
            raise NotFound("unknown agent")
        if not self.owns_agent(user_id, agent_id):
            raise NotFound("unknown agent")

    def list_agents(self, user_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, name, status, created_at FROM agents WHERE user_id = ?"
            " ORDER BY created_at", (user_id,)).fetchall()
        return [dict(r) for r in rows]

    def issue_api_key(self, agent_id: str, label: str | None = None,
                      user_id: str | None = None) -> dict:
        raw_key = "sk_agent_" + secrets.token_urlsafe(32)
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO api_keys (id, agent_id, key_prefix, key_hash, label, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (L.new_id("key"), agent_id, raw_key[:16], hash_key(raw_key),
                 label, L.now_iso()))
            L.audit(conn, agent_id, "api_key.issue", "ok", {"label": label},
                    user_id=user_id)
        return {"api_key": raw_key, "key_prefix": raw_key[:16], "label": label}

    def revoke_api_key(self, agent_id: str, key_prefix: str,
                       user_id: str | None = None) -> bool:
        """Rotation needs a revoke path: `revoked_at` was never written before,
        so a leaked key stayed valid for the lifetime of the agent."""
        with self.db.write() as conn:
            cur = conn.execute(
                "UPDATE api_keys SET revoked_at=? WHERE agent_id=? AND key_prefix=?"
                " AND revoked_at IS NULL", (L.now_iso(), agent_id, key_prefix))
            L.audit(conn, agent_id, "api_key.revoke",
                    "ok" if cur.rowcount else "not_found",
                    {"key_prefix": key_prefix}, user_id=user_id)
            return cur.rowcount > 0

    def list_api_keys(self, agent_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT key_prefix, label, created_at, revoked_at FROM api_keys"
            " WHERE agent_id=? ORDER BY created_at", (agent_id,)).fetchall()
        return [dict(r) for r in rows]

    def freeze_agent(self, agent_id: str, frozen: bool = True,
                     user_id: str | None = None) -> dict:
        with self.db.write() as conn:
            cur = conn.execute("UPDATE agents SET status = ? WHERE id = ?",
                               ("frozen" if frozen else "active", agent_id))
            if cur.rowcount == 0:
                raise NotFound("unknown agent")
            L.audit(conn, agent_id, "agent.freeze", str(frozen), None, user_id=user_id)
        return {"agent_id": agent_id, "status": "frozen" if frozen else "active"}

    def _write_policy(self, conn, agent_id: str, currency: str = "NGN", per_txn_max=None,
                      daily_max=None, monthly_max=None, allowlist_only: bool = False,
                      require_approval_above=None, tz_name: str | None = None,
                      tz_offset_minutes: int | None = None,
                      max_payouts_per_day=None, user_id: str | None = None) -> None:
        currency = check_currency(currency)
        conv = lambda v: None if v is None else to_minor(v, currency)
        existing = P.get_policy(conn, agent_id)
        tz_name = tz_name or (existing["tz_name"] if existing else "Africa/Lagos")
        if tz_offset_minutes is None:
            tz_offset_minutes = existing["tz_offset_minutes"] if existing else 60
        conn.execute(
            "INSERT INTO policies (agent_id, currency, per_txn_max_minor, daily_max_minor,"
            " monthly_max_minor, allowlist_only, require_approval_above_minor,"
            " tz_name, tz_offset_minutes, max_payouts_per_day, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET"
            " currency=excluded.currency, per_txn_max_minor=excluded.per_txn_max_minor,"
            " daily_max_minor=excluded.daily_max_minor,"
            " monthly_max_minor=excluded.monthly_max_minor,"
            " allowlist_only=excluded.allowlist_only,"
            " require_approval_above_minor=excluded.require_approval_above_minor,"
            " tz_name=excluded.tz_name, tz_offset_minutes=excluded.tz_offset_minutes,"
            " max_payouts_per_day=excluded.max_payouts_per_day,"
            " updated_at=excluded.updated_at",
            (agent_id, currency, conv(per_txn_max), conv(daily_max), conv(monthly_max),
             1 if allowlist_only else 0, conv(require_approval_above),
             tz_name, int(tz_offset_minutes),
             None if max_payouts_per_day is None else int(max_payouts_per_day),
             L.now_iso()),
        )
        L.audit(conn, agent_id, "policy.set", "ok",
                {"currency": currency, "per_txn_max": str(per_txn_max),
                 "daily_max": str(daily_max), "monthly_max": str(monthly_max),
                 "allowlist_only": allowlist_only,
                 "require_approval_above": str(require_approval_above),
                 "max_payouts_per_day": max_payouts_per_day}, user_id=user_id)

    def set_policy(self, agent_id: str, currency: str = "NGN", **kw) -> None:
        """Write an agent's spend limits.

        NOT reachable with an agent API key -- only an authenticated dashboard
        user (or admin) routes here. That is the invariant the whole design
        rests on: the spender cannot raise its own ceiling.
        """
        with self.db.write() as conn:
            self._write_policy(conn, agent_id, currency=currency, **kw)

    def get_policy(self, agent_id: str) -> dict | None:
        """An agent's limits, in BOTH minor units and decimal major units.

        The stored columns are `*_minor` integers, which is correct for the
        ledger and wrong for a form: a dashboard reading `per_txn_max` got
        `undefined` and rendered a configured ceiling as an empty field -- i.e.
        as "no limit". Saving that form back would then erase the limit the
        human had set, which is a silent widening of the agent's authority.

        So the API representation carries both: `*_minor` for exactness, and
        the decimal string for display. `None` means that particular ceiling
        is not checked -- NOT that the agent is unlimited, since an agent with
        no ceiling and no approval threshold is denied outright by
        `policy.evaluate`.
        """
        row = P.get_policy(self.conn, agent_id)
        if not row:
            return None
        d = dict(row)
        cur = d.get("currency") or "NGN"
        for field in ("per_txn_max", "daily_max", "monthly_max",
                      "require_approval_above"):
            minor = d.get(field + "_minor")
            d[field] = None if minor is None else to_major(minor, cur)
        return d

    def wallet_id(self, agent_id: str, currency: str = "NGN") -> str:
        return L.get_or_create_account(self.conn, agent_id, "agent_wallet", currency)

    def add_payee(self, agent_id: str, label: str, bank_code: str,
                  account_number: str, currency: str = "NGN") -> str:
        """Register a payout destination, idempotently.

        The same (agent, bank, account, currency) is the SAME payee, so
        re-registering it returns the existing id rather than failing. It used
        to raise `sqlite3.IntegrityError` straight through the handler as a
        bare HTTP 500 "internal", which is wrong three ways: a retry is normal
        agent behaviour (the first response can be lost exactly as a payout's
        can), a 500 invites the caller to retry a request that will never
        succeed, and it leaks a schema detail as an unhandled crash. Same
        refusal-to-punish-a-retry as the payout idempotency path.

        The label is NOT part of the identity -- the money lands on the account
        number, so two labels for one account must not create two payees that
        policy allowlists would then have to track separately.
        """
        currency = check_currency(currency)
        payee_id = L.new_id("payee")
        with self.db.write() as conn:
            try:
                conn.execute(
                    "INSERT INTO payees (id, agent_id, label, bank_code,"
                    " account_number, currency, created_at) VALUES (?,?,?,?,?,?,?)",
                    (payee_id, agent_id, label, bank_code, account_number,
                     currency, L.now_iso()),
                )
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT id FROM payees WHERE agent_id=? AND bank_code=?"
                    " AND account_number=? AND currency=?",
                    (agent_id, bank_code, account_number, currency)).fetchone()
                if row is None:
                    raise
                return row["id"]
        return payee_id

    def list_payees(self, agent_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, label, bank_code, account_number, currency, created_at"
            " FROM payees WHERE agent_id=? ORDER BY created_at", (agent_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---------- balances ----------
    def balance(self, agent_id: str, currency: str = "NGN") -> dict:
        acct = self.wallet_id(agent_id, currency)
        bal, hold = L.balance(self.conn, acct), L.held(self.conn, acct)
        return {"currency": currency, "balance_minor": bal, "held_minor": hold,
                "available_minor": bal - hold, "balance": to_major(bal, currency),
                "held": to_major(hold, currency), "available": to_major(bal - hold, currency)}

    def user_balance(self, user_id: str, currency: str = "NGN") -> dict:
        currency = check_currency(currency)
        with self.db.write() as conn:
            acct = L.user_wallet(conn, user_id, currency)
        bal, hold = L.balance(self.conn, acct), L.held(self.conn, acct)
        return {"currency": currency, "balance_minor": bal, "held_minor": hold,
                "available_minor": bal - hold, "balance": to_major(bal, currency),
                "available": to_major(bal - hold, currency)}

    def deposit_to_user(self, user_id: str, amount, currency: str = "NGN",
                        memo: str = "deposit", idempotency_key: str | None = None) -> str:
        """Money arriving from the outside world into a human's wallet.

        This is the top of the funnel the old design was missing: funds used to
        appear in agent wallets out of the settlement account with no record of
        which human they belonged to.
        """
        currency = check_currency(currency)
        minor = to_minor(amount, currency)
        if minor <= 0:
            raise BankError("deposit amount must be positive")
        with self.db.write() as conn:
            wallet = L.user_wallet(conn, user_id, currency)
            settle = L.get_or_create_account(conn, None, "flw_settlement", currency)
            entry = L.post_entry(
                conn, "deposit", [(wallet, minor), (settle, -minor)], currency,
                memo=memo, idempotency_key=idempotency_key)
            L.audit(conn, None, "wallet.deposit", "ok",
                    {"amount_minor": minor, "currency": currency}, user_id=user_id)
        return entry

    def allocate_to_agent(self, user_id: str, agent_id: str, amount,
                          currency: str = "NGN",
                          idempotency_key: str | None = None) -> dict:
        """Move the human's own money into one of their agents' wallets.

        Enforces two things the old `fund_agent` could not: the money comes out
        of a real user balance (so an agent cannot be funded from nothing), and
        the agent must belong to this user.
        """
        currency = check_currency(currency)
        minor = to_minor(amount, currency)
        if minor <= 0:
            raise BankError("allocation amount must be positive")
        if not self.owns_agent(user_id, agent_id):
            raise NotFound("unknown agent")
        with self.db.write() as conn:
            src = L.user_wallet(conn, user_id, currency)
            avail = L.available(conn, src)
            if avail < minor:
                raise L.InsufficientFunds(avail, minor, currency)
            dst = L.get_or_create_account(conn, agent_id, "agent_wallet", currency)
            entry = L.post_entry(
                conn, "allocation", [(dst, minor), (src, -minor)], currency,
                agent_id=agent_id, memo="funded from user wallet",
                idempotency_key=idempotency_key)
            L.audit(conn, agent_id, "wallet.allocate", "ok",
                    {"amount_minor": minor}, user_id=user_id)
        return {"entry_id": entry, "agent_balance": self.balance(agent_id, currency),
                "user_balance": self.user_balance(user_id, currency)}

    def withdraw_from_agent(self, user_id: str, agent_id: str, amount,
                            currency: str = "NGN",
                            idempotency_key: str | None = None) -> dict:
        """Pull unspent money back out of an agent. The reverse of allocate."""
        currency = check_currency(currency)
        minor = to_minor(amount, currency)
        if minor <= 0:
            raise BankError("withdrawal amount must be positive")
        if not self.owns_agent(user_id, agent_id):
            raise NotFound("unknown agent")
        with self.db.write() as conn:
            src = L.get_or_create_account(conn, agent_id, "agent_wallet", currency)
            avail = L.available(conn, src)
            if avail < minor:
                raise L.InsufficientFunds(avail, minor, currency)
            dst = L.user_wallet(conn, user_id, currency)
            entry = L.post_entry(
                conn, "withdrawal", [(dst, minor), (src, -minor)], currency,
                agent_id=agent_id, memo="returned to user wallet",
                idempotency_key=idempotency_key)
            L.audit(conn, agent_id, "wallet.withdraw", "ok",
                    {"amount_minor": minor}, user_id=user_id)
        return {"entry_id": entry, "agent_balance": self.balance(agent_id, currency),
                "user_balance": self.user_balance(user_id, currency)}

    def fund_agent(self, agent_id: str, amount, currency: str = "NGN",
                   memo: str = "funding", idempotency_key: str | None = None) -> str:
        """Admin-only top-up straight from settlement into an agent wallet.

        Retained for the admin/bootstrap path. The customer-facing flow is
        deposit_to_user -> allocate_to_agent, which keeps the human's ownership
        of the money on the books.
        """
        currency = check_currency(currency)
        minor = to_minor(amount, currency)
        if minor <= 0:
            raise BankError("funding amount must be positive")
        with self.db.write() as conn:
            wallet = L.get_or_create_account(conn, agent_id, "agent_wallet", currency)
            settle = L.get_or_create_account(conn, None, "flw_settlement", currency)
            # Debit the agent wallet (value in), credit settlement (value out).
            entry = L.post_entry(
                conn, "funding", [(wallet, minor), (settle, -minor)], currency,
                agent_id=agent_id, memo=memo, idempotency_key=idempotency_key,
            )
            L.audit(conn, agent_id, "wallet.fund", "ok", {"amount_minor": minor})
        return entry

    # ---------- payouts ----------
    def request_payout(self, agent_id: str, amount, currency: str = "NGN",
                       payee_id: str | None = None, bank_code: str | None = None,
                       account_number: str | None = None, narration: str = "",
                       fee=None, idempotency_key: str | None = None,
                       submit: bool = True) -> dict:
        currency = check_currency(currency)
        minor = to_minor(amount, currency)
        # The `fee` argument is accepted and IGNORED: it used to be whatever the
        # agent put in the body, which let the spender set our revenue to zero.
        # Pricing comes from the server-side schedule now.
        fee_minor = F.quote(self.conn, minor, currency)

        # Idempotency keys are scoped PER AGENT. A global namespace would let one
        # agent's key collide with another's -- returning someone else's payout.
        scoped_ref = f"ref_{agent_id[-12:]}_{idempotency_key}" if idempotency_key else None
        if scoped_ref:
            prior = self.conn.execute(
                "SELECT id FROM payouts WHERE reference = ? AND agent_id = ?",
                (scoped_ref, agent_id),
            ).fetchone()
            if prior:
                return self.get_payout(prior["id"], agent_id=agent_id)

        if payee_id:
            payee = self.conn.execute(
                "SELECT * FROM payees WHERE id = ? AND agent_id = ?", (payee_id, agent_id)
            ).fetchone()
            if not payee:
                raise PolicyDenied("payee does not belong to this agent")
            bank_code, account_number = payee["bank_code"], payee["account_number"]
        if not (bank_code and account_number):
            raise BankError("need payee_id or bank_code + account_number")

        # Policy check and the hold it authorises must be ONE atomic step, or two
        # concurrent requests could each pass the check and together overspend.
        payout_id = L.new_id("payout")
        try:
            with self.db.write() as conn:
                decision = P.evaluate(conn, agent_id, minor, fee_minor, currency, payee_id)
                if not decision.allowed:
                    L.audit(conn, agent_id, "payout.request", "denied",
                            {"reason": decision.reason, "amount_minor": minor})
                    raise PolicyDenied(decision.reason)

                wallet = L.get_or_create_account(conn, agent_id, "agent_wallet", currency)
                hold_id = L.place_hold(conn, agent_id, wallet, minor + fee_minor, currency,
                                       ttl_minutes=HOLD_TTL_MINUTES)

                reference = scoped_ref or f"aibank_{payout_id[-16:]}"
                status = "pending_approval" if decision.requires_approval else "submitted"
                ts = L.now_iso()
                conn.execute(
                    "INSERT INTO payouts (id, agent_id, payee_id, amount_minor, fee_minor,"
                    " currency, status, reference, hold_id, narration,"
                    " dest_bank_code, dest_account_number, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (payout_id, agent_id, payee_id, minor, fee_minor, currency, status,
                     reference, hold_id, narration or None,
                     bank_code, account_number, ts, ts),
                )
                L.audit(conn, agent_id, "payout.request", status,
                        {"payout_id": payout_id, "amount_minor": minor,
                         "fee_minor": fee_minor})
        except sqlite3.IntegrityError as exc:
            # Two concurrent requests carrying the SAME idempotency key: the
            # pre-check above found nothing for either, then one lost the UNIQUE
            # race on `reference`. The caller asked for one payout and there IS
            # one -- return it, instead of leaking a raw IntegrityError as a 500
            # and inviting a retry that could double-pay.
            if scoped_ref and "reference" in str(exc):
                prior = self.conn.execute(
                    "SELECT id FROM payouts WHERE reference = ? AND agent_id = ?",
                    (scoped_ref, agent_id)).fetchone()
                if prior:
                    return self.get_payout(prior["id"], agent_id=agent_id)
            raise

        # Network call happens AFTER commit -- never hold a DB write lock across I/O.
        if decision.requires_approval or not submit:
            return self.get_payout(payout_id, agent_id=agent_id)
        return self._submit(payout_id, bank_code, account_number, narration)

    def approve_payout(self, payout_id: str, narration: str = "",
                       user_id: str | None = None, reason: str | None = None) -> dict:
        """A human releases a payout that tripped the approval threshold.

        Only reachable from a dashboard session, never with an agent key: an
        agent that could approve its own held payouts would make the approval
        threshold meaningless.
        """
        p = self.conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
        if not p:
            raise NotFound("unknown payout")
        if p["status"] != "pending_approval":
            raise BankError(f"payout is {p['status']}, not awaiting approval")

        # The destination is read from the PAYOUT, not re-resolved from the
        # payee. Two reasons, both found the hard way:
        #   1. A payout to a raw bank_code/account_number has no payee row, so
        #      the old join returned nothing and the human could not approve it
        #      at all -- the money stayed held with no route forward.
        #   2. Even with a payee, re-resolving means the destination can CHANGE
        #      between request and approval (the agent edits the payee while the
        #      payment waits), so the human would approve one destination and
        #      the money would go to another. Pinning it at request time makes
        #      the approval mean what it says.
        bank_code = p["dest_bank_code"]
        account_number = p["dest_account_number"]
        if not (bank_code and account_number):
            # Pre-v3 rows with neither a destination nor a payee.
            payee = self.conn.execute(
                "SELECT * FROM payees WHERE id = ?", (p["payee_id"],)).fetchone()
            if not payee:
                raise BankError("payout has no recorded destination to send to")
            bank_code, account_number = payee["bank_code"], payee["account_number"]
        with self.db.write() as conn:
            conn.execute(
                "UPDATE payouts SET approved_by=?, approved_at=?, decided_reason=?,"
                " updated_at=? WHERE id=?",
                (user_id, L.now_iso(), reason, L.now_iso(), payout_id))
            L.audit(conn, p["agent_id"], "payout.approve", "ok",
                    {"payout_id": payout_id}, user_id=user_id)
        return self._submit(payout_id, bank_code, account_number,
                            narration or p["narration"] or "")

    def reject_payout(self, payout_id: str, user_id: str | None = None,
                      reason: str = "rejected by account holder") -> dict:
        """Refuse a held payout and give the money back to available spend."""
        with self.db.write() as conn:
            p = conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
            if not p:
                raise NotFound("unknown payout")
            if p["status"] != "pending_approval":
                raise BankError(f"payout is {p['status']}, not awaiting approval")
            L.release_hold(conn, p["hold_id"])
            conn.execute(
                "UPDATE payouts SET status='rejected', decided_reason=?, approved_by=?,"
                " approved_at=?, updated_at=? WHERE id=?",
                (reason, user_id, L.now_iso(), L.now_iso(), payout_id))
            L.audit(conn, p["agent_id"], "payout.reject", reason,
                    {"payout_id": payout_id}, user_id=user_id)
        return self.get_payout(payout_id)

    def pending_approvals(self, user_id: str) -> list[dict]:
        """Everything waiting on this human's decision, across all their agents."""
        rows = self.conn.execute(
            "SELECT p.*, a.name AS agent_name FROM payouts p"
            " JOIN agents a ON a.id = p.agent_id"
            " WHERE a.user_id = ? AND p.status = 'pending_approval'"
            " ORDER BY p.created_at", (user_id,)).fetchall()
        return [_payout_view(r) for r in rows]

    def refund_payout(self, payout_id: str, user_id: str | None = None,
                      reason: str = "refund") -> dict:
        """Reverse a SETTLED payout on the books.

        This does not claw money back from the beneficiary -- nothing can. It
        records the correction as a reversing entry so the ledger reflects that
        the money came back (e.g. the bank returned it), rather than editing
        history.
        """
        with self.db.write() as conn:
            p = conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
            if not p:
                raise NotFound("unknown payout")
            if p["status"] != "successful":
                raise BankError(f"only a successful payout can be refunded (is {p['status']})")
            orig = conn.execute(
                "SELECT id FROM entries WHERE reference = ? AND kind = 'payout'",
                (p["reference"],)).fetchone()
            if not orig:
                raise BankError("payout has no settled ledger entry to reverse")
            rev = L.reverse_entry(conn, orig["id"], memo=f"refund of {payout_id}")
            conn.execute(
                "UPDATE payouts SET status='refunded', decided_reason=?, updated_at=?"
                " WHERE id=?", (reason, L.now_iso(), payout_id))
            L.audit(conn, p["agent_id"], "payout.refund", "ok",
                    {"payout_id": payout_id, "reversal_entry": rev}, user_id=user_id)
        return self.get_payout(payout_id)

    def sweep_expired_holds(self) -> dict:
        """Release holds whose provider callback never arrived.

        Without this a lost webhook freezes the agent's money permanently. The
        sweeper only releases the HOLD; the payout is marked for reconciliation
        rather than declared failed, because we genuinely do not know whether
        the provider moved the money. Deciding "failed" here could release funds
        that actually left.
        """
        released, flagged = 0, []
        with self.db.write() as conn:
            for h in L.expired_holds(conn):
                p = conn.execute(
                    "SELECT id, status FROM payouts WHERE hold_id = ?", (h["id"],)).fetchone()
                if p and p["status"] in ("successful", "failed", "rejected", "refunded"):
                    continue
                L.release_hold(conn, h["id"])
                released += 1
                if p:
                    conn.execute(
                        "UPDATE payouts SET failure_reason=?, updated_at=? WHERE id=?",
                        ("hold expired without provider callback; needs reconciliation",
                         L.now_iso(), p["id"]))
                    flagged.append(p["id"])
                L.audit(conn, h["agent_id"], "hold.expired", "released",
                        {"hold_id": h["id"], "amount_minor": h["amount_minor"]})
        return {"released": released, "needs_reconciliation": flagged}

    def needs_reconciliation(self, limit: int = 200) -> list[dict]:
        """Payouts the sweeper released but could not resolve.

        `sweep_expired_holds` deliberately refuses to declare an unanswered
        payout failed -- the money may well have left. That correctness choice
        creates an OPERATOR obligation: someone must ask the provider what
        actually happened. Until this existed, that obligation was recorded in
        a `failure_reason` string nobody queried, so the sweeper was writing
        tickets into a drawer that was never opened.

        Non-terminal status is part of the predicate, not just the reason text:
        a payout later settled by a late webhook or resolved by `reconcile`
        keeps its historical reason, and re-listing it would send an operator
        chasing a closed item.
        """
        rows = self.conn.execute(
            "SELECT * FROM payouts"
            " WHERE failure_reason LIKE '%needs reconciliation%'"
            "   AND status NOT IN ('successful','failed','rejected','refunded')"
            " ORDER BY created_at ASC LIMIT ?",
            (max(1, min(int(limit), 500)),)).fetchall()
        return [_payout_view(r) for r in rows]

    def _submit(self, payout_id: str, bank_code: str, account_number: str,
                narration: str) -> dict:
        p = self.conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
        currency = p["currency"]
        try:
            resp = self.flw.initiate_transfer(
                bank_code=bank_code, account_number=account_number,
                amount_major=to_major(p["amount_minor"], currency),
                currency=currency, reference=p["reference"],
                narration=narration or "aibank payout",
                callback_url=self.callback_url,
                meta={"payout_id": payout_id, "agent_id": p["agent_id"]},
            )
        except FlutterwaveError as exc:
            if exc.indeterminate:
                # NO reply from the provider, so the transfer may already be
                # queued. Releasing the hold here would let the agent respend
                # money that is on its way out of the wallet, and the ledger
                # would be short by the amount once the webhook landed.
                #
                # So: keep the hold, leave the payout non-terminal, and put it
                # in the reconciliation queue -- the same refusal-to-guess the
                # hold sweeper already makes. An operator (or `cli reconcile`)
                # asks the provider what actually happened. The money stays
                # immobilised until someone knows, which is the correct bias
                # when the alternative is spending it twice.
                self._mark_indeterminate(payout_id, f"provider unreachable: {exc}")
                return self.get_payout(payout_id)
            # A reply arrived and the provider refused: nothing was queued.
            self._fail(payout_id, f"provider error: {exc}")
            return self.get_payout(payout_id)

        data = (resp or {}).get("data") or {}
        self.conn.execute(
            "UPDATE payouts SET status='submitted', provider_id=?, provider_status=?,"
            " updated_at=? WHERE id=?",
            (str(data.get("id")) if data.get("id") is not None else None,
             data.get("status"), L.now_iso(), payout_id),
        )
        return self.get_payout(payout_id)

    def _settle(self, payout_id: str, conn=None) -> None:
        """Money truly left. Capture the hold and write the real ledger entry.

        Guarded by the payout status check: settling twice is impossible, so a
        duplicate webhook can never debit the agent twice.
        """
        owns_txn = conn is None
        if owns_txn:
            ctx = self.db.write(); conn = ctx.__enter__()
        try:
            p = conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
            if p["status"] == "successful":
                return
            currency = p["currency"]
            wallet = L.get_or_create_account(conn, p["agent_id"], "agent_wallet", currency)
            external = L.get_or_create_account(conn, None, "external", currency)
            legs = [(wallet, -(p["amount_minor"] + p["fee_minor"])),
                    (external, p["amount_minor"])]
            if p["fee_minor"]:
                fees = L.get_or_create_account(conn, None, "revenue_fees", currency)
                legs.append((fees, p["fee_minor"]))
            entry = L.post_entry(conn, "payout", legs, currency, agent_id=p["agent_id"],
                                 reference=p["reference"], memo="payout settled")
            L.capture_hold(conn, p["hold_id"], entry)
            conn.execute(
                "UPDATE payouts SET status='successful', provider_status='SUCCESSFUL',"
                " updated_at=? WHERE id=?", (L.now_iso(), payout_id))
            L.audit(conn, p["agent_id"], "payout.settled", "ok", {"payout_id": payout_id})
        finally:
            if owns_txn:
                ctx.__exit__(None, None, None)

    def _mark_indeterminate(self, payout_id: str, reason: str, conn=None) -> None:
        """Provider outcome unknown: KEEP the hold, queue for reconciliation.

        The deliberate omission here is the whole point -- this never calls
        `L.release_hold`. The agent's money stays immobilised because the
        transfer may be in flight, and an operator resolves it via
        `needs_reconciliation` / `reconcile`.

        The reason text must contain "needs reconciliation": that substring is
        the `needs_reconciliation()` predicate, so an indeterminate payout that
        omitted it would sit in a non-terminal state forever with nothing
        surfacing it -- money frozen and nobody told. Status stays non-terminal
        so a late webhook can still settle it normally.
        """
        owns_txn = conn is None
        if owns_txn:
            ctx = self.db.write(); conn = ctx.__enter__()
        try:
            p = conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
            if p["status"] in ("failed", "successful", "rejected", "refunded"):
                return
            conn.execute(
                "UPDATE payouts SET failure_reason=?, updated_at=? WHERE id=?",
                (f"{reason}; needs reconciliation", L.now_iso(), payout_id))
            L.audit(conn, p["agent_id"], "payout.indeterminate", reason,
                    {"payout_id": payout_id, "hold_kept": True})
        finally:
            if owns_txn:
                ctx.__exit__(None, None, None)

    def _fail(self, payout_id: str, reason: str, conn=None) -> None:
        owns_txn = conn is None
        if owns_txn:
            ctx = self.db.write(); conn = ctx.__enter__()
        try:
            p = conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
            if p["status"] in ("failed", "successful"):
                return
            L.release_hold(conn, p["hold_id"])
            conn.execute(
                "UPDATE payouts SET status='failed', failure_reason=?, updated_at=? WHERE id=?",
                (reason, L.now_iso(), payout_id))
            L.audit(conn, p["agent_id"], "payout.failed", reason, {"payout_id": payout_id})
        finally:
            if owns_txn:
                ctx.__exit__(None, None, None)

    def get_payout(self, payout_id: str, agent_id: str | None = None,
                   user_id: str | None = None) -> dict:
        """Read one payout, scoped to the caller.

        TIER 1 FIX: this used to take only `payout_id`, so any valid agent key
        could read ANY agent's payout -- amount, reference, bank destination.
        Exactly the bug class already fixed on the write path. Scoping is now a
        SQL predicate rather than a post-hoc check, so there is no window where
        the row is fetched before the caller is authorised.

        Callers pass whichever scope they hold; passing neither is reserved for
        internal/admin paths.
        """
        sql = "SELECT * FROM payouts WHERE id = ?"
        args: list = [payout_id]
        if agent_id is not None:
            sql += " AND agent_id = ?"
            args.append(agent_id)
        if user_id is not None:
            sql += " AND agent_id IN (SELECT id FROM agents WHERE user_id = ?)"
            args.append(user_id)
        p = self.conn.execute(sql, tuple(args)).fetchone()
        if not p:
            raise NotFound("unknown payout")
        return _payout_view(p)

    def list_payouts(self, agent_id: str | None = None, user_id: str | None = None,
                     status: str | None = None, limit: int = 50,
                     offset: int = 0) -> list[dict]:
        sql = "SELECT * FROM payouts WHERE 1=1"
        args: list = []
        if agent_id is not None:
            sql += " AND agent_id = ?"
            args.append(agent_id)
        if user_id is not None:
            sql += " AND agent_id IN (SELECT id FROM agents WHERE user_id = ?)"
            args.append(user_id)
        if status:
            sql += " AND status = ?"
            args.append(status)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        args += [max(1, min(int(limit), 200)), max(0, int(offset))]
        return [_payout_view(r)
                for r in self.conn.execute(sql, tuple(args)).fetchall()]

    def statement(self, agent_id: str, currency: str = "NGN", limit: int = 100,
                  offset: int = 0) -> dict:
        """Every posting against an agent's wallet, with a running balance.

        Built from postings rather than payouts, so funding, allocations, fees
        and reversals all appear -- a payout list is not a statement.
        """
        currency = check_currency(currency)
        acct = self.wallet_id(agent_id, currency)
        rows = self.conn.execute(
            "SELECT p.id, p.amount_minor, p.created_at, e.id AS entry_id, e.kind,"
            " e.memo, e.reference FROM postings p JOIN entries e ON e.id = p.entry_id"
            " WHERE p.account_id = ? ORDER BY p.id LIMIT ? OFFSET ?",
            (acct, max(1, min(int(limit), 500)), max(0, int(offset)))).fetchall()
        running = 0
        lines = []
        for r in rows:
            running += r["amount_minor"]
            lines.append({
                "entry_id": r["entry_id"], "kind": r["kind"], "memo": r["memo"],
                "reference": r["reference"], "created_at": r["created_at"],
                "amount_minor": r["amount_minor"],
                "amount": to_major(r["amount_minor"], currency),
                "running_minor": running,
                "running": to_major(running, currency),
            })
        return {"agent_id": agent_id, "currency": currency, "account_id": acct,
                "lines": lines, "balance": self.balance(agent_id, currency)}

    def schema_version(self) -> int:
        from .db import current_version
        return current_version(self.conn)

    def trial_balance(self, currency: str | None = None) -> dict:
        """Zero means the books balance. Non-zero means corruption, loudly."""
        total = L.trial_balance(self.conn, currency)
        return {"currency": currency or "ALL", "net_minor": total,
                "balanced": total == 0}

    def agent_detail(self, agent_id: str) -> dict:
        row = self.conn.execute(
            "SELECT id, name, status, user_id, created_at FROM agents WHERE id=?",
            (agent_id,)).fetchone()
        if not row:
            raise NotFound("unknown agent")
        pol = self.get_policy(agent_id)
        cur = (pol or {}).get("currency", "NGN")
        return {**dict(row), "policy": pol, "balance": self.balance(agent_id, cur),
                "keys": self.list_api_keys(agent_id),
                "payees": self.list_payees(agent_id)}

    def dashboard(self, user_id: str, currency: str = "NGN") -> dict:
        """One call that renders the whole screen the human logs in to see."""
        currency = check_currency(currency)
        agents = []
        for a in self.list_agents(user_id):
            pol = self.get_policy(a["id"])
            cur = (pol or {}).get("currency", currency)
            agents.append({**a, "currency": cur, "policy": pol,
                           "balance": self.balance(a["id"], cur)})
        return {
            "user": U.get_user(self, user_id),
            "wallet": self.user_balance(user_id, currency),
            "agents": agents,
            "pending_approvals": self.pending_approvals(user_id),
            "recent_payouts": self.list_payouts(user_id=user_id, limit=10),
        }

    # ---------- webhooks ----------
    def handle_webhook(self, payload: dict) -> dict:
        """Idempotent by provider event identity: replays are no-ops.

        The claim INSERT is inside a write transaction, so two simultaneous
        deliveries of the same event cannot both proceed to settlement.
        """
        import sqlite3 as _sq
        key = dedupe_key(payload)
        event_id = L.new_id("evt")
        try:
            with self.db.write() as conn:
                prior = conn.execute(
                    "SELECT result FROM webhook_events WHERE dedupe_key = ?", (key,)
                ).fetchone()
                if prior:
                    return {"status": "duplicate", "result": prior["result"]}
                conn.execute(
                    "INSERT INTO webhook_events (id, provider, dedupe_key, payload, created_at)"
                    " VALUES (?,?,?,?,?)",
                    (event_id, "flutterwave", key, json.dumps(payload), L.now_iso()))
        except _sq.IntegrityError:
            return {"status": "duplicate", "result": "concurrent"}

        data = payload.get("data") or {}
        reference = data.get("reference")
        provider_status = str(data.get("status", "")).upper()
        result = "ignored"

        if reference:
            with self.db.write() as conn:
                p = conn.execute(
                    "SELECT * FROM payouts WHERE reference = ?", (reference,)).fetchone()
                if p:
                    if provider_status == "SUCCESSFUL":
                        self._settle(p["id"], conn); result = "settled"
                    elif provider_status in ("FAILED", "CANCELLED", "REVERSED"):
                        self._fail(p["id"], data.get("complete_message") or provider_status,
                                   conn)
                        result = "failed"
                    else:
                        conn.execute(
                            "UPDATE payouts SET provider_status=?, updated_at=? WHERE id=?",
                            (provider_status, L.now_iso(), p["id"]))
                        result = "status_updated"

        self.conn.execute(
            "UPDATE webhook_events SET processed_at=?, result=? WHERE id=?",
            (L.now_iso(), result, event_id))
        return {"status": "processed", "result": result}

    def reconcile(self, payout_id: str) -> dict:
        """Ask Flutterwave the truth when a webhook never arrived."""
        p = self.get_payout(payout_id)
        resp = self.flw.verify_by_reference(p["reference"])
        items = (resp or {}).get("data") or []
        if isinstance(items, dict):
            items = [items]
        if not items:
            return {"status": "not_found_at_provider"}
        status = str(items[0].get("status", "")).upper()
        if status == "SUCCESSFUL":
            self._settle(payout_id)
        elif status in ("FAILED", "CANCELLED"):
            self._fail(payout_id, "reconciled as failed")
        return {"status": status, "payout": self.get_payout(payout_id)}
