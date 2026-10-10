#!/usr/bin/env python3
"""The PHONE plays the authenticator app, so the PC never holds a secret.

WHY THIS EXISTS

The browser run on the PC has to prove one thing no other test in this project
can: that the enrolment symbol a browser RENDERS is sufficient on its own to
bind an authenticator. The obvious way is to hand the secret to the PC and let
it compute codes -- but then the test proves nothing about the pixels, because
the PC already knew the answer.

So the roles are split the way they are in real life:

    PC      = the user's browser. Sees the page, the symbol, six digits.
    phone   = the user's authenticator. Sees the symbol only as PIXELS,
              recovers the secret from them, and is the only holder of it.

The PC screenshots the symbol, POSTs the PNG here, and gets back nothing but
metadata. Later it asks for a code. Enrolment succeeding therefore proves the
rendered pixels were enough, and the secret never crosses the link -- which is
also why this is safe to use against a real account, not just the demo.

Reachable from the PC only through the authenticated SSH reverse tunnel
(`ssh -R 8099:127.0.0.1:8099`), and bound to loopback so nothing else can.
A bearer token is still required: the tunnel's far end is loopback on a
multi-process machine, and a code minter is exactly what a local attacker
would want.

Run:
    python3 scripts/dev/authn_service.py --token <hex> [--port 8099]
    python3 scripts/dev/authn_service.py --selftest

Routes (all need `Authorization: Bearer <token>`):
    GET  /health                      -> {"ok": true, "labels": [...]}
    POST /decode?label=L              body: image/png
                                      -> {"account","issuer","digits","period",
                                          "modules","matches_displayed"}
    POST /displayed?label=L           body: {"secret": "BASE32"}
                                      -> {"matches": bool}
    GET  /code?label=L[&skew=N]       -> {"code":"123456","period":30}
    POST /seed?label=L                body: {"secret": "..."} | {"otpauth": "..."}
                                      -> {"ok": true}   (for an account that is
                                         ALREADY enrolled, where there is no QR
                                         to read)
    POST /fund                        body: {"user_id": "...", "amount": "50000"}
                                      -> {"ok": true, "balance": {...}}
                                         Admin-gated deposit, performed HERE so
                                         the admin key stays on the phone.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.environ.get("AIBANK_REPO", os.path.abspath(os.path.join(HERE, "..", "..")))
sys.path.insert(0, REPO)

from aibank import totp as T                                   # noqa: E402
from scripts.dev.decode_png_qr import decode_png               # noqa: E402

MAX_BODY = 4 * 1024 * 1024          # a screenshot, not an upload service

# Funding ceilings. The browser run needs a few tens of thousands of (fake)
# naira; anything beyond that is a sign the caller is not the test.
FUND_MAX_PER_CALL = 500_000
FUND_MAX_TOTAL = 2_000_000
FUND_CFG: dict[str, str] = {}       # {"base": "http://...", "admin_key": "..."}
_FUNDED_TOTAL = 0

_LOCK = threading.Lock()
_SECRETS: dict[str, str] = {}       # label -> base32 secret, phone-side only
_DISPLAYED: dict[str, str] = {}     # label -> what the page showed, for compare
_ISSUED: dict[str, int] = {}        # label -> highest counter handed out


def _parse_otpauth(uri: str) -> dict:
    """Pull the fields a scanner would act on out of an otpauth:// URI."""
    if not uri.startswith("otpauth://totp/"):
        raise ValueError(f"not a TOTP provisioning URI: {uri[:40]!r}")
    u = urlparse(uri)
    label = unquote(u.path.lstrip("/"))
    q = {k: v[0] for k, v in parse_qs(u.query).items()}
    if "secret" not in q:
        raise ValueError("URI carries no secret")
    issuer, _, account = label.partition(":")
    if not account:
        issuer, account = q.get("issuer", ""), label
    return {"secret": q["secret"].upper(), "issuer": q.get("issuer", issuer),
            "account": account, "digits": int(q.get("digits", 6)),
            "period": int(q.get("period", 30)), "algorithm": q.get("algorithm", "SHA1")}


class Handler(BaseHTTPRequestHandler):
    server_version = "aibank-authn/1"
    protocol_version = "HTTP/1.1"
    token = ""

    # ------------------------------------------------------------- plumbing
    def log_message(self, format, *args):       # one tidy line per call
        sys.stderr.write("%s %s\n" % (time.strftime("%H:%M:%S"), format % args))

    def _send(self, code: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _await_fresh_counter(self, lab: str, at: float,
                             budget: float = 45.0) -> tuple[int, float]:
        """Block until the clock reaches a counter this label has not issued.

        The wait is real because the VERIFIER's clock is what matters: it
        accepts `now +/- SKEW_STEPS` and nothing further, so a counter can only
        be handed out once wall-clock time has actually reached it. Sleeping is
        the honest implementation of "wait for your app to tick over".

        Returns the counter and how long it waited, so a caller can show that
        a 30-second pause was a deliberate wait and not a hang. The budget is
        two periods plus slack: one period is the worst case, and exceeding
        two means the clock moved backwards or the host was suspended, which
        is worth an error rather than an unbounded block. It is kept BELOW the
        callers' 60s HTTP timeout so a slow wait surfaces as this service's
        own 503 with a reason, not as a client-side read timeout.
        """
        started = time.time()
        offset = at - started
        while True:
            now = time.time()
            counter = T.counter_for(now + offset)
            with _LOCK:
                last = _ISSUED.get(lab)
                if last is None or counter > last:
                    _ISSUED[lab] = counter
                    return counter, now - started
            if now - started > budget:
                raise TimeoutError(
                    f"counter {counter} still not past {last} after "
                    f"{budget:.0f}s")
            # Sleep to just past the next period boundary rather than polling:
            # one wakeup instead of hundreds, and no busy loop holding the GIL
            # while the rest of the service is serving the browser.
            boundary = (counter + 1) * T.STEP_SECONDS - (now + offset)
            time.sleep(max(0.2, min(boundary + 0.2, 5.0)))

    def _auth(self) -> bool:
        got = self.headers.get("Authorization", "")
        want = "Bearer " + self.token
        # compare_digest: the token is short and this is reachable from another
        # machine, so leaking its length/prefix through timing is avoidable.
        if len(got) == len(want) and secrets.compare_digest(got, want):
            return True
        self._send(401, {"error": "unauthorized"})
        return False

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError(f"body too large ({n} bytes)")
        return self.rfile.read(n) if n else b""

    def _label(self, q: dict) -> str:
        lab = (q.get("label", [""])[0] or "").strip()
        if not lab or len(lab) > 40 or not all(c.isalnum() or c in "-_." for c in lab):
            raise ValueError("label must be 1-40 chars of [A-Za-z0-9._-]")
        return lab

    # ------------------------------------------------------------- routes
    def do_GET(self):
        if not self._auth():
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path == "/health":
                with _LOCK:
                    return self._send(200, {"ok": True, "labels": sorted(_SECRETS)})

            if u.path == "/code":
                lab = self._label(q)
                skew = float(q.get("skew", ["0"])[0])
                fresh = q.get("fresh", ["0"])[0] in ("1", "true", "yes")
                with _LOCK:
                    sec = _SECRETS.get(lab)
                if not sec:
                    return self._send(404, {"error": f"no secret held for {lab!r}"})

                at = time.time() + skew
                if fresh:
                    # Replay protection makes every counter single-use: the
                    # server records the counter it accepted, so confirming an
                    # enrolment SPENDS the current code and the next sign-in a
                    # second later is correctly refused. A real user waits for
                    # their app to tick over; `fresh=1` is that wait.
                    #
                    # It must be an ACTUAL wait. Handing out `last + 1` without
                    # sleeping mints a code for a counter that has not arrived
                    # yet, and the verifier accepts at most SKEW_STEPS ahead --
                    # so the trick survives exactly one hop and the SECOND
                    # spent code in the same window is rejected as invalid.
                    # That failure looks like a product bug and is not one.
                    try:
                        counter, waited = self._await_fresh_counter(lab, at)
                    except TimeoutError as exc:
                        return self._send(503, {"error": "no fresh counter",
                                                "reason": str(exc)})
                    code = T.hotp(sec, counter)
                    return self._send(200, {"code": code, "counter": counter,
                                            "period": T.STEP_SECONDS,
                                            "label": lab, "fresh": True,
                                            "waited_s": round(waited, 1)})

                with _LOCK:
                    counter = T.counter_for(at)
                    prev = _ISSUED.get(lab)
                    _ISSUED[lab] = counter if prev is None else max(prev, counter)
                code = T.totp(sec, timestamp=at)
                # The code is logged deliberately: it expires in <30s and a
                # readable trace of what was typed is worth more than the
                # secrecy of a spent one-time value.
                return self._send(200, {"code": code, "counter": counter,
                                        "period": T.STEP_SECONDS, "label": lab})

            return self._send(404, {"error": "not found"})
        except Exception as exc:                                # noqa: BLE001
            return self._send(400, {"error": type(exc).__name__, "reason": str(exc)})

    def do_POST(self):
        if not self._auth():
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            raw = self._body()

            # /fund carries no label: it is an account operation, not an
            # authenticator one. Parse the label only for the routes that have
            # one, or a legitimate /fund gets rejected for a missing label.
            if u.path == "/fund":
                return self._fund(json.loads(raw or b"{}"))

            lab = self._label(q)

            if u.path == "/decode":
                if raw[:8] != b"\x89PNG\r\n\x1a\n":
                    return self._send(400, {"error": "not a PNG",
                                            "head": repr(raw[:8])})
                # Write to a temp file: the decoder reads a path, because its
                # other caller is a human with a screenshot on disk.
                fd, path = tempfile.mkstemp(suffix=".png", dir=os.path.join(
                    os.path.expanduser("~"), "tmp"))
                try:
                    with os.fdopen(fd, "wb") as fh:
                        fh.write(raw)
                    payload = decode_png(path).decode()
                finally:
                    os.remove(path)

                info = _parse_otpauth(payload)
                with _LOCK:
                    _SECRETS[lab] = info["secret"]
                    shown = _DISPLAYED.get(lab)
                out = {k: v for k, v in info.items() if k != "secret"}
                out["bytes"] = len(raw)
                # The secret itself is NOT returned. The PC has no use for it
                # and every reason not to hold it.
                out["matches_displayed"] = (shown == info["secret"]
                                            if shown else None)
                return self._send(200, out)

            if u.path == "/displayed":
                sec = (json.loads(raw or b"{}").get("secret") or "").upper()
                sec = "".join(sec.split())
                if not sec:
                    return self._send(400, {"error": "no secret field"})
                with _LOCK:
                    _DISPLAYED[lab] = sec
                    held = _SECRETS.get(lab)
                return self._send(200, {"matches": held == sec if held else None})

            if u.path == "/seed":
                b = json.loads(raw or b"{}")
                if b.get("otpauth"):
                    sec = _parse_otpauth(b["otpauth"])["secret"]
                else:
                    sec = "".join((b.get("secret") or "").split()).upper()
                T.totp(sec)                      # reject garbage immediately
                with _LOCK:
                    _SECRETS[lab] = sec
                return self._send(200, {"ok": True, "label": lab})

            if u.path == "/forget":
                with _LOCK:
                    _SECRETS.pop(lab, None)
                    _DISPLAYED.pop(lab, None)
                    _ISSUED.pop(lab, None)
                return self._send(200, {"ok": True})

            return self._send(404, {"error": "not found"})
        except Exception as exc:                                # noqa: BLE001
            return self._send(400, {"error": type(exc).__name__, "reason": str(exc)})

    # ------------------------------------------------------------- funding
    def _fund(self, body: dict):
        """Credit a wallet, holding the admin key on the PHONE.

        `POST /v1/wallet/deposit` is admin-gated, deliberately: crediting a
        wallet from nothing is not a customer operation. The browser run still
        needs a funded wallet to exercise allocation and payouts, and the naive
        way to get one is to put `AIBANK_ADMIN_KEY` on the PC -- which would
        hand a remote machine the key that can mint money in every account.

        So the deposit is performed here instead. The PC asks for a named test
        account to be topped up; the key never leaves this process.

        Two deliberate limits, because a reachable money-minter is exactly what
        an attacker on the far end of the tunnel would reach for:
          - a per-call ceiling, so a compromised runner cannot invent millions;
          - a running total per process, so it cannot loop to the same effect.
        """
        global _FUNDED_TOTAL
        if not FUND_CFG.get("base"):
            return self._send(503, {"error": "funding not configured",
                                    "reason": "start with --fund-base/--admin-key"})
        user_id = (body.get("user_id") or "").strip()
        if not user_id:
            return self._send(400, {"error": "no user_id"})
        try:
            amount = int(str(body.get("amount", "0")).replace(",", ""))
        except ValueError:
            return self._send(400, {"error": "amount must be a whole number"})
        if amount <= 0 or amount > FUND_MAX_PER_CALL:
            return self._send(400, {"error": "amount out of range",
                                    "max": FUND_MAX_PER_CALL})
        with _LOCK:
            if _FUNDED_TOTAL + amount > FUND_MAX_TOTAL:
                return self._send(429, {"error": "funding budget exhausted",
                                        "funded": _FUNDED_TOTAL,
                                        "budget": FUND_MAX_TOTAL})
            _FUNDED_TOTAL += amount

        import urllib.error
        import urllib.request
        payload = json.dumps({
            "user_id": user_id, "amount": str(amount),
            "currency": body.get("currency", "NGN"),
            # Idempotent on (user, amount, label): a retry after a dropped
            # reply must not deposit twice.
            "idempotency_key": body.get("idempotency_key")
            or f"authn-fund-{user_id}-{amount}-{body.get('nonce', '1')}",
        }).encode()
        req = urllib.request.Request(
            FUND_CFG["base"].rstrip("/") + "/v1/wallet/deposit", data=payload,
            headers={"Content-Type": "application/json",
                     # The admin gate reads X-Admin-Key, NOT Authorization:
                     # Bearer -- `_admin()` compares that header against
                     # AIBANK_ADMIN_KEY and a Bearer token is simply ignored,
                     # giving a 401 that reads like a wrong key.
                     "X-Admin-Key": FUND_CFG["admin_key"]},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                out = json.loads(r.read() or b"{}")
            return self._send(200, {"ok": True, "amount": amount,
                                    "balance": out.get("balance"),
                                    "funded_so_far": _FUNDED_TOTAL})
        except urllib.error.HTTPError as exc:
            return self._send(502, {"error": "deposit refused by the API",
                                    "status": exc.code,
                                    "body": exc.read().decode()[:300]})
        except Exception as exc:                                # noqa: BLE001
            return self._send(502, {"error": type(exc).__name__,
                                    "reason": str(exc)})


def selftest() -> int:
    """Prove the whole loop locally: encode -> render -> decode -> code."""
    import http.client

    from aibank import qr as QR
    from scripts.dev.decode_png_qr import _render, _write_png

    tmp = os.path.join(os.path.expanduser("~"), "tmp")
    os.makedirs(tmp, exist_ok=True)
    tok = secrets.token_hex(16)
    Handler.token = tok
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def call(method, path, body=None, ctype="application/json", token=tok,
             timeout=20):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        hdr = {"Content-Type": ctype}
        if token:
            hdr["Authorization"] = "Bearer " + token
        c.request(method, path, body=body, headers=hdr)
        r = c.getresponse()
        out = r.read()
        c.close()
        try:
            return r.status, json.loads(out)
        except Exception:                                       # noqa: BLE001
            return r.status, out

    fails = 0
    total = 0

    def check(label, got, want):
        nonlocal fails, total
        total += 1
        ok = got == want
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
        if not ok:
            fails += 1
            print(f"       got {got!r} want {want!r}")

    secret = T.new_secret()
    uri = T.provisioning_uri(secret, "kayode@aibank.local")
    png = os.path.join(tmp, "authn_selftest.png")
    _write_png(png, _render(QR.encode(uri), scale=5, quiet=4))
    with open(png, "rb") as fh:
        blob = fh.read()

    st, _ = call("GET", "/health", token=None)
    check("no token is refused", st, 401)
    st, _ = call("GET", "/health", token="deadbeef")
    check("a wrong token is refused", st, 401)
    st, b = call("GET", "/health")
    check("health ok", (st, b["ok"]), (200, True))

    st, b = call("POST", "/displayed?label=t", json.dumps({"secret": secret}))
    check("the page's displayed key is accepted", st, 200)

    st, b = call("POST", "/decode?label=t", blob, "image/png")
    check("the PNG decodes", st, 200)
    check("account recovered from pixels", b.get("account"), "kayode@aibank.local")
    check("pixels agree with the displayed key", b.get("matches_displayed"), True)
    check("the secret is NOT returned to the caller", "secret" in b, False)

    st, b = call("GET", "/code?label=t")
    check("a code is minted from the decoded secret", st, 200)
    check("the code verifies against the original secret",
          T.verify(secret, b["code"]) is not None, True)

    st, b = call("GET", "/code?label=nope")
    check("an unknown label has no code", st, 404)

    st, b = call("POST", "/decode?label=t", b"not a png at all", "image/png")
    check("junk is refused as not-a-PNG", st, 400)

    st, b = call("POST", "/displayed?label=t", json.dumps({"secret": "AAAA2222"}))
    check("a mismatched displayed key is reported, not accepted",
          b.get("matches"), False)

    st, b = call("POST", "/seed?label=real", json.dumps({"otpauth": uri}))
    check("an already-enrolled account can be seeded from its URI", st, 200)
    st, b = call("GET", "/code?label=real&skew=60")
    check("a skewed code is computable", T.verify(secret, b["code"],
          timestamp=time.time() + 60) is not None, True)

    st, b = call("GET", "/code?label=../../etc/passwd")
    check("a path-ish label is refused", st, 400)

    # ---------------------------------------------------------------- fresh=1
    # The regression this guards: `fresh=1` used to hand out `last + 1`
    # immediately, which is a counter in the FUTURE. The verifier accepts at
    # most SKEW_STEPS ahead, so the trick worked once and the second spent code
    # in the same window came back invalid -- a harness fault that reads
    # exactly like a broken second factor. A fresh code must therefore be
    # (a) strictly later than any already issued, (b) NOT in the future, and
    # (c) acceptable to the real verifier with replay protection armed. Only a
    # real wait satisfies all three, so this costs up to one period.
    #
    # On its OWN label: the `skew=60` check above pushed `real`'s issued
    # counter two periods into the future, so asking that label for a fresh
    # code would correctly wait a full minute for the clock to catch up.
    st, _ = call("POST", "/seed?label=fresh", json.dumps({"secret": secret}))
    check("the fresh-code label is seeded", st, 200)
    st, first = call("GET", "/code?label=fresh")
    check("a plain code is issued", st, 200)
    # Timeout above one period: the wait is real, so a 20s client timeout
    # would abort it and report a hang instead of a pass.
    st, fresh = call("GET", "/code?label=fresh&fresh=1", timeout=90)
    check("a fresh code is issued", st, 200)
    check("the fresh counter is strictly later than the spent one",
          fresh["counter"] > first["counter"], True)
    check("the fresh counter is NOT in the future",
          fresh["counter"] <= T.counter_for(), True)
    check("the fresh code passes the real verifier with replay armed",
          T.verify(secret, fresh["code"],
                   last_counter=first["counter"]) == fresh["counter"], True)
    check("the wait is reported, so a pause is not mistaken for a hang",
          "waited_s" in fresh, True)

    # Funding is refused outright until configured, so an unconfigured service
    # can never be mistaken for one that silently did nothing.
    st, b = call("POST", "/fund", json.dumps({"user_id": "u", "amount": "100"}))
    check("funding is refused while unconfigured", st, 503)

    FUND_CFG["base"] = "http://127.0.0.1:1"     # nothing listens there
    FUND_CFG["admin_key"] = "test-admin-key"
    st, b = call("POST", "/fund", json.dumps({"user_id": "u", "amount": "0"}))
    check("a zero deposit is refused", st, 400)
    st, b = call("POST", "/fund", json.dumps({"user_id": "u",
                                              "amount": str(FUND_MAX_PER_CALL + 1)}))
    check("an over-ceiling deposit is refused", st, 400)
    st, b = call("POST", "/fund", json.dumps({"amount": "100"}))
    check("a deposit with no user is refused", st, 400)
    st, b = call("POST", "/fund", json.dumps({"user_id": "u", "amount": "100"}))
    check("a configured deposit reaches the API (and fails loudly here)", st, 502)
    FUND_CFG.clear()

    os.remove(png)
    srv.shutdown()
    # Counted, not hard-coded: a literal total silently stops matching the
    # moment an assertion is added, and "19 passed" with 24 checks run is
    # worse than no number at all.
    print(f"\n{total - fails} passed, {fails} failed")
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--token", default="")
    ap.add_argument("--token-file", default="")
    ap.add_argument("--fund-base", default="",
                    help="aibank base URL to perform admin deposits against")
    ap.add_argument("--admin-key", default=os.environ.get("AIBANK_ADMIN_KEY", ""),
                    help="stays in THIS process; never sent to the PC")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()

    if a.fund_base:
        if not a.admin_key:
            print("--fund-base needs --admin-key (or AIBANK_ADMIN_KEY)")
            return 2
        FUND_CFG["base"] = a.fund_base
        FUND_CFG["admin_key"] = a.admin_key

    tok = a.token
    if a.token_file:
        with open(a.token_file) as fh:
            tok = fh.read().strip()
    if not tok:
        tok = secrets.token_hex(16)
        print(f"generated token: {tok}")
    if a.host not in ("127.0.0.1", "localhost", "::1"):
        print("REFUSING a non-loopback bind: reach this through ssh -R instead.")
        return 2

    Handler.token = tok
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"authenticator service on {a.host}:{a.port} — the phone holds the "
          f"secrets, the PC only ever sees six digits")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
