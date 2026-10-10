#!/usr/bin/env python3
"""Rehearse the PC browser run, on the phone, without a browser.

WHY

`pc-aibank-test.sh` can only run when the PC is reachable, and the first run is
exactly when a bug in the harness is most expensive: a half-enrolled real
account, or an hour of Tor retries spent discovering a typo. Everything in that
pipeline except the browser's own rasteriser is phone-side code, and all of it
can be exercised here:

    register -> fund (admin, via the authenticator) -> begin enrolment ->
    render the returned modules to a PNG -> POST the PNG to the authenticator ->
    it recovers the secret FROM THE PIXELS -> ask it for a code -> confirm ->
    sign in again and be challenged -> complete with another code -> disable

What this does NOT cover, and what the PC run exists for: the SVG the page
builds, the CSS that sizes it, the dark theme behind it, and Edge's rasteriser.
So a pass here means "the mechanism is sound"; only the PC run means "a camera
could read it".

The PNG here is drawn by the same deliberately crude renderer the decoder's own
self test uses, including the antialiasing pass -- so the decode being tested
is a real sampling problem, not an identity function.

Run:  python scripts/dev/rehearse_pc_run.py [--base http://127.0.0.1:8088]
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)

from aibank import qr as QR                                    # noqa: E402
from scripts.dev.decode_png_qr import _render, _write_png      # noqa: E402

FAILS = 0
TOTAL = 0


def check(label: str, ok, detail: str = "") -> bool:
    global FAILS, TOTAL
    TOTAL += 1
    ok = bool(ok)
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + (f"  -- {detail}" if detail else ""))
    if not ok:
        FAILS += 1
    return ok


def call(base: str, method: str, path: str, body=None, token: str = "",
         admin: str = "", ctype: str = "application/json"):
    data = body if isinstance(body, bytes) else (
        json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method)
    req.add_header("Content-Type", ctype)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if admin:
        req.add_header("Authorization", "Bearer " + admin)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return r.status, {"raw": raw[:200].decode(errors="replace")}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw[:200].decode(errors="replace")}
    except urllib.error.URLError as exc:
        # A refused connection is an ANSWER here -- the readiness poll depends
        # on it -- not an exception to propagate out of the harness.
        return 0, {"error": str(exc.reason)}
    except OSError as exc:
        return 0, {"error": str(exc)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8088")
    ap.add_argument("--authn-port", type=int, default=8098)   # not 8099: avoid
    ap.add_argument("--admin-key", default="demo-admin-key-not-a-secret")
    a = ap.parse_args()                                       # a live run

    print(f"rehearsing against {a.base}\n")

    st, b = call(a.base, "GET", "/health")
    if not check("the app answers", st == 200, f"HTTP {st}"):
        print("\nnothing to rehearse against; start the demo service first")
        return 1

    # --- stand up the authenticator, exactly as the orchestrator does ------
    token = secrets.token_hex(16)
    tokfile = os.path.join(os.path.expanduser("~"), "tmp", f"rehearse.{os.getpid()}")
    with open(tokfile, "w") as fh:
        fh.write(token)
    os.chmod(tokfile, 0o600)
    env = dict(os.environ,
               AIBANK_ALLOW_DEV_SECRETS="1", AIBANK_SCRYPT_N="4096",
               AIBANK_ADMIN_KEY=a.admin_key,
               AIBANK_KEY_PEPPER=os.environ.get("AIBANK_KEY_PEPPER",
                                                "demo-pepper-not-a-secret"))
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "authn_service.py"),
         "--port", str(a.authn_port), "--token-file", tokfile,
         "--fund-base", a.base, "--admin-key", a.admin_key],
        cwd=REPO, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True)
    authn = f"http://127.0.0.1:{a.authn_port}"
    try:
        st = 0
        for _ in range(25):
            if proc.poll() is not None:
                # It died. Its own output is the diagnosis; swallowing it would
                # leave only "connection refused", which says nothing.
                print(f"  FAIL the authenticator exited {proc.returncode}:")
                out = proc.stdout.read() if proc.stdout else ""
                for line in (out or "").splitlines()[:12]:
                    print(f"       {line}")
                return 1
            st, _ = call(authn, "GET", "/health", token=token)
            if st == 200:
                break
            time.sleep(0.4)
        if not check("the authenticator comes up", st == 200, f"HTTP {st}"):
            return 1

        # --- phase 2 rehearsal: an account created during the run ----------
        stamp = time.strftime("%m%d%H%M%S")
        email = f"rehearse-{stamp}@aibank.local"
        pw = f"rehearse-pass-{stamp}"

        st, reg = call(a.base, "POST", "/v1/auth/register",
                       {"email": email, "password": pw, "display_name": "Rehearsal"})
        check("an account registers through the API", st == 201, f"HTTP {st}")
        uid = reg.get("user_id", "")
        check("registration identifies the new account", uid.startswith("user_"), uid)

        # Register does NOT hand back a session -- deliberately: it creates an
        # account, it does not authenticate one. The page signs in immediately
        # afterwards, so the rehearsal does the same.
        st, lg = call(a.base, "POST", "/v1/auth/login",
                      {"email": email, "password": pw})
        sess = lg.get("session_token", "")
        check("a fresh account signs in with password alone",
              st == 200 and sess.startswith("sess_"), f"HTTP {st}")

        # Funding through the AUTHENTICATOR, which holds the admin key. This is
        # the property under test: the browser's machine never sees that key.
        st, f = call(authn, "POST", "/fund",
                     {"user_id": uid, "amount": "80000", "nonce": stamp},
                     token=token)
        check("the authenticator credits the wallet with its own admin key",
              st == 200 and f.get("ok"), f"HTTP {st} {str(f)[:90]}")
        st, w = call(a.base, "GET", "/v1/wallet", token=sess)
        check("the money is actually in the wallet",
              st == 200 and w.get("balance") not in (None, "0.00"),
              f"balance {w.get('balance')}")

        # A wrong password must be refused, since the browser run asserts the
        # same thing through the form.
        st, _ = call(a.base, "POST", "/v1/auth/login",
                     {"email": email, "password": "wrong-one-entirely"})
        check("a wrong password is refused", st == 401, f"HTTP {st}")

        # --- the pixel loop ------------------------------------------------
        st, enrol = call(a.base, "POST", "/v1/auth/mfa/enrol",
                         {"current_password": pw}, token=sess)
        check("enrolment begins", st == 200, f"HTTP {st}")
        check("it is NOT yet active", enrol.get("enrolled") is False)
        rows = enrol.get("qr_rows") or []
        check("the API returns drawable modules, not markup",
              bool(rows) and set("".join(rows)) <= {"0", "1"},
              f"{len(rows)}x{len(rows[0]) if rows else 0}")
        if "secret" not in enrol or not rows:
            # Without an enrolment there is nothing left to rehearse, and
            # pressing on would raise a KeyError that buries the real failure
            # above it.
            print("\n  enrolment did not start; the remaining steps are moot")
            print(f"\n{TOTAL - FAILS} passed, {FAILS} failed")
            return 1

        # Tell the authenticator what the page WOULD display beside the symbol,
        # so it can compare that against what it reads from the pixels.
        st, _ = call(authn, "POST", "/displayed?label=rehearse",
                     {"secret": enrol["secret"]}, token=token)
        check("the displayed key is registered for comparison", st == 200)

        # Render those modules the way a browser would, then throw away any
        # knowledge of the secret: from here only the PIXELS carry it.
        matrix = [[c == "1" for c in row] for row in rows]
        png_path = os.path.join(os.path.expanduser("~"), "tmp",
                                f"rehearse-{stamp}.png")
        _write_png(png_path, _render(matrix, scale=6, quiet=4, soften=True))
        with open(png_path, "rb") as fh:
            blob = fh.read()
        check("a PNG of the symbol was produced", len(blob) > 500, f"{len(blob)} bytes")

        st, dec = call(authn, "POST", "/decode?label=rehearse", blob,
                       token=token, ctype="image/png")
        check("the authenticator recovered the payload from the pixels",
              st == 200 and dec.get("account") == email,
              f"HTTP {st} account={dec.get('account')}")
        check("the pixels agree with the key shown for hand entry",
              dec.get("matches_displayed") is True)
        check("the decoded secret is NOT handed back to the caller",
              "secret" not in dec)

        st, c = call(authn, "GET", "/code?label=rehearse", token=token)
        check("a code is minted from the pixel-derived secret", st == 200)

        st, conf = call(a.base, "POST", "/v1/auth/mfa/confirm",
                        {"code": c["code"]}, token=sess)
        check("ENROLLED using a code derived only from the rendered pixels",
              st == 200 and conf.get("enrolled") is True, f"HTTP {st}")
        codes = conf.get("recovery_codes") or []
        check("recovery codes are issued once", len(codes) >= 8, f"{len(codes)} codes")

        # --- the factor must now be load-bearing ---------------------------
        st, step1 = call(a.base, "POST", "/v1/auth/login",
                         {"email": email, "password": pw})
        check("the correct password alone no longer yields a session",
              st == 200 and step1.get("mfa_required") is True
              and "session_token" not in step1, f"HTTP {st}")
        chal = step1.get("challenge_token", "")

        st, bad = call(authn, "GET", "/code?label=rehearse&skew=-3600", token=token)
        st, r = call(a.base, "POST", "/v1/auth/mfa/verify",
                     {"challenge_token": chal, "code": bad["code"]})
        check("a code from an hour ago is refused", st == 401, f"HTTP {st}")

        # fresh=1, NOT the current code: confirming the enrolment a moment ago
        # SPENT that counter, and the server's replay protection correctly
        # refuses it. A real user waits for their app to tick over; this is
        # that wait without sleeping 30 seconds.
        st, good = call(authn, "GET", "/code?label=rehearse&fresh=1", token=token)
        st, done = call(a.base, "POST", "/v1/auth/mfa/verify",
                        {"challenge_token": chal, "code": good["code"]})
        ok = check("a fresh code from the authenticator completes the sign-in",
                   st == 200 and done.get("session_token", "").startswith("sess_"),
                   f"HTTP {st}")
        sess2 = done.get("session_token", "")

        if ok:
            st, _ = call(a.base, "GET", "/v1/dashboard", token=sess2)
            check("the new session reads the dashboard", st == 200, f"HTTP {st}")

            # The same digits must not work twice: replay is the cheapest real
            # attack on TOTP.
            st, step1b = call(a.base, "POST", "/v1/auth/login",
                              {"email": email, "password": pw})
            st, rep = call(a.base, "POST", "/v1/auth/mfa/verify",
                           {"challenge_token": step1b.get("challenge_token", ""),
                            "code": good["code"]})
            check("the just-spent code is refused on a new challenge",
                  st == 401, f"HTTP {st}")

            # And leave nothing enrolled behind: the account was created by
            # this script and should not outlive it in a half state.
            st, nxt = call(authn, "GET", "/code?label=rehearse&fresh=1", token=token)
            st, _ = call(a.base, "POST", "/v1/auth/mfa/disable",
                         {"current_password": pw, "code": nxt["code"]}, token=sess2)
            check("the factor can be turned back off with password + code",
                  st == 200, f"HTTP {st}")

        os.remove(png_path)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        os.remove(tokfile)

    print(f"\n{TOTAL - FAILS} passed, {FAILS} failed")
    if FAILS:
        print("the PC run would fail the same way; fix these first")
    else:
        print("the mechanism is sound. Only the browser's rasteriser is "
              "untested -- that is what the PC run adds.")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
