#!/usr/bin/env python3
"""End-to-end HTTP smoke test for the SECOND FACTOR, over a real socket.

The unit tests prove the logic in `users.py`. This proves the WIRING: routing,
status codes, which trust domain each route accepts, and that the dashboard's
actual two-step flow works against a live server. A second factor that is
correct in the module and unreachable over HTTP protects nothing.

    AIBANK_ALLOW_DEV_SECRETS=1 python scripts/smoke_mfa.py

Exit code 0 means every assertion passed.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("AIBANK_ALLOW_DEV_SECRETS", "1")
os.environ.setdefault("AIBANK_SCRYPT_N", "1024")
os.environ.setdefault("AIBANK_ADMIN_KEY", "test-admin-key")
os.environ.setdefault("AIBANK_KEY_PEPPER", "test-pepper")

from aibank import db as D
from aibank import totp as T
from aibank.api import make_handler
from aibank.bank import Bank
from aibank.flutterwave import FlutterwaveClient
from tests.fake_flw import FakeFLW

PASS, FAIL = 0, 0
PASSWORD = "dashboard-password-1234"


def check(label: str, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  ok   {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label}: got {got!r}, want {want!r}")


def check_true(label: str, cond):
    check(label, bool(cond), True)


def call(method, path, body=None, token=None, admin=False):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if admin:
        req.add_header("X-Admin-Key", os.environ["AIBANK_ADMIN_KEY"])
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


bank = Bank(D.ephemeral_path(),
            flw=FlutterwaveClient(secret_key="FLWSECK_TEST-x", opener=FakeFLW()))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(bank))
PORT = httpd.server_address[1]
BASE = f"http://127.0.0.1:{PORT}"
threading.Thread(target=httpd.serve_forever, daemon=True).start()
time.sleep(0.3)

try:
    print("\n-- setup: a human with an agent under limits --")
    st, _ = call("POST", "/v1/auth/register",
                 {"email": "owner@example.com", "password": PASSWORD})
    check("register", st, 201)
    st, login = call("POST", "/v1/auth/login",
                     {"email": "owner@example.com", "password": PASSWORD})
    check("password login before enrolment returns a session", st, 200)
    check_true("session token present", login.get("session_token"))
    check("and reports mfa:false", login.get("mfa"), False)
    sess = login["session_token"]

    st, agent = call("POST", "/v1/agents",
                     {"name": "spender", "per_txn_max": 1000, "daily_max": 5000},
                     token=sess)
    check("agent created", st, 201)
    agent_key = agent["api_key"]
    agent_id = agent["agent_id"]

    print("\n-- the factor is off by default, and reports so --")
    st, state = call("GET", "/v1/auth/mfa", token=sess)
    check("GET /v1/auth/mfa", st, 200)
    check("enabled=false", state["enabled"], False)
    check("no recovery codes yet", state["recovery_codes_remaining"], 0)

    print("\n-- an AGENT KEY may not touch the factor guarding its own limits --")
    # This is the same invariant as the policy route: the agent's credential
    # must not reach the human trust domain. If it could read or remove the
    # second factor, the factor would be inside the blast radius of the
    # credential it exists to constrain.
    for method, path, body in [
        ("GET", "/v1/auth/mfa", None),
        ("POST", "/v1/auth/mfa/enrol", {"current_password": PASSWORD}),
        ("POST", "/v1/auth/mfa/confirm", {"code": "123456"}),
        ("POST", "/v1/auth/mfa/disable", {"current_password": PASSWORD, "code": "1"}),
        ("POST", "/v1/auth/mfa/recovery-codes", {"current_password": PASSWORD}),
    ]:
        st, _ = call(method, path, body, token=agent_key)
        check(f"agent key rejected: {method} {path}", st, 401)

    print("\n-- enrolment requires the password, even with a valid session --")
    st, body = call("POST", "/v1/auth/mfa/enrol",
                    {"current_password": "wrong"}, token=sess)
    check("wrong password refused", st, 401)
    check("as auth_failed", body["error"], "auth_failed")

    st, enrol = call("POST", "/v1/auth/mfa/enrol",
                     {"current_password": PASSWORD}, token=sess)
    check("enrol begins", st, 200)
    secret = enrol["secret"]
    check_true("otpauth uri returned", enrol["otpauth_uri"].startswith("otpauth://totp/"))
    check("not yet enrolled", enrol["enrolled"], False)

    print("\n-- a wrong code does not activate the factor --")
    st, _ = call("POST", "/v1/auth/mfa/confirm", {"code": "000000"}, token=sess)
    check("bad confirm refused", st, 401)
    st, state = call("GET", "/v1/auth/mfa", token=sess)
    check("still disabled", state["enabled"], False)

    print("\n-- confirming with a real code activates it and issues recovery codes --")
    st, confirmed = call("POST", "/v1/auth/mfa/confirm",
                         {"code": T.totp(secret)}, token=sess)
    check("confirm accepted", st, 200)
    check("enrolled", confirmed["enrolled"], True)
    codes = confirmed["recovery_codes"]
    check("ten recovery codes", len(codes), T.RECOVERY_CODE_COUNT)
    st, state = call("GET", "/v1/auth/mfa", token=sess)
    check("now enabled", state["enabled"], True)
    check("ten unused", state["recovery_codes_remaining"], T.RECOVERY_CODE_COUNT)

    print("\n-- THE CENTRAL PROPERTY: password alone no longer yields a session --")
    st, step1 = call("POST", "/v1/auth/login",
                     {"email": "owner@example.com", "password": PASSWORD})
    check("login returns 200 (credentials were correct)", st, 200)
    check("mfa_required", step1.get("mfa_required"), True)
    check("NO session token", "session_token" in step1, False)
    challenge = step1["challenge_token"]

    # The decisive check: the challenge must not authenticate the route that
    # raises an agent's ceiling. If it did, the whole two-step flow would be
    # theatre.
    st, _ = call("POST", f"/v1/agents/{agent_id}/policy",
                 {"per_txn_max": 10_000_000}, token=challenge)
    check("challenge token CANNOT raise a policy ceiling", st, 401)
    st, _ = call("GET", "/v1/dashboard", token=challenge)
    check("challenge token cannot read the dashboard", st, 401)
    st, _ = call("GET", "/v1/wallet", token=challenge)
    check("challenge token cannot read the wallet", st, 401)

    print("\n-- a wrong code is refused, and guesses are capped --")
    for i in range(1, 6):
        st, body = call("POST", "/v1/auth/mfa/verify",
                        {"challenge_token": challenge, "code": "000000"})
        check(f"guess {i} refused", st, 401)
    st, body = call("POST", "/v1/auth/mfa/verify",
                    {"challenge_token": challenge, "code": "000000"})
    check("cap trips with 429", st, 429)
    check("as locked_out", body["error"], "locked_out")

    print("\n-- a fresh challenge plus a real code yields a working session --")
    print("   (and a SPENT code is distinguished from a wrong one)")
    st, step1 = call("POST", "/v1/auth/login",
                     {"email": "owner@example.com", "password": PASSWORD})
    challenge = step1["challenge_token"]

    # The confirm step above SPENT the code for the current 30-second step, so
    # this is the exact situation a real user hits when they enrol and sign in
    # straight away. It must not be reported as an invalid code, and it must
    # not burn the challenge.
    st, body = call("POST", "/v1/auth/mfa/verify",
                    {"challenge_token": challenge, "code": T.totp(secret)})
    check("the just-spent code is refused", st, 401)
    check_true("and says it was already used, not 'invalid'",
               "already been used" in body.get("reason", ""))

    # What their authenticator shows next. Inside the accepted skew window.
    code = T.totp(secret, timestamp=time.time() + T.STEP_SECONDS)
    st, step2 = call("POST", "/v1/auth/mfa/verify",
                     {"challenge_token": challenge, "code": code})
    check("the SAME challenge accepts the next code (no re-login)", st, 200)
    check("mfa:true on the session", step2.get("mfa"), True)
    mfa_sess = step2["session_token"]
    st, dash = call("GET", "/v1/dashboard", token=mfa_sess)
    check("the new session reads the dashboard", st, 200)
    st, _ = call("POST", f"/v1/agents/{agent_id}/policy",
                 {"per_txn_max": 2000, "daily_max": 5000}, token=mfa_sess)
    check("and CAN set policy (it is a full session)", st, 200)

    print("\n-- the challenge is single-use --")
    st, _ = call("POST", "/v1/auth/mfa/verify",
                 {"challenge_token": challenge, "code": code})
    check("replayed challenge refused", st, 401)

    print("\n-- a recovery code substitutes for the authenticator --")
    st, step1 = call("POST", "/v1/auth/login",
                     {"email": "owner@example.com", "password": PASSWORD})
    st, step2 = call("POST", "/v1/auth/mfa/verify",
                     {"challenge_token": step1["challenge_token"], "code": codes[0]})
    check("recovery code accepted", st, 200)
    check("flagged as recovery", step2["used_recovery_code"], True)
    check("one fewer remaining", step2["recovery_codes_remaining"],
          T.RECOVERY_CODE_COUNT - 1)
    rec_sess = step2["session_token"]

    st, step1 = call("POST", "/v1/auth/login",
                     {"email": "owner@example.com", "password": PASSWORD})
    st, _ = call("POST", "/v1/auth/mfa/verify",
                 {"challenge_token": step1["challenge_token"], "code": codes[0]})
    check("the same recovery code cannot be reused", st, 401)

    print("\n-- recovery codes can be rotated --")
    st, body = call("POST", "/v1/auth/mfa/recovery-codes",
                    {"current_password": "wrong"}, token=rec_sess)
    check("rotation needs the password", st, 401)
    st, body = call("POST", "/v1/auth/mfa/recovery-codes",
                    {"current_password": PASSWORD}, token=rec_sess)
    check("rotation issues a new set", st, 200)
    new_codes = body["recovery_codes"]
    check("ten again", len(new_codes), T.RECOVERY_CODE_COUNT)
    check("none shared with the old set", bool(set(new_codes) & set(codes)), False)

    print("\n-- the password alone cannot REMOVE the factor --")
    st, _ = call("POST", "/v1/auth/mfa/disable",
                 {"current_password": PASSWORD}, token=rec_sess)
    check("password with no code refused", st, 401)
    st, _ = call("POST", "/v1/auth/mfa/disable",
                 {"current_password": PASSWORD, "code": "000000"}, token=rec_sess)
    check("password with a bad code refused", st, 401)
    st, state = call("GET", "/v1/auth/mfa", token=rec_sess)
    check("still enabled", state["enabled"], True)

    print("\n-- password plus possession removes it and revokes sessions --")
    st, body = call("POST", "/v1/auth/mfa/disable",
                    {"current_password": PASSWORD, "code": new_codes[0]},
                    token=rec_sess)
    check("disable accepted", st, 200)
    check("reports disabled", body["enabled"], False)
    st, _ = call("GET", "/v1/dashboard", token=rec_sess)
    check("the session used to disable it is now dead", st, 401)
    st, _ = call("GET", "/v1/dashboard", token=mfa_sess)
    check("every other session is dead too", st, 401)

    st, login = call("POST", "/v1/auth/login",
                     {"email": "owner@example.com", "password": PASSWORD})
    check("password-only login works again", st, 200)
    check_true("and returns a session", login.get("session_token"))

    print("\n-- an operator fault is not reported as a user error --")
    # Simulate a rotated AIBANK_KEY_PEPPER: the sealed secret can no longer be
    # opened. The user must not be told their code is invalid, because no code
    # they ever type can succeed.
    sess2 = login["session_token"]
    st, enrol = call("POST", "/v1/auth/mfa/enrol",
                     {"current_password": PASSWORD}, token=sess2)
    call("POST", "/v1/auth/mfa/confirm", {"code": T.totp(enrol["secret"])},
         token=sess2)
    with bank.write() as conn:
        conn.execute("UPDATE users SET totp_secret_sealed='v1.00.00.00'"
                     " WHERE email='owner@example.com'")
    st, step1 = call("POST", "/v1/auth/login",
                     {"email": "owner@example.com", "password": PASSWORD})
    st, body = call("POST", "/v1/auth/mfa/verify",
                    {"challenge_token": step1["challenge_token"], "code": "123456"})
    check("seal failure is a 500, not a 401", st, 500)
    check("named as mfa_unavailable", body["error"], "mfa_unavailable")
    check_true("and points at the pepper", "AIBANK_KEY_PEPPER" in body["reason"])

    print(f"\n{PASS} passed, {FAIL} failed")
finally:
    httpd.shutdown()
    bank.close()

sys.exit(1 if FAIL else 0)
