#!/usr/bin/env python3
"""End-to-end HTTP smoke test against a REAL server on a real socket.

The unit tests exercise the Bank object directly. This exercises the thing a
customer actually talks to: routing, status codes, header auth, and the three
trust domains. Run it against a throwaway database:

    AIBANK_ALLOW_DEV_SECRETS=1 python scripts/smoke_http.py

Exit code 0 means every assertion below passed.
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
from aibank.api import make_handler
from aibank.bank import Bank
from aibank.flutterwave import FlutterwaveClient
from tests.fake_flw import FakeFLW

PASS, FAIL = 0, 0


def check(label: str, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  ok   {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label}: got {got!r}, want {want!r}")


def call(method, path, body=None, token=None, admin=False, idem=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if admin:
        req.add_header("X-Admin-Key", os.environ["AIBANK_ADMIN_KEY"])
    if idem:
        req.add_header("Idempotency-Key", idem)
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

# Readiness check instead of a blind sleep.
for _ in range(50):
    try:
        if call("GET", "/health")[0] == 200:
            break
    except Exception:
        time.sleep(0.05)

print("\n-- public --")
s, b = call("GET", "/health")
check("health 200", s, 200)
# Pinned to db.SCHEMA_VERSION, never a literal: a hard-coded version turns
# every future migration into a false test failure.
check("health reports the current schema", b.get("schema"), D.SCHEMA_VERSION)
check("unknown route 404", call("GET", "/v1/nope")[0], 404)

print("\n-- registration & login --")
s, b = call("POST", "/v1/auth/register",
            {"email": "Kay@Example.com", "password": "correct-horse-battery",
             "display_name": "Kay"})
check("register 201", s, 201)
check("email normalised", b.get("email"), "kay@example.com")
USER = b["user_id"]

check("weak password 401/400",
      call("POST", "/v1/auth/register",
           {"email": "x@y.com", "password": "short"})[0] in (400, 401), True)
check("duplicate email rejected",
      call("POST", "/v1/auth/register",
           {"email": "kay@example.com", "password": "another-long-pass"})[0] in (400, 401),
      True)

s, b = call("POST", "/v1/auth/login",
            {"email": "kay@example.com", "password": "correct-horse-battery"})
check("login 200", s, 200)
SESS = b["session_token"]
check("session token shape", SESS.startswith("sess_"), True)

check("bad password 401",
      call("POST", "/v1/auth/login",
           {"email": "kay@example.com", "password": "wrong-password-xx"})[0], 401)

print("\n-- session-protected routes reject anonymous & agent creds --")
check("dashboard without token 401", call("GET", "/v1/dashboard")[0], 401)
check("dashboard with garbage token 401",
      call("GET", "/v1/dashboard", token="sess_garbage")[0], 401)

print("\n-- agent creation (user domain) --")
s, b = call("POST", "/v1/agents",
            {"name": "buyer", "currency": "NGN", "daily_max": "50000",
             "require_approval_above": "20000", "max_payouts_per_day": 5},
            token=SESS)
check("create agent 201", s, 201)
AGENT = b["agent_id"]
AKEY = b["api_key"]
check("agent is owned by the user", b["user_id"], USER)

s, b = call("GET", "/v1/agents", token=SESS)
check("agent list 200", s, 200)
check("one agent listed", len(b["agents"]), 1)

print("\n-- THE invariant: agent key cannot read or write policy --")
check("agent key on policy GET -> 401", call("GET", f"/v1/agents/{AGENT}/policy",
                                             token=AKEY)[0], 401)
s, b = call("POST", f"/v1/agents/{AGENT}/policy",
            {"currency": "NGN", "daily_max": "99999999"}, token=AKEY)
check("agent key on policy POST -> 401", s, 401)
s, b = call("GET", f"/v1/agents/{AGENT}/policy", token=SESS)
check("user reads policy 200", s, 200)
check("limit unchanged by the agent's attempt", b["daily_max_minor"], 5_000_000)

print("\n-- funding: user wallet -> agent --")
check("customer cannot credit their own wallet",
      call("POST", "/v1/wallet/deposit",
           {"user_id": USER, "amount": "100000"}, token=SESS)[0], 401)
s, b = call("POST", "/v1/wallet/deposit",
            {"user_id": USER, "amount": "100000"}, admin=True)
check("admin deposit 201", s, 201)
check("wallet credited", b["balance"]["balance_minor"], 10_000_000)

s, b = call("POST", f"/v1/agents/{AGENT}/allocate", {"amount": "40000"}, token=SESS)
check("allocate 201", s, 201)
check("agent funded", b["agent_balance"]["balance_minor"], 4_000_000)
check("user debited", b["user_balance"]["balance_minor"], 6_000_000)

s, b = call("POST", f"/v1/agents/{AGENT}/allocate", {"amount": "999999"}, token=SESS)
check("over-allocation 402", s, 402)

print("\n-- pricing is server-side --")
s, _ = call("POST", "/v1/fees", {"currency": "NGN", "flat_minor": 5000, "bps": 50},
            admin=True)
check("set fee schedule 200", s, 200)
check("agent cannot set fees", call("POST", "/v1/fees",
                                    {"currency": "NGN", "flat_minor": 0},
                                    token=AKEY)[0], 401)
s, b = call("GET", "/v1/quote?amount=10000&currency=NGN", token=AKEY)
check("quote 200", s, 200)
check("quote = 5000 flat + 0.5%", b["fee_minor"], 5000 + (1_000_000 * 50) // 10_000)

print("\n-- agent domain: payees and payouts --")
s, b = call("POST", "/v1/payees",
            {"label": "vendor", "bank_code": "058", "account_number": "0690000031"},
            token=AKEY)
check("add payee 201", s, 201)
PAYEE = b["payee_id"]

check("session token cannot act as an agent",
      call("POST", "/v1/payees",
           {"label": "x", "bank_code": "058", "account_number": "0690000032"},
           token=SESS)[0], 401)

s, b = call("POST", "/v1/payouts",
            {"amount": "1000", "payee_id": PAYEE, "fee": "0"},
            token=AKEY, idem="idem-1")
check("small payout 201", s, 201)
check("submitted without approval", b["status"], "submitted")
# 1,000 NGN = 100,000 kobo -> 5000 flat + 0.5% (500) = 5500. The caller asked
# for a fee of 0 and did not get it.
check("fee was NOT the caller's 0", b["fee_minor"], 5000 + (100_000 * 50) // 10_000)
P1 = b["id"]

s, b = call("POST", "/v1/payouts",
            {"amount": "1000", "payee_id": PAYEE}, token=AKEY, idem="idem-1")
check("replayed idempotency key returns the same payout", b["id"], P1)

s, b = call("POST", "/v1/payouts", {"amount": "999999", "payee_id": PAYEE}, token=AKEY)
check("over-limit payout 403", s, 403)

print("\n-- approval workflow --")
s, b = call("POST", "/v1/payouts", {"amount": "30000", "payee_id": PAYEE}, token=AKEY)
check("large payout held 201", s, 201)
check("status pending_approval", b["status"], "pending_approval")
P2 = b["id"]

check("agent cannot approve its own payout",
      call("POST", f"/v1/payouts/{P2}/approve", {}, token=AKEY)[0], 401)

s, b = call("GET", "/v1/approvals", token=SESS)
check("approvals listed for the human", [p["id"] for p in b["pending"]], [P2])

s, b = call("POST", f"/v1/payouts/{P2}/approve", {"reason": "ok"}, token=SESS)
check("human approves 200", s, 200)
check("now submitted", b["status"], "submitted")
check("approver recorded", b["approved_by"], USER)

print("\n-- cross-tenant isolation (TIER 1) --")
call("POST", "/v1/auth/register", {"email": "eve@example.com",
                                   "password": "eve-long-password"})
s, b = call("POST", "/v1/auth/login", {"email": "eve@example.com",
                                       "password": "eve-long-password"})
EVE_SESS = b["session_token"]
s, b = call("POST", "/v1/agents", {"name": "eve-agent", "daily_max": "1000"},
            token=EVE_SESS)
EVE_KEY = b["api_key"]
EVE_AGENT = b["agent_id"]

check("eve's agent key cannot read kay's payout",
      call("GET", f"/v1/payouts/{P1}", token=EVE_KEY)[0], 404)
check("eve's session cannot read kay's payout",
      call("GET", f"/v1/payouts/{P1}", token=EVE_SESS)[0], 404)
check("eve cannot read kay's agent policy",
      call("GET", f"/v1/agents/{AGENT}/policy", token=EVE_SESS)[0], 404)
check("eve cannot fund kay's agent",
      call("POST", f"/v1/agents/{AGENT}/allocate", {"amount": "1"}, token=EVE_SESS)[0],
      404)
check("eve cannot approve kay's payout",
      call("POST", f"/v1/payouts/{P2}/approve", {}, token=EVE_SESS)[0], 404)
check("eve's payout list is empty",
      len(call("GET", "/v1/payouts", token=EVE_SESS)[1]["payouts"]), 0)
check("owner CAN read own payout",
      call("GET", f"/v1/payouts/{P1}", token=AKEY)[0], 200)

print("\n-- key rotation --")
s, b = call("POST", f"/v1/agents/{AGENT}/keys", {"label": "ci"}, token=SESS)
check("issue key 201", s, 201)
NEWKEY, NEWPREFIX = b["api_key"], b["key_prefix"]
check("new key works", call("GET", "/v1/balance", token=NEWKEY)[0], 200)
s, _ = call("POST", f"/v1/agents/{AGENT}/keys", {"revoke": NEWPREFIX}, token=SESS)
check("revoke 200", s, 200)
check("revoked key rejected", call("GET", "/v1/balance", token=NEWKEY)[0], 401)
check("original key still works", call("GET", "/v1/balance", token=AKEY)[0], 200)

print("\n-- freeze stops spending --")
s, _ = call("POST", f"/v1/agents/{AGENT}/freeze", {"frozen": True}, token=SESS)
check("freeze 200", s, 200)
check("frozen agent denied 403",
      call("POST", "/v1/payouts", {"amount": "10", "payee_id": PAYEE}, token=AKEY)[0],
      403)
call("POST", f"/v1/agents/{AGENT}/freeze", {"frozen": False}, token=SESS)

print("\n-- statement, dashboard, admin --")
s, b = call("GET", f"/v1/agents/{AGENT}/statement", token=SESS)
check("statement 200", s, 200)
check("statement has lines", len(b["lines"]) > 0, True)
s, b = call("GET", "/v1/dashboard", token=SESS)
check("dashboard 200", s, 200)
check("dashboard has every panel",
      sorted(b.keys()),
      ["agents", "pending_approvals", "recent_payouts", "user", "wallet"])
s, b = call("GET", "/v1/admin/trial-balance", admin=True)
check("trial balance 200", s, 200)
check("BOOKS BALANCE", b["balanced"], True)
check("non-admin blocked from trial balance",
      call("GET", "/v1/admin/trial-balance", token=SESS)[0], 401)
s, b = call("POST", "/v1/admin/sweep-holds", {}, admin=True)
check("sweeper callable 200", s, 200)

print("\n-- webhook signature --")
s, _ = call("POST", "/v1/webhooks/flutterwave",
            {"event": "transfer.completed", "data": {"id": 9, "reference": "x",
                                                     "status": "SUCCESSFUL"}})
check("unsigned webhook rejected 401", s, 401)

print("\n-- error hygiene --")
s, b = call("POST", "/v1/payouts", {"amount": "not-a-number", "payee_id": PAYEE},
            token=AKEY)
check("bad amount 400", s, 400)
s, b = call("GET", "/v1/payouts/payout_doesnotexist", token=AKEY)
check("unknown payout 404", s, 404)

print("\n-- password change kills sessions --")
s, _ = call("POST", "/v1/auth/password",
            {"current_password": "wrong-one-here", "new_password": "brand-new-password"},
            token=SESS)
check("wrong current password 401", s, 401)
s, _ = call("POST", "/v1/auth/password",
            {"current_password": "correct-horse-battery",
             "new_password": "brand-new-password"}, token=SESS)
check("password change 200", s, 200)
check("old session now rejected", call("GET", "/v1/dashboard", token=SESS)[0], 401)
s, _ = call("POST", "/v1/auth/login", {"email": "kay@example.com",
                                       "password": "brand-new-password"})
check("login with new password 200", s, 200)

httpd.shutdown()
bank.close()

print(f"\n{'='*52}\n{PASS} passed, {FAIL} failed\n{'='*52}")
sys.exit(1 if FAIL else 0)
