#!/usr/bin/env python3
"""End-to-end test of the DASHBOARD's contract with the API.

There is no browser on this host, and a headless browser is not a dependency
this project will take. So rather than pretend to test rendering, this script
tests the thing that actually breaks: the dashboard calling an endpoint that
does not exist, or that returns a shape the page does not expect.

Method, in two halves:

  1. EXTRACT every API call site out of dashboard.html by parsing the source,
     and assert each one is covered by an exercised case below. A new fetch
     added to the page with no test fails this script -- which is what stops
     "built but unreachable" from recurring.
  2. EXERCISE each endpoint against a real server on a real socket with a real
     session, asserting the status AND the specific fields the page reads.

Plus static XSS guards on the page itself (no innerHTML, no inline handlers).

    AIBANK_ALLOW_DEV_SECRETS=1 python3 scripts/smoke_dashboard.py
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("AIBANK_ALLOW_DEV_SECRETS", "1")
os.environ.setdefault("AIBANK_SCRYPT_N", "1024")
os.environ.setdefault("AIBANK_ADMIN_KEY", "test-admin-key")
os.environ.setdefault("AIBANK_KEY_PEPPER", "test-pepper")

from aibank import db as D
from aibank.api import STATIC_DIR, make_handler
from aibank.bank import Bank
from aibank.flutterwave import FlutterwaveClient
from tests.fake_flw import FakeFLW

PASS, FAIL = 0, 0


def check(label, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  ok   {label}")
    else:
        FAIL += 1
        print(f"  FAIL {label}: got {got!r}, want {want!r}")


bank = Bank(D.ephemeral_path(),
            flw=FlutterwaveClient(secret_key="FLWSECK_TEST-x", opener=FakeFLW()))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(bank))
PORT = httpd.server_address[1]
BASE = f"http://127.0.0.1:{PORT}"
threading.Thread(target=httpd.serve_forever, daemon=True).start()


def raw(method, path, body=None, token=None, admin=False, idem=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if admin:
        req.add_header("X-Admin-Key", os.environ["AIBANK_ADMIN_KEY"])
    if idem:
        req.add_header("Idempotency-Key", idem)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def call(method, path, body=None, **kw):
    s, b, h = raw(method, path, body, **kw)
    try:
        return s, json.loads(b or b"{}")
    except ValueError:
        return s, {}


for _ in range(60):
    try:
        if call("GET", "/health")[0] == 200:
            break
    except Exception:
        time.sleep(0.05)

# ---------------------------------------------------------------------------
HTML = (STATIC_DIR / "dashboard.html").read_text()

# Every endpoint this script hits on the dashboard's behalf, recorded so the
# coverage check at the end can prove no call site in the page went untested.
EXERCISED: list[tuple[str, str]] = []


def ex(label, method, path, body=None, **kw):
    """Exercise an endpoint the dashboard calls, and record the coverage."""
    s, b = call(method, path, body, **kw)
    EXERCISED.append((method, path))
    return s, b

print("\n-- the page is served, with banking-grade headers --")
s, body, hdr = raw("GET", "/")
check("GET / is 200", s, 200)
check("served as html", hdr.get("Content-Type", "").startswith("text/html"), True)
check("is the dashboard", b"ai<span" in body, True)
check("CSP present", "Content-Security-Policy" in hdr, True)
csp = hdr.get("Content-Security-Policy", "")
check("CSP blocks external fetches", "connect-src 'self'" in csp, True)
check("CSP denies framing (clickjacked Approve)",
      "frame-ancestors 'none'" in csp, True)
check("CSP default-src none", "default-src 'none'" in csp, True)
check("nosniff", hdr.get("X-Content-Type-Options"), "nosniff")
check("no-store", hdr.get("Cache-Control"), "no-store")
check("no referrer leak", hdr.get("Referrer-Policy"), "no-referrer")
check("/dashboard also serves it", raw("GET", "/dashboard")[0], 200)
check("API responses carry the headers too",
      raw("GET", "/health")[2].get("X-Content-Type-Options"), "nosniff")

print("\n-- static asset route cannot be walked out of --")
for evil in ("/../api.py", "/static/../api.py", "/dashboard/../../api.py",
             "/%2e%2e/api.py"):
    s, b, _ = raw("GET", evil)
    check(f"{evil} does not serve source", b"def serve(" in b, False)

print("\n-- page-level XSS guards --")
# Every value rendered comes from the API; one innerHTML would make a narration
# field executable.
check("no innerHTML assignment", re.search(r"\.innerHTML\s*=", HTML), None)
check("no outerHTML assignment", re.search(r"\.outerHTML\s*=", HTML), None)
check("no document.write", "document.write" in HTML, False)
check("no eval", re.search(r"\beval\s*\(", HTML), None)
check("no inline on* handlers",
      re.search(r"<[^>]+\son[a-z]+\s*=", HTML, re.I), None)
check("no external script/link tags",
      re.search(r"<(script|link)[^>]+(src|href)\s*=\s*[\"']https?:", HTML, re.I),
      None)
# Look for the API, not the word: the header comment explains WHY localStorage
# is not used, and matching on the bare string flagged its own documentation.
check("token kept in sessionStorage, not localStorage",
      re.search(r"localStorage\.", HTML), None)
check("sessionStorage is what is actually used",
      "sessionStorage.setItem" in HTML, True)
# Interpolating an id straight into a URL is how a crafted id escapes the path.
# NOTE on the regex: a lookahead after `\s*` is useless, because `\s*` happily
# backtracks to zero width and lets the lookahead pass at the space. Capture the
# following token instead and compare it.
ids_in_urls = [m for m in re.findall(r'"(/v1/[^"]*)"\s*\+\s*(\w+)', HTML)
               if m[1] != "encodeURIComponent"]
check("every id interpolated into a URL is encoded", ids_in_urls, [])
check("the encoding check actually matched something",
      len(re.findall(r'"/v1/[^"]*"\s*\+\s*encodeURIComponent', HTML)) >= 5, True)

# ---------------------------------------------------------------------------
print("\n-- set up a real account, agent and payment --")
s, u = call("POST", "/v1/auth/register",
            {"email": "dash@example.com", "password": "correct-horse-battery",
             "display_name": "Kay"})
check("register 201", s, 201)
USER = u["user_id"]
s, lg = call("POST", "/v1/auth/login",
             {"email": "dash@example.com", "password": "correct-horse-battery"})
SESS = lg["session_token"]

s, ag = call("POST", "/v1/agents",
             {"name": "dash-agent", "per_txn_max": "50000",
              "daily_max": "150000", "require_approval_above": "30000",
              "tz_offset_minutes": 60}, token=SESS)
check("create agent 201", s, 201)
EXERCISED.append(("POST", "/v1/agents"))
AGENT, AKEY = ag["agent_id"], ag["api_key"]
check("new agent returns a key once", AKEY.startswith("sk_agent_"), True)

call("POST", "/v1/wallet/deposit",
     {"user_id": USER, "amount": "400000", "idempotency_key": "d1"}, admin=True)
call("POST", "/v1/fees", {"currency": "NGN", "flat_minor": 5000, "bps": 50},
     admin=True)

print("\n-- /v1/dashboard: every panel the page renders --")
s, dash = ex("dashboard", "GET", "/v1/dashboard", token=SESS)
check("dashboard 200", s, 200)
for field in ("user", "wallet", "agents", "pending_approvals", "recent_payouts"):
    check(f"dashboard.{field} present", field in dash, True)
check("user.email rendered by the header",
      dash["user"].get("email"), "dash@example.com")
check("wallet.balance is a decimal string",
      dash["wallet"].get("balance"), "400000.00")
check("wallet.currency present", dash["wallet"].get("currency"), "NGN")
check("one agent listed", len(dash["agents"]), 1)
a0 = dash["agents"][0]
for field in ("id", "name", "status", "policy", "balance", "currency"):
    check(f"agent.{field} present (page reads it)", field in a0, True)
check("agent.balance.available present", "available" in a0["balance"], True)
check("agent.balance.held present", "held" in a0["balance"], True)
check("agent.policy.per_txn_max present", "per_txn_max" in (a0["policy"] or {}), True)

print("\n-- allocate / withdraw (the Move funds tab) --")
s, b = ex("allocate", "POST", f"/v1/agents/{AGENT}/allocate",
          {"amount": "100000", "currency": "NGN", "idempotency_key": "al-1"},
          token=SESS)
check("allocate 201", s, 201)
s, b = call("POST", f"/v1/agents/{AGENT}/allocate",
            {"amount": "100000", "currency": "NGN", "idempotency_key": "al-1"},
            token=SESS)
check("double-click allocate does not move money twice", s in (200, 201, 409), True)
_, bal = call("GET", "/v1/dashboard", token=SESS)
check("agent holds exactly one allocation",
      bal["agents"][0]["balance"]["balance"], "100000.00")

s, b = ex("withdraw", "POST", f"/v1/agents/{AGENT}/withdraw",
          {"amount": "20000", "currency": "NGN", "idempotency_key": "wd-1"},
          token=SESS)
check("withdraw 201", s, 201)

print("\n-- agent detail (keys + payees tabs) --")
s, det = ex("agent_detail", "GET", f"/v1/agents/{AGENT}", token=SESS)
check("agent detail 200", s, 200)
check("keys listed", len(det.get("keys", [])), 1)
for field in ("key_prefix", "label", "created_at", "revoked_at"):
    check(f"key.{field} present (table column)", field in det["keys"][0], True)
check("payees key present", "payees" in det, True)

s, k = ex("issue_key", "POST", f"/v1/agents/{AGENT}/keys", {"label": "laptop"},
          token=SESS)
check("issue key 201", s, 201)
check("key shown once", k.get("api_key", "").startswith("sk_agent_"), True)
NEWPFX = k["key_prefix"]
s, r = ex("revoke_key", "POST", f"/v1/agents/{AGENT}/keys", {"revoke": NEWPFX},
          token=SESS)
check("revoke 200", s, 200)
check("revoked", r.get("revoked"), True)
check("revoked key no longer authenticates",
      call("GET", "/v1/balance", token=k["api_key"])[0], 401)

print("\n-- policy GET/POST (the Limits tab, the whole security model) --")
s, pol = ex("get_policy", "GET", f"/v1/agents/{AGENT}/policy", token=SESS)
check("policy 200", s, 200)
for field in ("per_txn_max", "daily_max", "monthly_max",
              "require_approval_above", "max_payouts_per_day",
              "allowlist_only", "tz_offset_minutes", "currency"):
    check(f"policy.{field} present (form field)", field in pol, True)

s, pol = ex("set_policy", "POST", f"/v1/agents/{AGENT}/policy",
            {"currency": "NGN", "per_txn_max": "40000", "daily_max": "150000",
             "require_approval_above": "30000", "max_payouts_per_day": "5",
             "allowlist_only": False, "tz_offset_minutes": 60}, token=SESS)
check("set policy 200", s, 200)
check("limit actually changed", pol.get("per_txn_max"), "40000.00")
check("blank field means no limit", pol.get("monthly_max"), None)

print("\n-- and the agent still cannot reach that form's endpoint --")
check("agent key on policy GET -> 401",
      call("GET", f"/v1/agents/{AGENT}/policy", token=AKEY)[0], 401)
check("agent key on policy POST -> 401",
      call("POST", f"/v1/agents/{AGENT}/policy",
           {"per_txn_max": "99999999"}, token=AKEY)[0], 401)
check("limit unchanged by the agent's attempt",
      call("GET", f"/v1/agents/{AGENT}/policy", token=SESS)[1]["per_txn_max"],
      "40000.00")

print("\n-- statement tab --")
s, st = ex("statement", "GET", f"/v1/agents/{AGENT}/statement?limit=50",
           token=SESS)
check("statement 200", s, 200)
check("lines present", len(st.get("lines", [])) >= 2, True)
for field in ("created_at", "kind", "memo", "amount", "running"):
    check(f"statement line.{field} present (table column)",
          field in st["lines"][0], True)

print("\n-- payments: agent spends, dashboard shows and decides --")
s, p1 = call("POST", "/v1/payouts",
             {"amount": "10000", "bank_code": "058",
              "account_number": "0690000031", "narration": "invoice 1"},
             token=AKEY, idem="inv-1")
check("agent payment submitted", p1.get("status"), "submitted")
s, p2 = call("POST", "/v1/payouts",
             {"amount": "35000", "bank_code": "058",
              "account_number": "0690000031", "narration": "big one"},
             token=AKEY, idem="inv-2")
check("over threshold parks", p2.get("status"), "pending_approval")

s, dash = call("GET", "/v1/dashboard", token=SESS)
pend = dash["pending_approvals"]
check("dashboard surfaces the parked payment", len(pend), 1)
for field in ("id", "amount", "fee", "currency", "agent_name",
              "narration", "created_at", "destination", "dest_bank_code"):
    check(f"approval.{field} present (card field)", field in pend[0], True)
check("approval shows which agent", pend[0]["agent_name"], "dash-agent")
# The card shows where the money is going -- masked, because the page and its
# logs are not a place for a full account number.
check("destination shown masked", pend[0]["destination"], "******0031")
check("full account number is not in the payload",
      "0690000031" in json.dumps(dash), False)
check("this payout had no saved payee at all", pend[0]["payee_id"], None)

print("\n-- approve / reject from the dashboard --")
s, b = ex("approve", "POST", f"/v1/payouts/{p2['id']}/approve", {}, token=SESS)
check("approve 200", s, 200)
# This is the v3 regression: p2 was paid to a raw bank_code/account_number with
# no saved payee, so the old code could not resolve a destination at approval
# time and the human could never release it.
check("raw-destination payout was approvable",
      b.get("status") in ("submitted", "successful"), True)
check("no longer pending",
      len(call("GET", "/v1/dashboard", token=SESS)[1]["pending_approvals"]), 0)

s, p3 = call("POST", "/v1/payouts",
             {"amount": "33000", "bank_code": "058",
              "account_number": "0690000031"}, token=AKEY, idem="inv-3")
check("another parks", p3.get("status"), "pending_approval")
s, b = ex("reject", "POST", f"/v1/payouts/{p3['id']}/reject",
          {"reason": "not approved"}, token=SESS)
check("reject 200", s, 200)
check("rejected", b.get("status"), "rejected")

print("\n-- reconcile and refund buttons --")
s, p4 = call("POST", "/v1/payouts",
             {"amount": "5000", "bank_code": "058",
              "account_number": "0690000031"}, token=AKEY, idem="inv-4")
s, b = ex("reconcile", "POST", f"/v1/payouts/{p4['id']}/reconcile", {},
          token=SESS)
check("reconcile 200", s, 200)
check("provider verdict returned", b.get("status"), "SUCCESSFUL")

s, dash = call("GET", "/v1/dashboard", token=SESS)
done = [p for p in dash["recent_payouts"] if p["status"] == "successful"]
check("a successful payment is listed", len(done) >= 1, True)
for field in ("id", "created_at", "amount", "fee", "status", "narration"):
    check(f"payout.{field} present (table column)",
          field in dash["recent_payouts"][0], True)
s, b = ex("refund", "POST", f"/v1/payouts/{done[0]['id']}/refund",
          {"reason": "refunded from dashboard"}, token=SESS)
check("refund 200", s, 200)
check("refunded", b.get("status"), "refunded")

print("\n-- freeze / unfreeze --")
s, b = ex("freeze", "POST", f"/v1/agents/{AGENT}/freeze", {"frozen": True},
          token=SESS)
check("freeze 200", s, 200)
check("frozen agent cannot spend",
      call("POST", "/v1/payouts",
           {"amount": "100", "bank_code": "058", "account_number": "0690000031"},
           token=AKEY, idem="inv-f")[0], 403)
call("POST", f"/v1/agents/{AGENT}/freeze", {"frozen": False}, token=SESS)

print("\n-- auth routes the page uses --")
s, b = ex("register", "POST", "/v1/auth/register",
          {"email": "two@example.com", "password": "another-long-password"})
check("register 201", s, 201)
s, b = ex("login", "POST", "/v1/auth/login",
          {"email": "two@example.com", "password": "another-long-password"})
check("login 200", s, 200)
T2 = b["session_token"]
s, b = ex("logout", "POST", "/v1/auth/logout", {}, token=T2)
check("logout 200", s, 200)
check("token dead after logout", call("GET", "/v1/dashboard", token=T2)[0], 401)
s, b = ex("health", "GET", "/health")
check("health 200", s, 200)
s, b = ex("wallet", "GET", "/v1/wallet?currency=NGN", token=SESS)
check("wallet 200", s, 200)
s, b = ex("agents_list", "GET", "/v1/agents", token=SESS)
check("agents list 200", s, 200)
s, b = ex("payouts_list", "GET", "/v1/payouts?limit=50", token=SESS)
check("payouts list 200", s, 200)

print("\n-- the second account sees none of the first's data --")
s, b = call("POST", "/v1/auth/login",
            {"email": "two@example.com", "password": "another-long-password"})
T2 = b["session_token"]
check("other user's dashboard is empty",
      len(call("GET", "/v1/dashboard", token=T2)[1]["agents"]), 0)
check("other user cannot read the agent -> 404",
      call("GET", f"/v1/agents/{AGENT}", token=T2)[0], 404)
check("other user cannot set its policy -> 404",
      call("POST", f"/v1/agents/{AGENT}/policy",
           {"per_txn_max": "99999999"}, token=T2)[0], 404)
check("other user cannot approve into it -> 404",
      call("POST", f"/v1/payouts/{p1['id']}/approve", {}, token=T2)[0], 404)
check("other user cannot allocate to it -> 404",
      call("POST", f"/v1/agents/{AGENT}/allocate",
           {"amount": "1", "idempotency_key": "x"}, token=T2)[0], 404)

# ---------------------------------------------------------------------------
print("\n-- COVERAGE: every call site in the page is exercised above --")
# Parse the page's fetch sites into comparable route shapes. Two forms exist:
#   api("GET", "/v1/dashboard")
#   api("POST", "/v1/agents/" + encodeURIComponent(id) + "/policy", ...)
# The second must be matched FIRST and its prefix fragment ("/v1/agents/")
# removed from consideration, or the literal-form regex also matches that same
# prefix and reports a phantom uncovered route called "POST /v1/agents/".
called: set[tuple[str, str]] = set()
consumed: set[tuple[str, str]] = set()

for m, p, tail in re.findall(
        r'api\(\s*"(GET|POST)"\s*,\s*"([^"]+)"\s*\+\s*encodeURIComponent\('
        r'[^)]*\)\s*(?:\+\s*"([^"]*)")?', HTML):
    called.add((m, p.rstrip("/") + "/{id}" + (tail or "")))
    consumed.add((m, p))

for m, p in re.findall(r'api\(\s*"(GET|POST)"\s*,\s*"([^"]+)"', HTML):
    if (m, p) in consumed:
        continue
    called.add((m, p))

# Two call sites end in a VARIABLE, not a literal: the Move-funds buttons share
# one function over allocate|withdraw, and the approval buttons share one over
# approve|reject. The extractor sees ".../{id}/" and cannot know the tails, so
# they are enumerated here and each must be exercised individually -- which is
# the point, since a shared handler is exactly where one of the two branches
# goes untested.
DYNAMIC_TAILS = {
    ("POST", "/v1/agents/{id}/"): ["allocate", "withdraw"],
    ("POST", "/v1/payouts/{id}/"): ["approve", "reject"],
}
for key, tails in DYNAMIC_TAILS.items():
    if key in called:
        called.discard(key)
        for t in tails:
            called.add((key[0], key[1] + t))


def norm(method: str, path: str) -> tuple[str, str]:
    p = path.split("?")[0]
    p = p.replace(AGENT, "{id}")
    p = re.sub(r"payout_[0-9a-f]+", "{id}", p)
    return (method, p.rstrip("/") or "/")


exercised_norm = {norm(m, p) for m, p in EXERCISED}
missing = [f"{m} {p}" for m, p in sorted(called)
           if (m, p.split("?")[0].rstrip("/") or "/") not in exercised_norm]
check("no dashboard call site is untested", missing, [])
check("the coverage extractor found the page's call sites",
      len(called) >= 15, True)
print(f"       ({len(called)} call sites in the page, "
      f"{len(exercised_norm)} endpoints exercised)")

print("\n-- the books balance after everything the dashboard did --")
s, tb = call("GET", "/v1/admin/trial-balance", admin=True)
check("trial balance 0", tb.get("net_minor"), 0)
check("balanced", tb.get("balanced"), True)

print("\n" + "=" * 52)
print(f"{PASS} passed, {FAIL} failed")
print("=" * 52)
httpd.shutdown()
bank.close()
sys.exit(1 if FAIL else 0)
