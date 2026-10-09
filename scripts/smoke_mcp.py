#!/usr/bin/env python3
"""End-to-end MCP test: a REAL subprocess speaking JSON-RPC over stdio.

Why a subprocess rather than importing `Server` and calling `handle()`: the
thing that ships is a process an MCP client spawns, so the parts most likely to
be wrong are exactly the parts an in-process test skips -- stdio framing, stdout
purity (one stray print and every client fails to parse), env-var credential
handling, and the refusal to boot on the wrong credential type.

The aibank service itself runs in THIS process on a real socket with a fake
Flutterwave, so money moves end to end without touching the network.

    AIBANK_ALLOW_DEV_SECRETS=1 python3 scripts/smoke_mcp.py
"""
from __future__ import annotations

import json
import os
import subprocess
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
from aibank.api import make_handler
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


# ---------------------------------------------------------------- aibank
bank = Bank(D.ephemeral_path(),
            flw=FlutterwaveClient(secret_key="FLWSECK_TEST-x", opener=FakeFLW()))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(bank))
PORT = httpd.server_address[1]
BASE = f"http://127.0.0.1:{PORT}"
threading.Thread(target=httpd.serve_forever, daemon=True).start()


def call(method, path, body=None, token=None, admin=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
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


for _ in range(60):
    try:
        if call("GET", "/health")[0] == 200:
            break
    except Exception:
        time.sleep(0.05)

# Human account holder sets everything up; the agent only spends.
_, u = call("POST", "/v1/auth/register",
            {"email": "mcp@example.com", "password": "correct-horse-battery",
             "display_name": "Kay"})
USER = u["user_id"]
_, lg = call("POST", "/v1/auth/login",
             {"email": "mcp@example.com", "password": "correct-horse-battery"})
SESS = lg["session_token"]

_, ag = call("POST", "/v1/agents",
             {"name": "mcp-agent", "per_txn_max": "50000", "daily_max": "120000",
              "require_approval_above": "40000"}, token=SESS)
AGENT = ag["agent_id"]
AKEY = ag["api_key"]

call("POST", "/v1/wallet/deposit",
     {"user_id": USER, "amount": "500000", "idempotency_key": "d1"}, admin=True)
call("POST", f"/v1/agents/{AGENT}/allocate",
     {"amount": "200000", "idempotency_key": "a1"}, token=SESS)
_, fee = call("POST", "/v1/fees", {"currency": "NGN", "flat_minor": 5000,
                                   "bps": 50}, admin=True)


# ------------------------------------------------------------- MCP harness
class MCP:
    """Spawn the server and speak line-delimited JSON-RPC to it."""

    def __init__(self, **env_extra):
        env = dict(os.environ)
        env["AIBANK_URL"] = BASE
        env["PYTHONPATH"] = ROOT
        env.update(env_extra)
        self.p = subprocess.Popen(
            [sys.executable, "-m", "aibank.mcp_server"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, cwd=ROOT, text=True, bufsize=1)
        self._id = 0

    def rpc(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        if notify:
            return None
        line = self.p.stdout.readline()
        if not line:
            raise AssertionError(
                "server closed stdout; stderr:\n" + self.p.stderr.read())
        return json.loads(line)

    def tool(self, name, **args):
        r = self.rpc("tools/call", {"name": name, "arguments": args})
        res = r.get("result")
        if res is None:
            return {"_rpc_error": r.get("error")}
        out = res.get("structuredContent", {})
        out["_isError"] = res.get("isError", False)
        return out

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()


print("\n-- credential refusal at boot (the model must not hold authority) --")
for label, key in (("no key", ""), ("session token", SESS)):
    p = subprocess.Popen([sys.executable, "-m", "aibank.mcp_server"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True,
                         cwd=ROOT,
                         env={**os.environ, "AIBANK_URL": BASE,
                              "PYTHONPATH": ROOT, "AIBANK_API_KEY": key})
    _, err = p.communicate(timeout=30)
    check(f"refuses to start with {label}", p.returncode != 0, True)
    check(f"{label}: says why", len(err.strip()) > 20, True)

m = MCP(AIBANK_API_KEY=AKEY)

print("\n-- handshake --")
r = m.rpc("initialize", {"protocolVersion": "2025-06-18",
                         "capabilities": {},
                         "clientInfo": {"name": "smoke", "version": "0"}})
check("initialize ok", "result" in r, True)
check("protocol version echoed", r["result"]["protocolVersion"], "2025-06-18")
check("declares tools capability", "tools" in r["result"]["capabilities"], True)
check("server name", r["result"]["serverInfo"]["name"], "aibank")
check("ships instructions", len(r["result"].get("instructions", "")) > 50, True)

m.rpc("notifications/initialized", notify=True)
check("ping answers", "result" in m.rpc("ping"), True)

print("\n-- tools/list --")
r = m.rpc("tools/list")
tools = {t["name"]: t for t in r["result"]["tools"]}
check("pay exposed", "pay" in tools, True)
check("get_balance exposed", "get_balance" in tools, True)
for name, t in tools.items():
    check(f"{name} has inputSchema", t["inputSchema"]["type"], "object")
    check(f"{name} described", len(t.get("description", "")) > 20, True)
check("pay requires idempotency_key",
      "idempotency_key" in tools["pay"]["inputSchema"]["required"], True)

# The structural invariant: no tool may touch policy, approval, or admin.
FORBIDDEN = ("policy", "approve", "fund", "fees", "admin", "deposit",
             "allocate", "freeze", "trial")
leaked = [n for n in tools if any(f in n for f in FORBIDDEN)]
check("no policy/approval/admin tool is exposed", leaked, [])

print("\n-- read-only tools --")
who = m.tool("whoami")
check("whoami identifies the agent", who.get("kind"), "agent")
check("whoami is the right agent", who.get("id"), AGENT)

bal = m.tool("get_balance")
check("balance 200000.00", bal.get("balance"), "200000.00")
check("available reported", "available" in bal, True)

q = m.tool("quote_fee", amount="1000")
# Derived from the schedule, not a literal: 5000 kobo flat + 50bps of 100000.
check("fee quoted server-side", q.get("fee_minor"), 5000 + (100000 * 50) // 10000)

print("\n-- float amounts are refused, not silently rounded --")
bad = m.tool("pay", amount=1000.55, idempotency_key="f1",
             bank_code="058", account_number="0690000031")
check("float amount rejected", bad["_isError"], True)
check("rejection names the type", "float" in bad.get("error", ""), True)
check("no payout created by the rejected call",
      len(m.tool("list_payouts").get("payouts", [])), 0)

print("\n-- missing idempotency key is refused --")
bad = m.tool("pay", amount="100", bank_code="058", account_number="0690000031")
check("idempotency_key required", bad["_isError"], True)

print("\n-- payee flow --")
p = m.tool("add_payee", label="Vendor", bank_code="058",
           account_number="0690000031")
PAYEE = p.get("payee_id")
check("payee created", bool(PAYEE), True)
check("payee listed", len(m.tool("list_payees").get("payees", [])), 1)

print("\n-- pay: under the approval threshold, settles --")
out = m.tool("pay", amount="10000", payee_id=PAYEE, idempotency_key="inv-1",
             narration="invoice 1")
check("submitted", out.get("status"), "submitted")
check("fee charged server-side", out.get("fee_minor"),
      5000 + (1000000 * 50) // 10000)
check("note warns it is not yet delivered",
      "NOT yet confirmed" in out.get("note", ""), True)
PAYOUT1 = out["id"]

print("\n-- idempotency: same key returns the SAME payout --")
again = m.tool("pay", amount="10000", payee_id=PAYEE, idempotency_key="inv-1")
check("same payout id returned", again.get("id"), PAYOUT1)
check("exactly one payout exists",
      len(m.tool("list_payouts").get("payouts", [])), 1)

print("\n-- pay: over the approval threshold, parks for a human --")
out = m.tool("pay", amount="45000", payee_id=PAYEE, idempotency_key="inv-2")
check("pending_approval", out.get("status"), "pending_approval")
check("note says money has not moved",
      out.get("note", "").startswith("MONEY HAS NOT MOVED"), True)
PARKED = out["id"]

print("\n-- health reports the current schema --")
s, h = call("GET", "/health")
check("health 200", s, 200)
from aibank import db as _D
check("health reports the code's schema head", h.get("schema"), _D.SCHEMA_VERSION)

print("\n-- the agent cannot approve its own parked payout --")
s, _ = call("POST", f"/v1/payouts/{PARKED}/approve", {}, token=AKEY)
check("agent key on approve -> 401", s, 401)
check("still parked after the attempt",
      m.tool("get_payout", payout_id=PARKED).get("status"), "pending_approval")
# ...and the human can.
s, b = call("POST", f"/v1/payouts/{PARKED}/approve", {}, token=SESS)
check("human approves 200", s, 200)
check("agent now sees it submitted",
      m.tool("get_payout", payout_id=PARKED).get("status") in
      ("submitted", "successful"), True)

print("\n-- policy denial is reported as final, with guidance --")
out = m.tool("pay", amount="90000", payee_id=PAYEE, idempotency_key="inv-3")
check("isError", out["_isError"], True)
check("http 403 surfaced", out.get("http_status"), 403)
err = out.get("error", "")
check("told not to retry", "Do not retry" in err, True)
check("told not to split the amount", "split the amount" in err, True)
check("machine code preserved alongside the guidance",
      out.get("code"), "policy_denied")
check("the real limit reason is quoted", "per-transaction" in err.lower(), True)

print("\n-- the agent sees only a masked destination --")
got = m.tool("get_payout", payout_id=PAYOUT1)
check("destination masked for the agent too", got.get("destination"),
      "******0031")
check("no full account number anywhere in the tool result",
      "0690000031" in json.dumps(got), False)

print("\n-- another agent's payout is not readable --")
_, ag2 = call("POST", "/v1/agents", {"name": "other"}, token=SESS)
m2 = MCP(AIBANK_API_KEY=ag2["api_key"])
m2.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "s", "version": "0"}})
other = m2.tool("get_payout", payout_id=PAYOUT1)
check("cross-agent read isError", other["_isError"], True)
check("cross-agent read is 404 not 403", other.get("http_status"), 404)
check("other agent sees no payouts",
      len(m2.tool("list_payouts").get("payouts", [])), 0)
m2.close()

print("\n-- protocol errors are distinct from tool errors --")
r = m.rpc("tools/call", {"name": "definitely_not_a_tool", "arguments": {}})
check("unknown tool -> JSON-RPC error", "error" in r, True)
check("unknown tool code", r["error"]["code"], -32602)
r = m.rpc("nonexistent/method")
check("unknown method -> -32601", r["error"]["code"], -32601)

print("\n-- notifications get no reply (a reply desynchronises the client) --")
m.rpc("notifications/cancelled", {"requestId": 1}, notify=True)
check("still in sync after a notification", "result" in m.rpc("ping"), True)

print("\n-- malformed input does not kill the server --")
m.p.stdin.write("this is not json\n")
m.p.stdin.flush()
r = json.loads(m.p.stdout.readline())
check("parse error reported", r["error"]["code"], -32700)
check("server alive after parse error", "result" in m.rpc("ping"), True)

print("\n-- read-only mode hides every money-moving tool --")
m3 = MCP(AIBANK_API_KEY=AKEY, AIBANK_MCP_READONLY="1")
m3.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "s", "version": "0"}})
names = {t["name"] for t in m3.rpc("tools/list")["result"]["tools"]}
check("pay hidden", "pay" in names, False)
check("add_payee hidden", "add_payee" in names, False)
check("get_balance still there", "get_balance" in names, True)
r = m3.rpc("tools/call", {"name": "pay", "arguments": {"amount": "1",
                                                       "idempotency_key": "x"}})
check("hidden pay refused", "error" in r, True)
check("refusal explains read-only", "read-only" in r["error"]["message"], True)
m3.close()

print("\n-- unreachable service: warns against a fresh-key retry --")
m4 = MCP(AIBANK_API_KEY=AKEY, AIBANK_URL="http://127.0.0.1:1",
         AIBANK_MCP_TIMEOUT="3")
m4.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                      "clientInfo": {"name": "s", "version": "0"}})
out = m4.tool("pay", amount="100", payee_id=PAYEE, idempotency_key="inv-9")
check("transport failure isError", out["_isError"], True)
check("warns the request may have applied",
      "may or may not" in out.get("error", ""), True)
check("tells it to reuse the same key",
      "SAME key" in out.get("error", ""), True)
m4.close()

print("\n-- stdout carried protocol frames only --")
m.close()
stderr = m.p.stderr.read()
check("startup log went to stderr", "aibank MCP server" in stderr, True)

print("\n-- the books still balance after everything above --")
s, tb = call("GET", "/v1/admin/trial-balance", admin=True)
check("trial balance 0", tb.get("net_minor"), 0)
check("balanced", tb.get("balanced"), True)

print("\n" + "=" * 52)
print(f"{PASS} passed, {FAIL} failed")
print("=" * 52)
httpd.shutdown()
bank.close()
sys.exit(1 if FAIL else 0)
