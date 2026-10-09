#!/usr/bin/env python3
"""Boot a real aibank server with seeded data, then run the DOM check on it.

Separate from smoke_dashboard.py because this half needs node, which may not
exist on every host. It skips cleanly (exit 0, with a message) when node is
absent rather than failing the build -- the Python smoke tests remain the
mandatory gate.
"""
from __future__ import annotations

import json
import os
import shutil
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

NODE = shutil.which("node")
if not NODE:
    print("node not installed -- skipping the DOM check "
          "(scripts/smoke_dashboard.py is the mandatory gate)")
    sys.exit(0)

from aibank import db as D
from aibank.api import make_handler
from aibank.bank import Bank
from aibank.flutterwave import FlutterwaveClient
from tests.fake_flw import FakeFLW

EMAIL, PASSWORD = "dom@example.com", "correct-horse-battery"

bank = Bank(D.ephemeral_path(),
            flw=FlutterwaveClient(secret_key="FLWSECK_TEST-x", opener=FakeFLW()))
httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(bank))
PORT = httpd.server_address[1]
BASE = f"http://127.0.0.1:{PORT}"
threading.Thread(target=httpd.serve_forever, daemon=True).start()


def call(method, path, body=None, token=None, admin=False, idem=None):
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
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


for _ in range(60):
    try:
        if call("GET", "/health")[0] == 200:
            break
    except Exception:
        time.sleep(0.05)

# Seed exactly the state the DOM assertions expect: funded wallet, one agent
# with real limits, one settled payment, one payment parked for approval.
_, u = call("POST", "/v1/auth/register",
            {"email": EMAIL, "password": PASSWORD, "display_name": "Dom"})
_, lg = call("POST", "/v1/auth/login", {"email": EMAIL, "password": PASSWORD})
SESS = lg["session_token"]
_, ag = call("POST", "/v1/agents",
             {"name": "dash-agent", "per_txn_max": "50000", "daily_max": "150000",
              "require_approval_above": "30000", "tz_offset_minutes": 60},
             token=SESS)
AGENT, AKEY = ag["agent_id"], ag["api_key"]
call("POST", "/v1/wallet/deposit",
     {"user_id": u["user_id"], "amount": "400000", "idempotency_key": "d1"},
     admin=True)
call("POST", "/v1/fees", {"currency": "NGN", "flat_minor": 5000, "bps": 50},
     admin=True)
call("POST", f"/v1/agents/{AGENT}/allocate",
     {"amount": "100000", "idempotency_key": "a1"}, token=SESS)
call("POST", "/v1/payouts",
     {"amount": "8000", "bank_code": "058", "account_number": "0690000031",
      "narration": "settled one"}, token=AKEY, idem="s1")
call("POST", "/v1/payouts",
     {"amount": "35000", "bank_code": "058", "account_number": "0690000031",
      "narration": "needs a human"}, token=AKEY, idem="s2")

print(f"server up on {BASE}; running the page's own JS under node\n")
proc = subprocess.run([NODE, os.path.join(ROOT, "scripts", "dom_check.mjs"),
                       BASE, EMAIL, PASSWORD],
                      cwd=ROOT, timeout=180)

print("\n-- books still balance after the browser-side flow --")
s, tb = call("GET", "/v1/admin/trial-balance", admin=True)
ok = tb.get("net_minor") == 0
print(f"  {'ok  ' if ok else 'FAIL'} trial balance {tb.get('net_minor')}")

httpd.shutdown()
bank.close()
sys.exit(proc.returncode or (0 if ok else 1))
