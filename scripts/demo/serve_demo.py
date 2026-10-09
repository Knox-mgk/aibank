#!/usr/bin/env python3
"""Serve aibank with a FAKE payment provider, for a dashboard review or demo.

Why this exists: evaluating this service should not require a Flutterwave
account. An empty dashboard also tells you nothing — you need realistic data
on the page to judge it. So this starts a throwaway database, seeds it with
every state the UI must render, and wires the provider transport to the
in-process test fake.

Nothing here can move real money: there is no real credential loaded, and the
HTTP transport is replaced before the Bank is constructed.

    python3 scripts/demo/serve_demo.py                   # 127.0.0.1:8088
    python3 scripts/demo/serve_demo.py --reseed           # rebuild the data
    python3 scripts/demo/serve_demo.py --host 0.0.0.0     # review from a LAN device

Then open the printed URL and sign in with the printed credentials.
"""
from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# scripts/demo/ -> repo root. Resolved from __file__ so the demo works from a
# fresh clone with no PYTHONPATH and no install step, which is the whole point
# of handing it to someone evaluating the service.
REPO = os.environ.get("AIBANK_REPO",
                      os.path.abspath(os.path.join(HERE, "..", "..")))
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

# Dev secrets ONLY: a throwaway database behind a fake provider. Set before
# importing anything that reads them at import time — the real service reads
# these at import and fails closed, which is correct and must stay that way.
os.environ.setdefault("AIBANK_ALLOW_DEV_SECRETS", "1")
os.environ.setdefault("AIBANK_ADMIN_KEY", "demo-admin-key-not-a-secret")
os.environ.setdefault("AIBANK_KEY_PEPPER", "demo-pepper-not-a-secret")
# Production scrypt cost (2**14) is ~16MB and tens of ms per call. On a small
# host that makes signing in slow enough to look broken, and this database is
# disposable. NEVER lower this with real accounts.
os.environ.setdefault("AIBANK_SCRYPT_N", "4096")

from aibank import db as D                        # noqa: E402
from aibank.api import make_handler               # noqa: E402
from aibank.bank import Bank                      # noqa: E402
from aibank.flutterwave import FlutterwaveClient  # noqa: E402
from tests.fake_flw import FakeFLW                # noqa: E402

import seed as seedmod                            # noqa: E402


def build_bank(db_path: str) -> Bank:
    """A Bank whose provider transport is the test fake.

    The fake replaces the urlopen-level opener, not our own client methods, so
    request building, the auth header, JSON encoding and error handling are all
    still exercised by the real code.
    """
    return Bank(db_path,
                flw=FlutterwaveClient(secret_key="FLWSECK_TEST-demo",
                                      opener=FakeFLW()),
                migrate_on_open=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8088)
    # Loopback by default. The dashboard posts a password and then carries a
    # session token, so on a shared network a routable bind puts both on the
    # wire in clear. --host 0.0.0.0 exists for reviewing from another device on
    # a trusted network, and says so loudly at boot.
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--db", default=os.path.join(HERE, "demo.db"))
    ap.add_argument("--reseed", action="store_true",
                    help="delete the demo database and rebuild it")
    args = ap.parse_args()

    if args.reseed:
        for suffix in ("", "-wal", "-shm"):
            p = args.db + suffix
            if os.path.exists(p):
                os.remove(p)

    if not os.path.exists(args.db):
        conn = D.connect(args.db)
        try:
            applied = D.migrate(conn)
            print(f"schema: v0 -> v{D.current_version(conn)} (applied {applied})")
        finally:
            conn.close()
        seedmod.seed(build_bank(args.db))

    bank = build_bank(args.db)
    print("\n  DEMO MODE — fake payment provider, no real credential loaded")
    print(f"  database: {args.db}")
    print(f"  sign in:  {seedmod.DEMO_EMAIL}  /  {seedmod.DEMO_PASSWORD}")
    print(f"  dashboard: http://{args.host}:{args.port}/\n")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING: non-loopback bind over plain HTTP — the password and")
        print("  session token are readable on the wire. Trusted network only.\n")

    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(bank))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
