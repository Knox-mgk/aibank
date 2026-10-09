"""Operator CLI: migrate, serve, sweep, and bootstrap an admin user.

    python -m aibank.cli migrate            # bring a database to head
    python -m aibank.cli version            # schema version of a database
    python -m aibank.cli serve              # run the HTTP API
    python -m aibank.cli sweep-holds        # release holds with no callback
    python -m aibank.cli create-user EMAIL  # register an account holder
    python -m aibank.cli trial-balance      # prove the books net to zero

`migrate` exists because `Database(migrate_on_open=False)` refuses to open a
database whose schema does not match the code -- which is the right behaviour
for a service (never silently alter a production schema at boot) but needs an
explicit, auditable command to perform the upgrade.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import db as D
from . import ledger as L
from . import users as U


def _db_path(args) -> str:
    return args.db or os.environ.get("AIBANK_DB", "aibank.db")


def _require_head(conn, path: str) -> None:
    """Refuse to run against a database that is not at head, with a readable
    message naming the fix.

    Without this, every subcommand on a fresh or stale database raised a raw
    `sqlite3.OperationalError: no such table: postings` traceback -- which tells
    an operator nothing about the actual problem (the schema was never applied)
    and nothing about the one-word remedy. A CLI that answers "wrong schema"
    with a stack trace will be read as "the tool is broken".
    """
    have = D.current_version(conn)
    if have == D.SCHEMA_VERSION:
        return
    if have == 0:
        raise SystemExit(
            f"error: {path} has no aibank schema.\n"
            f"       run:  python -m aibank.cli migrate")
    raise SystemExit(
        f"error: {path} is at schema v{have}; this code expects "
        f"v{D.SCHEMA_VERSION}.\n"
        f"       run:  python -m aibank.cli migrate")


def cmd_migrate(args) -> int:
    path = _db_path(args)
    conn = D.connect(path)
    try:
        before = D.current_version(conn)
        applied = D.migrate(conn)
        after = D.current_version(conn)
        print(f"{path}: v{before} -> v{after}"
              + (f" (applied {applied})" if applied else " (already at head)"))
        bad = conn.execute("PRAGMA foreign_key_check").fetchall()
        if bad:
            print(f"WARNING: {len(bad)} foreign key violations", file=sys.stderr)
            return 1
        net = L.trial_balance(conn)
        print(f"trial balance: {net} ({'balanced' if net == 0 else 'CORRUPT'})")
        return 0 if net == 0 else 1
    finally:
        conn.close()


def cmd_version(args) -> int:
    conn = D.connect(_db_path(args))
    try:
        print(f"database: v{D.current_version(conn)}   code expects: v{D.SCHEMA_VERSION}")
    finally:
        conn.close()
    return 0


def cmd_trial_balance(args) -> int:
    path = _db_path(args)
    conn = D.connect(path)
    try:
        _require_head(conn, path)
        net = L.trial_balance(conn, args.currency)
        print(f"net={net} {'balanced' if net == 0 else 'CORRUPT'}")
        return 0 if net == 0 else 1
    finally:
        conn.close()


def cmd_create_user(args) -> int:
    from .bank import Bank
    bank = Bank(_db_path(args))
    try:
        pw = args.password or getpass.getpass("password: ")
        out = U.create_user(bank, args.email, pw, args.name, role=args.role)
        print(f"created {out['email']} ({out['role']}) id={out['user_id']}")
        return 0
    except U.AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        bank.close()


def cmd_sweep(args) -> int:
    from .bank import Bank
    bank = Bank(_db_path(args))
    try:
        res = bank.sweep_expired_holds()
        print(f"released {res['released']} expired hold(s)")
        for pid in res["needs_reconciliation"]:
            print(f"  needs reconciliation: {pid}")
        return 0
    finally:
        bank.close()


def cmd_serve(args) -> int:
    from .api import serve
    path = _db_path(args)
    conn = D.connect(path)
    try:
        # Checked here so an out-of-date database produces a one-line message
        # naming the fix, rather than a RuntimeError traceback out of the
        # Database constructor. `serve()` enforces the same thing on its own
        # for callers that import it directly.
        _require_head(conn, path)
    finally:
        conn.close()
    serve(path, args.host, args.port)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="aibank")
    p.add_argument("--db", help="database path (default $AIBANK_DB or aibank.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("migrate").set_defaults(fn=cmd_migrate)
    sub.add_parser("version").set_defaults(fn=cmd_version)
    sub.add_parser("sweep-holds").set_defaults(fn=cmd_sweep)

    tb = sub.add_parser("trial-balance")
    tb.add_argument("--currency")
    tb.set_defaults(fn=cmd_trial_balance)

    cu = sub.add_parser("create-user")
    cu.add_argument("email")
    cu.add_argument("--password", help="prompted for if omitted (preferred)")
    cu.add_argument("--name")
    cu.add_argument("--role", default="user", choices=["user", "admin"])
    cu.set_defaults(fn=cmd_create_user)

    sv = sub.add_parser("serve")
    sv.add_argument("--host", default=os.environ.get("AIBANK_HOST", "127.0.0.1"))
    sv.add_argument("--port", type=int, default=int(os.environ.get("AIBANK_PORT", "8000")))
    sv.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
