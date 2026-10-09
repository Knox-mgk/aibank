"""Operator CLI: migrate, serve, sweep, and bootstrap an admin user.

    python -m aibank.cli migrate            # bring a database to head
    python -m aibank.cli version            # schema version of a database
    python -m aibank.cli serve              # run the HTTP API
    python -m aibank.cli sweep-holds        # release holds with no callback
    python -m aibank.cli create-user EMAIL  # register an account holder
    python -m aibank.cli trial-balance      # prove the books net to zero
    python -m aibank.cli backup DEST        # verified online ledger copy
    python -m aibank.cli needs-reconciliation   # the sweeper's open tickets
    python -m aibank.cli reconcile PAYOUT_ID    # ask the provider the truth

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
from datetime import datetime, timezone

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


def cmd_backup(args) -> int:
    path = _db_path(args)
    conn = D.connect(path)
    try:
        _require_head(conn, path)
    finally:
        conn.close()
    dest = args.dest
    # A trailing separator, or an existing directory, means "put a timestamped
    # file in here". Testing only `isdir` was wrong: on a first run the backup
    # directory does not exist yet, so `backup /var/backups/aibank` silently
    # created a FILE with that name -- and the next run then refused because
    # "it exists". Both the compose and systemd units pass a directory that
    # will not exist the first time, which is exactly the path that broke.
    want_dir = (os.path.isdir(dest)
                or dest.endswith(("/", os.sep))
                or args.dir)
    if want_dir:
        os.makedirs(dest, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = os.path.join(dest, f"aibank-{stamp}.db")
        # The stamp is second-granularity, so a retry inside the same second
        # would collide and exit non-zero -- a false alarm from a backup timer
        # that actually succeeded. A name WE chose should never need --force;
        # that flag is for protecting a path the operator named.
        if os.path.exists(dest):
            base = dest[:-3]
            n = 2
            while os.path.exists(f"{base}-{n}.db"):
                n += 1
            dest = f"{base}-{n}.db"
    else:
        parent = os.path.dirname(os.path.abspath(dest))
        os.makedirs(parent, exist_ok=True)
    if os.path.exists(dest) and not args.force:
        print(f"error: {dest} exists; pass --force to overwrite", file=sys.stderr)
        return 1
    res = D.backup(path, dest)
    print(f"{res['path']}  {res['bytes']} bytes  schema v{res['schema_version']}")
    print(f"integrity: {res['integrity']}   trial balance: {res['trial_balance']}")
    if not res["ok"]:
        print("BACKUP NOT USABLE -- do not rely on this file", file=sys.stderr)
        return 1
    print("verified: this copy was opened and checked, not just written")
    return 0


def cmd_needs_reconciliation(args) -> int:
    from .bank import Bank
    bank = Bank(_db_path(args))
    try:
        rows = bank.needs_reconciliation()
        if not rows:
            print("nothing awaiting reconciliation")
            return 0
        print(f"{len(rows)} payout(s) awaiting reconciliation:\n")
        for p in rows:
            print(f"  {p['id']}  {p.get('currency','')} {p.get('amount','?')}"
                  f"  agent={p.get('agent_id','?')}  status={p.get('status','?')}")
            print(f"      created {p.get('created_at','?')}  ref={p.get('reference','?')}")
            print(f"      resolve: python -m aibank.cli reconcile {p['id']}")
        # Non-zero: this is a nagios-style check as much as a report, so a
        # cron wrapper can alert on it without parsing stdout.
        return 2
    finally:
        bank.close()


def cmd_reconcile(args) -> int:
    from .bank import Bank
    bank = Bank(_db_path(args))
    try:
        res = bank.reconcile(args.payout_id)
        print(f"provider says: {res.get('status')}")
        p = res.get("payout") or {}
        print(f"payout now: {p.get('status','?')}")
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

    bk = sub.add_parser("backup", help="verified online copy of the ledger")
    bk.add_argument("dest", help="destination file, or a directory to timestamp into")
    bk.add_argument("--force", action="store_true", help="overwrite an existing file")
    bk.add_argument("--dir", action="store_true",
                    help="treat DEST as a directory and create it if missing")
    bk.set_defaults(fn=cmd_backup)

    nr = sub.add_parser("needs-reconciliation",
                        help="payouts the sweeper could not resolve (exit 2 if any)")
    nr.set_defaults(fn=cmd_needs_reconciliation)

    rc = sub.add_parser("reconcile", help="ask the provider the truth about one payout")
    rc.add_argument("payout_id")
    rc.set_defaults(fn=cmd_reconcile)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
