"""Double-entry ledger. The single source of truth for every balance.

Invariants this module refuses to break:
  1. Postings within an entry sum to exactly zero.
  2. Postings are immutable -- corrections are new reversing entries.
  3. Balance = SUM(postings). Available = balance - active holds.
  4. An idempotency key can produce at most one entry, ever.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from .money import check_currency


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:24]}"


class LedgerError(Exception):
    pass


class Unbalanced(LedgerError):
    pass


class InsufficientFunds(LedgerError):
    def __init__(self, available: int, requested: int, currency: str):
        self.available, self.requested, self.currency = available, requested, currency
        super().__init__(
            f"insufficient funds: available={available} requested={requested} {currency}"
        )


class DuplicateIdempotencyKey(LedgerError):
    def __init__(self, existing_entry_id: str):
        self.existing_entry_id = existing_entry_id
        super().__init__(f"idempotency key already used by entry {existing_entry_id}")


def get_or_create_account(conn, agent_id, kind: str, currency: str) -> str:
    currency = check_currency(currency)
    row = conn.execute(
        "SELECT id FROM accounts WHERE agent_id IS ? AND kind = ? AND currency = ?",
        (agent_id, kind, currency),
    ).fetchone()
    if row:
        return row["id"]
    acct_id = new_id("acct")
    conn.execute(
        "INSERT INTO accounts (id, agent_id, kind, currency, created_at) VALUES (?,?,?,?,?)",
        (acct_id, agent_id, kind, currency, now_iso()),
    )
    return acct_id


def balance(conn, account_id: str) -> int:
    row = conn.execute(
        "SELECT COALESCE(SUM(amount_minor), 0) AS bal FROM postings WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    return int(row["bal"])


def held(conn, account_id: str) -> int:
    row = conn.execute(
        "SELECT COALESCE(SUM(amount_minor), 0) AS h FROM holds "
        "WHERE account_id = ? AND status = 'active'",
        (account_id,),
    ).fetchone()
    return int(row["h"])


def available(conn, account_id: str) -> int:
    """What the agent may actually spend right now."""
    return balance(conn, account_id) - held(conn, account_id)


def post_entry(
    conn,
    kind: str,
    legs: list[tuple[str, int]],
    currency: str,
    agent_id: str | None = None,
    memo: str | None = None,
    reference: str | None = None,
    idempotency_key: str | None = None,
    metadata: dict | None = None,
    status: str = "posted",
) -> str:
    """Write one balanced entry atomically. legs = [(account_id, amount_minor)].

    Sign convention: positive = debit (value into that account),
    negative = credit (value out of it). The legs MUST sum to zero.
    """
    currency = check_currency(currency)
    if not legs:
        raise Unbalanced("entry has no postings")
    total = sum(a for _, a in legs)
    if total != 0:
        raise Unbalanced(f"postings sum to {total}, expected 0")
    if any(a == 0 for _, a in legs):
        raise Unbalanced("zero-amount posting is not meaningful")

    if idempotency_key:
        prior = conn.execute(
            "SELECT id FROM entries WHERE idempotency_key = ?", (idempotency_key,)
        ).fetchone()
        if prior:
            raise DuplicateIdempotencyKey(prior["id"])

    entry_id = new_id("entry")
    ts = now_iso()
    try:
        conn.execute(
            "INSERT INTO entries (id, kind, idempotency_key, reference, status, agent_id,"
            " memo, metadata, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (entry_id, kind, idempotency_key, reference, status, agent_id, memo,
             json.dumps(metadata) if metadata else None, ts),
        )
    except sqlite3.IntegrityError as exc:
        if "idempotency_key" in str(exc):
            prior = conn.execute(
                "SELECT id FROM entries WHERE idempotency_key = ?", (idempotency_key,)
            ).fetchone()
            if prior:
                raise DuplicateIdempotencyKey(prior["id"]) from exc
        raise
    conn.executemany(
        "INSERT INTO postings (entry_id, account_id, amount_minor, currency, created_at)"
        " VALUES (?,?,?,?,?)",
        [(entry_id, acct, amt, currency, ts) for acct, amt in legs],
    )
    return entry_id


def place_hold(conn, agent_id: str, account_id: str, amount_minor: int, currency: str) -> str:
    """Reserve funds so concurrent spends cannot exceed the balance."""
    currency = check_currency(currency)
    if amount_minor <= 0:
        raise LedgerError("hold amount must be positive")
    avail = available(conn, account_id)
    if avail < amount_minor:
        raise InsufficientFunds(avail, amount_minor, currency)
    hold_id = new_id("hold")
    conn.execute(
        "INSERT INTO holds (id, agent_id, account_id, amount_minor, currency, status, created_at)"
        " VALUES (?,?,?,?,?, 'active', ?)",
        (hold_id, agent_id, account_id, amount_minor, currency, now_iso()),
    )
    return hold_id


def release_hold(conn, hold_id: str) -> None:
    """Payout failed -> give the money back to available spend."""
    conn.execute(
        "UPDATE holds SET status='released', resolved_at=? WHERE id=? AND status='active'",
        (now_iso(), hold_id),
    )


def capture_hold(conn, hold_id: str, entry_id: str) -> None:
    """Payout succeeded -> the hold is realised by a real posting."""
    conn.execute(
        "UPDATE holds SET status='captured', resolved_at=?, entry_id=? WHERE id=? AND status='active'",
        (now_iso(), entry_id, hold_id),
    )


def audit(conn, agent_id, action: str, decision: str | None = None, detail=None) -> None:
    conn.execute(
        "INSERT INTO audit_log (agent_id, action, decision, detail, created_at) VALUES (?,?,?,?,?)",
        (agent_id, action, decision,
         json.dumps(detail) if isinstance(detail, (dict, list)) else detail, now_iso()),
    )


def trial_balance(conn, currency: str | None = None) -> int:
    """Every posting in the system must net to zero. Non-zero == corruption."""
    sql = "SELECT COALESCE(SUM(amount_minor), 0) AS t FROM postings"
    args: tuple = ()
    if currency:
        sql += " WHERE currency = ?"
        args = (check_currency(currency),)
    return int(conn.execute(sql, args).fetchone()["t"])
