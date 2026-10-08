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
from datetime import datetime, timedelta, timezone

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


def get_or_create_account(conn, agent_id, kind: str, currency: str,
                          user_id: str | None = None) -> str:
    """Find or create the one account for (owner, kind, currency).

    An owner is an agent, a user, or neither (the platform's own settlement,
    fee and external accounts). `IS ?` rather than `= ?` is deliberate: SQLite
    `=` never matches NULL, so a platform account would be re-created on every
    lookup and the books would silently split across duplicates.
    """
    currency = check_currency(currency)
    row = conn.execute(
        "SELECT id FROM accounts WHERE agent_id IS ? AND user_id IS ?"
        " AND kind = ? AND currency = ?",
        (agent_id, user_id, kind, currency),
    ).fetchone()
    if row:
        return row["id"]
    acct_id = new_id("acct")
    try:
        conn.execute(
            "INSERT INTO accounts (id, agent_id, user_id, kind, currency, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (acct_id, agent_id, user_id, kind, currency, now_iso()),
        )
    except sqlite3.IntegrityError:
        # Lost a race against another writer creating the same account; theirs
        # is as good as ours. Re-read instead of failing the caller's payout.
        row = conn.execute(
            "SELECT id FROM accounts WHERE agent_id IS ? AND user_id IS ?"
            " AND kind = ? AND currency = ?",
            (agent_id, user_id, kind, currency),
        ).fetchone()
        if row is None:
            raise
        return row["id"]
    return acct_id


def user_wallet(conn, user_id: str, currency: str) -> str:
    """The human's own funding wallet. Agents are funded FROM here."""
    return get_or_create_account(conn, None, "user_wallet", currency, user_id=user_id)


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


def place_hold(conn, agent_id: str, account_id: str, amount_minor: int, currency: str,
               ttl_minutes: int | None = None) -> str:
    """Reserve funds so concurrent spends cannot exceed the balance.

    `expires_at` is the answer to a real failure mode: if the provider never
    sends a webhook, a hold with no expiry freezes that money forever and the
    agent's available balance silently shrinks for good. The sweeper releases
    expired holds; it does NOT decide the payout failed, it only stops the
    funds being hostage to a missing callback.
    """
    currency = check_currency(currency)
    if amount_minor <= 0:
        raise LedgerError("hold amount must be positive")
    avail = available(conn, account_id)
    if avail < amount_minor:
        raise InsufficientFunds(avail, amount_minor, currency)
    hold_id = new_id("hold")
    expires = None
    if ttl_minutes:
        expires = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat()
    conn.execute(
        "INSERT INTO holds (id, agent_id, account_id, amount_minor, currency, status,"
        " created_at, expires_at) VALUES (?,?,?,?,?, 'active', ?,?)",
        (hold_id, agent_id, account_id, amount_minor, currency, now_iso(), expires),
    )
    return hold_id


def expired_holds(conn, nowdt: datetime | None = None) -> list:
    nowdt = nowdt or datetime.now(timezone.utc)
    return conn.execute(
        "SELECT * FROM holds WHERE status='active' AND expires_at IS NOT NULL"
        " AND expires_at <= ?", (nowdt.isoformat(),)).fetchall()


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


def reverse_entry(conn, entry_id: str, memo: str | None = None,
                  idempotency_key: str | None = None) -> str:
    """Correct a posted entry by writing its mirror image.

    Postings are immutable by design, so a refund is NOT an edit or a delete --
    it is a new entry whose legs are the negation of the original's. Both stay
    on the books, which is what makes the history auditable: you can see that
    money moved and that it came back, rather than seeing a row that silently
    changed.

    Reversing twice is refused rather than tolerated: a double reversal would
    re-apply the original movement and look like a real payment.
    """
    orig = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
    if orig is None:
        raise LedgerError(f"unknown entry {entry_id}")
    if orig["status"] == "reversed":
        raise LedgerError(f"entry {entry_id} is already reversed")
    existing = conn.execute(
        "SELECT id FROM entries WHERE reverses_entry_id = ?", (entry_id,)).fetchone()
    if existing:
        raise LedgerError(f"entry {entry_id} already reversed by {existing['id']}")

    legs = conn.execute(
        "SELECT account_id, amount_minor, currency FROM postings WHERE entry_id = ?",
        (entry_id,)).fetchall()
    if not legs:
        raise LedgerError(f"entry {entry_id} has no postings to reverse")
    currency = legs[0]["currency"]

    rev_id = new_id("entry")
    ts = now_iso()
    conn.execute(
        "INSERT INTO entries (id, kind, idempotency_key, status, agent_id, memo,"
        " reverses_entry_id, created_at) VALUES (?,?,?,'posted',?,?,?,?)",
        (rev_id, f"reversal:{orig['kind']}", idempotency_key, orig["agent_id"],
         memo or f"reversal of {entry_id}", entry_id, ts),
    )
    conn.executemany(
        "INSERT INTO postings (entry_id, account_id, amount_minor, currency, created_at)"
        " VALUES (?,?,?,?,?)",
        [(rev_id, r["account_id"], -r["amount_minor"], r["currency"], ts) for r in legs],
    )
    conn.execute("UPDATE entries SET status='reversed' WHERE id=?", (entry_id,))
    audit(conn, orig["agent_id"], "entry.reverse", "ok",
          {"entry_id": entry_id, "reversal_id": rev_id, "currency": currency})
    return rev_id


def audit(conn, agent_id, action: str, decision: str | None = None, detail=None,
          user_id: str | None = None, ip: str | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_log (agent_id, action, decision, detail, user_id, ip, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (agent_id, action, decision,
         json.dumps(detail) if isinstance(detail, (dict, list)) else detail,
         user_id, ip, now_iso()),
    )


def trial_balance(conn, currency: str | None = None) -> int:
    """Every posting in the system must net to zero. Non-zero == corruption."""
    sql = "SELECT COALESCE(SUM(amount_minor), 0) AS t FROM postings"
    args: tuple = ()
    if currency:
        sql += " WHERE currency = ?"
        args = (check_currency(currency),)
    return int(conn.execute(sql, args).fetchone()["t"])
