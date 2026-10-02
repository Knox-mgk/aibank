"""SQLite setup. WAL + FULL sync + enforced foreign keys.

Design rules encoded here:
  * Balances are NEVER stored as a mutable column. They are derived from
    immutable ledger postings. A stored balance is a bug waiting to drift.
  * Every money movement is double-entry: postings for one entry MUST sum to 0.
  * Idempotency keys are UNIQUE, so a retried request can never double-spend.
"""
from __future__ import annotations

import atexit
import itertools
import os
import shutil
import sqlite3
import tempfile
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Agents: the AI principals that hold money.
CREATE TABLE IF NOT EXISTS agents (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'frozen', 'closed')),
    created_at    TEXT NOT NULL
);

-- API credentials. We store ONLY a salted hash; the plaintext is shown once.
CREATE TABLE IF NOT EXISTS api_keys (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL REFERENCES agents(id),
    key_prefix    TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE,
    revoked_at    TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_keys_agent ON api_keys(agent_id);

-- Accounts. 'asset'/'liability' etc. follow normal accounting signs.
-- kind='agent_wallet'  -> liability (we owe the agent its balance)
-- kind='flw_settlement'-> asset (money sitting at Flutterwave)
-- kind='revenue_fees'  -> revenue
-- kind='external'      -> the outside world (counterparty leg)
CREATE TABLE IF NOT EXISTS accounts (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT REFERENCES agents(id),
    kind          TEXT NOT NULL
                  CHECK (kind IN ('agent_wallet','flw_settlement','revenue_fees','external')),
    currency      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    UNIQUE (agent_id, kind, currency)
);

-- An entry is one atomic financial event (a transfer, a funding, a fee).
CREATE TABLE IF NOT EXISTS entries (
    id               TEXT PRIMARY KEY,
    kind             TEXT NOT NULL,
    idempotency_key  TEXT UNIQUE,
    reference        TEXT UNIQUE,
    status           TEXT NOT NULL DEFAULT 'posted'
                     CHECK (status IN ('pending','posted','failed','reversed')),
    agent_id         TEXT REFERENCES agents(id),
    memo             TEXT,
    metadata         TEXT,
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entries_agent ON entries(agent_id, created_at);

-- Postings are immutable. Debits positive, credits negative. Sum per entry = 0.
CREATE TABLE IF NOT EXISTS postings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id      TEXT NOT NULL REFERENCES entries(id),
    account_id    TEXT NOT NULL REFERENCES accounts(id),
    amount_minor  INTEGER NOT NULL,
    currency      TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_postings_account ON postings(account_id);
CREATE INDEX IF NOT EXISTS idx_postings_entry ON postings(entry_id);

-- Holds reserve funds for in-flight payouts so the agent cannot double-spend
-- while Flutterwave is still deciding. Released or captured on webhook.
CREATE TABLE IF NOT EXISTS holds (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL REFERENCES agents(id),
    account_id    TEXT NOT NULL REFERENCES accounts(id),
    amount_minor  INTEGER NOT NULL CHECK (amount_minor > 0),
    currency      TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','captured','released')),
    entry_id      TEXT REFERENCES entries(id),
    created_at    TEXT NOT NULL,
    resolved_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_holds_account ON holds(account_id, status);

-- Spend policy per agent: hard ceilings the agent cannot talk its way past.
CREATE TABLE IF NOT EXISTS policies (
    agent_id          TEXT PRIMARY KEY REFERENCES agents(id),
    currency          TEXT NOT NULL,
    per_txn_max_minor INTEGER,
    daily_max_minor   INTEGER,
    monthly_max_minor INTEGER,
    allowlist_only    INTEGER NOT NULL DEFAULT 0,
    require_approval_above_minor INTEGER,
    updated_at        TEXT NOT NULL
);

-- Counterparties an agent is allowed to pay.
CREATE TABLE IF NOT EXISTS payees (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL REFERENCES agents(id),
    label         TEXT NOT NULL,
    bank_code     TEXT NOT NULL,
    account_number TEXT NOT NULL,
    currency      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    UNIQUE (agent_id, bank_code, account_number, currency)
);

-- Payout lifecycle mirrored against the provider.
CREATE TABLE IF NOT EXISTS payouts (
    id             TEXT PRIMARY KEY,
    agent_id       TEXT NOT NULL REFERENCES agents(id),
    payee_id       TEXT REFERENCES payees(id),
    amount_minor   INTEGER NOT NULL,
    fee_minor      INTEGER NOT NULL DEFAULT 0,
    currency       TEXT NOT NULL,
    status         TEXT NOT NULL
                   CHECK (status IN ('pending_approval','submitted','successful','failed','cancelled')),
    reference      TEXT NOT NULL UNIQUE,
    provider_id    TEXT,
    provider_status TEXT,
    hold_id        TEXT REFERENCES holds(id),
    failure_reason TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payouts_agent ON payouts(agent_id, created_at);

-- Every provider webhook, stored raw, deduped by provider event id.
CREATE TABLE IF NOT EXISTS webhook_events (
    id            TEXT PRIMARY KEY,
    provider      TEXT NOT NULL,
    dedupe_key    TEXT NOT NULL UNIQUE,
    payload       TEXT NOT NULL,
    processed_at  TEXT,
    result        TEXT,
    created_at    TEXT NOT NULL
);

-- Append-only audit of decisions (esp. policy denials) for forensics.
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT,
    action        TEXT NOT NULL,
    decision      TEXT,
    detail        TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id, created_at);
"""


_MEM_SEQ = itertools.count()
_SCRATCH_DIRS: list[str] = []


def _cleanup_scratch() -> None:
    for d in _SCRATCH_DIRS:
        shutil.rmtree(d, ignore_errors=True)


atexit.register(_cleanup_scratch)


def ephemeral_path() -> str:
    """A private, throwaway database file standing in for ':memory:'.

    WHY NOT a real in-memory database: the only way several threads can share
    one is `cache=shared`, and shared-cache SQLite raises SQLITE_LOCKED
    ("database table is locked") on write contention. SQLITE_LOCKED is NOT
    retried by `busy_timeout` -- that only covers SQLITE_BUSY -- so concurrent
    writers fail instantly instead of queueing. A temp file gives us real WAL
    behaviour, real busy_timeout backoff, and makes tests exercise exactly the
    locking semantics production will hit.
    """
    d = tempfile.mkdtemp(prefix=f"aibank_{next(_MEM_SEQ)}_")
    _SCRATCH_DIRS.append(d)
    return os.path.join(d, "aibank.db")


def connect(path: str | Path) -> sqlite3.Connection:
    """One connection. Callers must not share these across threads -- use Database."""
    p = str(path)
    if p == ":memory:":
        p = ephemeral_path()
    conn = sqlite3.connect(p, isolation_level=None, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


class Database:
    """Thread-local connections over one SQLite file.

    SQLite connections are NOT shareable across threads, and our HTTP server is
    threaded. Each thread lazily gets its own connection to the same database.
    """

    def __init__(self, path: str | Path):
        self.path = ephemeral_path() if str(path) == ":memory:" else str(path)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._all_conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()
        boot = connect(self.path)
        boot.executescript(SCHEMA)
        boot.close()

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = connect(self.path)
            self._local.conn = c
            with self._conns_lock:
                self._all_conns.append(c)
        return c

    @contextmanager
    def write(self):
        """Serialized, atomic read-modify-write.

        BEGIN IMMEDIATE takes the write lock up front, so a policy check and the
        hold it authorises cannot interleave with another spender.
        """
        with self._write_lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except Exception:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def close(self):
        """Close EVERY thread's connection, not just the caller's.

        Worker threads exit without closing theirs; leaking them keeps WAL
        files open and, under a test runner, exhausts file descriptors.
        """
        with self._conns_lock:
            conns, self._all_conns = self._all_conns, []
        for c in conns:
            try:
                c.close()
            except sqlite3.Error:
                pass
        self._local.conn = None


def init_db(path: str | Path) -> sqlite3.Connection:
    conn = connect(path)
    conn.executescript(SCHEMA)
    return conn
