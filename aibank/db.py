"""SQLite setup, schema, and versioned migrations.

Design rules encoded here:
  * Balances are NEVER stored as a mutable column. They are derived from
    immutable ledger postings. A stored balance is a bug waiting to drift.
  * Every money movement is double-entry: postings for one entry MUST sum to 0.
  * Idempotency keys are UNIQUE, so a retried request can never double-spend.
  * Schema changes go through MIGRATIONS, never by editing an earlier version.
    A database that already exists is stamped at the version matching its
    shape and then migrated forward, so an old file can never silently keep
    an old shape.
"""
from __future__ import annotations

import atexit
import itertools
import os
import shutil
import sqlite3
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

# ---------------------------------------------------------------------------
# v1 -- the original ledger schema.
# ---------------------------------------------------------------------------
MIGRATION_1 = """
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
-- while the provider is still deciding. Released or captured on webhook.
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

# ---------------------------------------------------------------------------
# v2 -- the human layer.
#
# A bank has account holders, not just API principals. A user signs in, owns
# agents, funds a wallet, and sets the limits from a dashboard. The agent is
# demoted to a spender operating under limits it cannot reach.
#
# Two rebuilds are unavoidable here: SQLite cannot alter a CHECK constraint,
# and both `accounts.kind` and `payouts.status` gain new legal values.
# ---------------------------------------------------------------------------
MIGRATION_2 = """
-- Human account holders.
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    password_salt   TEXT NOT NULL,
    kdf             TEXT NOT NULL DEFAULT 'scrypt',
    role            TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','suspended','closed')),
    display_name    TEXT,
    created_at      TEXT NOT NULL,
    last_login_at   TEXT
);

-- Dashboard sessions. The token is stored hashed: a stolen database must not
-- yield live sessions any more than it yields live API keys.
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id),
    token_hash    TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    last_seen_at  TEXT,
    revoked_at    TEXT,
    client_ip     TEXT,
    user_agent    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, expires_at);

-- Failed sign-ins, so brute force can be throttled durably rather than only
-- in process memory (which resets on every restart).
CREATE TABLE IF NOT EXISTS login_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT,
    client_ip   TEXT,
    ok          INTEGER NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(email, created_at);

-- Server-side pricing. The fee was previously whatever the caller said it was,
-- which let the spender choose the platform's own revenue.
CREATE TABLE IF NOT EXISTS fee_schedule (
    currency     TEXT PRIMARY KEY,
    flat_minor   INTEGER NOT NULL DEFAULT 0,
    bps          INTEGER NOT NULL DEFAULT 0,
    min_minor    INTEGER NOT NULL DEFAULT 0,
    cap_minor    INTEGER,
    updated_at   TEXT NOT NULL
);

-- Agents belong to a user.
ALTER TABLE agents ADD COLUMN user_id TEXT REFERENCES users(id);
CREATE INDEX IF NOT EXISTS idx_agents_user ON agents(user_id);

-- A label makes key rotation legible in the dashboard.
ALTER TABLE api_keys ADD COLUMN label TEXT;

-- Reversal linkage, so a correction points at what it corrects.
ALTER TABLE entries ADD COLUMN reverses_entry_id TEXT REFERENCES entries(id);

-- Holds can expire, which is what stops a never-delivered webhook from
-- freezing funds forever.
ALTER TABLE holds ADD COLUMN expires_at TEXT;
CREATE INDEX IF NOT EXISTS idx_holds_expiry ON holds(status, expires_at);

-- Policy gains a timezone (a "daily" cap that resets at UTC midnight resets at
-- 01:00 in Lagos) and a payout-count ceiling.
ALTER TABLE policies ADD COLUMN tz_name TEXT NOT NULL DEFAULT 'Africa/Lagos';
ALTER TABLE policies ADD COLUMN tz_offset_minutes INTEGER NOT NULL DEFAULT 60;
ALTER TABLE policies ADD COLUMN max_payouts_per_day INTEGER;

-- accounts: + user_id, + 'user_wallet' kind. CHECK change forces a rebuild.
CREATE TABLE accounts_v2 (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT REFERENCES agents(id),
    user_id       TEXT REFERENCES users(id),
    kind          TEXT NOT NULL
                  CHECK (kind IN ('agent_wallet','user_wallet','flw_settlement',
                                  'revenue_fees','external')),
    currency      TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    UNIQUE (agent_id, kind, currency),
    UNIQUE (user_id, kind, currency)
);
INSERT INTO accounts_v2 (id, agent_id, user_id, kind, currency, created_at)
    SELECT id, agent_id, NULL, kind, currency, created_at FROM accounts;
DROP TABLE accounts;
ALTER TABLE accounts_v2 RENAME TO accounts;

-- SQLite treats NULLs as distinct, so UNIQUE(agent_id, kind, currency) never
-- constrained the platform's own accounts (agent_id IS NULL). Two processes
-- could each create a second 'external' account and split the books in half.
-- A partial unique index is what actually enforces one per kind+currency.
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_platform_unique
    ON accounts(kind, currency) WHERE agent_id IS NULL AND user_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);

-- payouts: + approval trail, + 'rejected'/'refunded' states. CHECK -> rebuild.
CREATE TABLE payouts_v2 (
    id             TEXT PRIMARY KEY,
    agent_id       TEXT NOT NULL REFERENCES agents(id),
    payee_id       TEXT REFERENCES payees(id),
    amount_minor   INTEGER NOT NULL,
    fee_minor      INTEGER NOT NULL DEFAULT 0,
    currency       TEXT NOT NULL,
    status         TEXT NOT NULL
                   CHECK (status IN ('pending_approval','submitted','successful',
                                     'failed','cancelled','rejected','refunded')),
    reference      TEXT NOT NULL UNIQUE,
    provider_id    TEXT,
    provider_status TEXT,
    hold_id        TEXT REFERENCES holds(id),
    failure_reason TEXT,
    narration      TEXT,
    approved_by    TEXT REFERENCES users(id),
    approved_at    TEXT,
    decided_reason TEXT,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
INSERT INTO payouts_v2 (id, agent_id, payee_id, amount_minor, fee_minor, currency,
                        status, reference, provider_id, provider_status, hold_id,
                        failure_reason, created_at, updated_at)
    SELECT id, agent_id, payee_id, amount_minor, fee_minor, currency, status,
           reference, provider_id, provider_status, hold_id, failure_reason,
           created_at, updated_at FROM payouts;
DROP TABLE payouts;
ALTER TABLE payouts_v2 RENAME TO payouts;
CREATE INDEX IF NOT EXISTS idx_payouts_agent ON payouts(agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_payouts_status ON payouts(status, updated_at);

-- audit_log gains the acting user, so the dashboard can show who approved what.
ALTER TABLE audit_log ADD COLUMN user_id TEXT;
ALTER TABLE audit_log ADD COLUMN ip TEXT;
"""

MIGRATIONS: list[tuple[int, str]] = [
    (1, MIGRATION_1),
    (2, MIGRATION_2),
]

SCHEMA_VERSION = MIGRATIONS[-1][0]


# ---------------------------------------------------------------------------
# migration runner
# ---------------------------------------------------------------------------
def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def current_version(conn: sqlite3.Connection) -> int:
    """Version of an existing database, inferring it when unstamped.

    A database written before migrations existed has the v1 tables and no
    version row. Treating it as v0 would re-run v1 (harmless, IF NOT EXISTS)
    but then skip nothing -- so we stamp it as 1 and migrate it forward.
    """
    if not _table_exists(conn, "schema_version"):
        return 1 if _table_exists(conn, "agents") else 0
    row = conn.execute("SELECT COALESCE(MAX(version), 0) AS v FROM schema_version").fetchone()
    v = int(row[0] if not isinstance(row, sqlite3.Row) else row["v"])
    if v == 0 and _table_exists(conn, "agents"):
        return 1
    return v


def migrate(conn: sqlite3.Connection) -> list[int]:
    """Bring a database up to SCHEMA_VERSION. Returns versions applied.

    Each migration runs in its own transaction with foreign keys deferred --
    v2 rebuilds two tables, and an enforced FK would reject the intermediate
    state where the old table is dropped. `PRAGMA foreign_key_check` verifies
    nothing was actually orphaned once the migration commits.
    """
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version ("
                 " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    have = current_version(conn)
    applied: list[int] = []
    from datetime import datetime, timezone

    for version, sql in MIGRATIONS:
        if version <= have:
            # Stamp an inferred-but-unrecorded version so the next run is cheap.
            conn.execute("INSERT OR IGNORE INTO schema_version (version, applied_at)"
                         " VALUES (?,?)",
                         (version, datetime.now(timezone.utc).isoformat()))
            continue
        conn.execute("PRAGMA foreign_keys = OFF")
        try:
            # WHY "BEGIN;" is INSIDE the script and not an execute() above it:
            # sqlite3.executescript() issues an implicit COMMIT before it runs,
            # which silently discards any transaction opened beforehand. The
            # migration then ran statement-by-statement in autocommit mode (so a
            # mid-script failure left the schema half-applied) and the explicit
            # COMMIT below raised "cannot commit - no transaction is active".
            # Opening the transaction inside the script survives that implicit
            # commit, and executescript() does NOT append a COMMIT, so the
            # version stamp lands in the same atomic unit as the DDL.
            conn.executescript("BEGIN;\n" + sql)
            conn.execute("INSERT INTO schema_version (version, applied_at) VALUES (?,?)",
                         (version, datetime.now(timezone.utc).isoformat()))
        except Exception:
            conn.execute("ROLLBACK")
            conn.execute("PRAGMA foreign_keys = ON")
            raise
        conn.execute("COMMIT")
        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        conn.execute("PRAGMA foreign_keys = ON")
        if violations:
            raise sqlite3.IntegrityError(
                f"migration {version} left {len(violations)} FK violations: "
                f"{violations[:3]}")
        applied.append(version)
    return applied


# ---------------------------------------------------------------------------
# connections
# ---------------------------------------------------------------------------
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

    SCALING BOUNDARY: `write()` serialises on a process-global lock, so
    correctness here assumes exactly ONE process owns this file. Running two
    workers against the same SQLite file would reintroduce the policy-check /
    hold race the lock exists to prevent. Multi-worker deployment needs
    Postgres behind this class, not a second process.
    """

    def __init__(self, path: str | Path, migrate_on_open: bool = True):
        self.path = ephemeral_path() if str(path) == ":memory:" else str(path)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._all_conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()
        boot = connect(self.path)
        try:
            if migrate_on_open:
                self.migrations_applied = migrate(boot)
            else:
                have = current_version(boot)
                if have != SCHEMA_VERSION:
                    raise RuntimeError(
                        f"database at schema v{have}, code expects v{SCHEMA_VERSION}:"
                        " run `python -m aibank.cli migrate`")
                self.migrations_applied = []
        finally:
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
    migrate(conn)
    return conn
