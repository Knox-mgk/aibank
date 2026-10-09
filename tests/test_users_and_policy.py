"""Tests for the human layer: users, sessions, ownership, approvals, pricing.

These exist because of a specific pivot: the service became a real banking
product where a HUMAN sets the limits from a dashboard and the agent merely
spends under them. Every test below pins one half of that invariant --
either "the human can do X" or, more importantly, "the agent cannot".

Run: python -m unittest discover -s tests
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# scrypt at production cost is ~16MB and tens of ms per call, which makes an
# auth-heavy suite crawl on a phone. Lower it BEFORE importing users.
os.environ.setdefault("AIBANK_SCRYPT_N", "1024")
os.environ.setdefault("AIBANK_ALLOW_DEV_SECRETS", "1")

from aibank import fees as F
from aibank import ledger as L
from aibank import policy as P
from aibank import users as U
from aibank.bank import Bank, BankError, NotFound, PolicyDenied
from aibank.flutterwave import FlutterwaveClient
from aibank.ledger import InsufficientFunds
from tests.fake_flw import FakeFLW

_OPEN: list = []


def make_bank() -> tuple[Bank, FakeFLW]:
    fake = FakeFLW()
    bank = Bank(":memory:", flw=FlutterwaveClient(secret_key="FLWSECK_TEST-x", opener=fake))
    _OPEN.append(bank)
    return bank, fake


class Base(unittest.TestCase):
    def tearDown(self):
        while _OPEN:
            try:
                _OPEN.pop().close()
            except Exception:
                pass
        while self._scratch:
            shutil.rmtree(self._scratch.pop(), ignore_errors=True)

    # Tests that need a directory on disk must take it from here, not from a
    # bare `tempfile.mkdtemp`. Two backup tests did the latter and never
    # removed it, so every suite run leaked two directories holding a copy of
    # the ledger -- 38 of them, ~9MB, had accumulated in $TMPDIR on a host
    # whose filesystem sits at 99% full. A test that cannot be run a thousand
    # times is a slow leak with a passing status.
    _scratch: list = []

    def scratch(self) -> str:
        d = tempfile.mkdtemp(prefix="aibank_bk_")
        self._scratch.append(d)
        return d

    def user(self, bank, email="kay@example.com", pw="correct-horse-battery"):
        u = U.create_user(bank, email, pw, "Kay")
        s = U.login(bank, email, pw, client_ip="10.0.0.1")
        return u, s


class TestMigrations(Base):
    """These assert against db.SCHEMA_VERSION, never a literal.

    Three of these tests hard-coded `2` and all three broke the moment a v3
    migration landed -- a failing suite that says nothing about whether the
    migration is correct. Deriving the expectation from the migration list
    keeps the test about the PROPERTY (a fresh database is at head, migrations
    are stamped and idempotent) instead of about today's version number.
    """

    def test_fresh_db_is_at_head(self):
        from aibank import db as D
        bank, _ = make_bank()
        self.assertEqual(bank.schema_version(), D.SCHEMA_VERSION)

    def test_serve_refuses_to_migrate_a_production_schema_at_boot(self):
        """The README promises schema changes are never applied implicitly at
        boot. `serve()` was nonetheless constructing `Bank(db_path)` with the
        auto-migrate DEFAULT, so starting a new binary against an old database
        would have silently rewritten it -- precisely when an unreviewed,
        unbacked-up ALTER is most dangerous.

        Asserted at two levels: that the guarantee holds behaviourally, and
        that `serve` passes the flag, so restoring the default is a test
        failure rather than a silent regression of a documented promise.
        """
        import inspect

        from aibank import api as A
        from aibank import db as D

        path = D.ephemeral_path()
        conn = D.connect(path)
        try:
            # Build a v1-only database: behind head, exactly like a host that
            # has taken new code but not yet been migrated.
            conn.executescript("BEGIN;\n" + D.MIGRATION_1)
            conn.execute("CREATE TABLE IF NOT EXISTS schema_version ("
                         "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            conn.execute("INSERT INTO schema_version VALUES (1, 'x')")
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(RuntimeError) as cm:
            Bank(path, flw=FlutterwaveClient(secret_key="FLWSECK_TEST-x",
                                             opener=FakeFLW()),
                 migrate_on_open=False)
        self.assertIn("cli migrate", str(cm.exception))

        # And the schema was NOT touched by the attempt.
        conn = D.connect(path)
        try:
            self.assertEqual(D.current_version(conn), 1)
        finally:
            conn.close()
            os.unlink(path)

        self.assertIn("migrate_on_open=False", inspect.getsource(A.serve))

    def test_migration_is_atomic_and_stamped(self):
        """Regression: executescript() issues an implicit COMMIT, which used to
        discard the BEGIN opened just before it. Migrations then ran outside any
        transaction (so a mid-script failure left a half-built schema) and the
        explicit COMMIT raised "cannot commit - no transaction is active"."""
        from aibank import db as D
        conn = D.connect(":memory:")
        try:
            every = [v for v, _sql in D.MIGRATIONS]
            applied = D.migrate(conn)
            self.assertEqual(applied, every)
            rows = conn.execute("SELECT version FROM schema_version ORDER BY version").fetchall()
            self.assertEqual([r[0] for r in rows], every)
            # Re-running is a no-op, not an error.
            self.assertEqual(D.migrate(conn), [])
        finally:
            conn.close()

    def test_v1_database_is_upgraded_in_place_without_losing_money(self):
        """A pre-migrations database must survive the upgrade with balances intact."""
        from aibank import db as D
        path = D.ephemeral_path()
        conn = D.connect(path)
        conn.executescript("BEGIN;\n" + D.MIGRATION_1)
        conn.execute("COMMIT")
        conn.execute("INSERT INTO agents (id,name,status,created_at) VALUES"
                     " ('agent_old','legacy','active','2026-01-01T00:00:00+00:00')")
        # Raw v1 inserts: ledger helpers are v2-aware (they reference
        # accounts.user_id), so they cannot be used against a v1 schema.
        conn.execute("INSERT INTO accounts (id,agent_id,kind,currency,created_at)"
                     " VALUES ('acct_w','agent_old','agent_wallet','NGN','2026-01-01T00:00:00+00:00')")
        conn.execute("INSERT INTO accounts (id,agent_id,kind,currency,created_at)"
                     " VALUES ('acct_x',NULL,'external','NGN','2026-01-01T00:00:00+00:00')")
        conn.execute("INSERT INTO entries (id,kind,status,agent_id,created_at)"
                     " VALUES ('entry_old','funding','posted','agent_old','2026-01-01T00:00:00+00:00')")
        for acct, amt in (("acct_w", 77700), ("acct_x", -77700)):
            conn.execute("INSERT INTO postings (entry_id,account_id,amount_minor,currency,created_at)"
                         " VALUES ('entry_old',?,?,'NGN','2026-01-01T00:00:00+00:00')", (acct, amt))
        conn.close()

        bank = Bank(path, flw=FlutterwaveClient(secret_key="k", opener=FakeFLW()))
        _OPEN.append(bank)
        from aibank import db as D
        self.assertEqual(bank.schema_version(), D.SCHEMA_VERSION)
        # The v2 rebuild of `accounts` must have carried the row (and its
        # postings, by id) across the DROP/RENAME.
        self.assertEqual(bank.balance("agent_old")["balance_minor"], 77700)
        self.assertTrue(bank.trial_balance()["balanced"])

    def test_v3_backfills_the_destination_from_the_payee(self):
        """A v2 payout's destination must survive into the v3 column.

        Without the backfill, every payout written before v3 would be
        unapprovable after the upgrade -- the exact failure v3 exists to fix,
        reintroduced for historical rows.
        """
        from aibank import db as D
        conn = D.connect(":memory:")
        try:
            # Build v1+v2 only, then seed a payout with a payee, then migrate.
            #
            # The versions must be STAMPED after applying them by hand: the
            # runner infers v1 from the presence of `agents` but has no way to
            # see that v2 already ran, so it would re-apply v2's ALTERs and die
            # on "duplicate column name".
            conn.execute("CREATE TABLE IF NOT EXISTS schema_version ("
                         " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            for version, sql in D.MIGRATIONS:
                if version > 2:
                    break
                conn.executescript("BEGIN;\n" + sql)
                conn.execute("INSERT INTO schema_version (version, applied_at)"
                             " VALUES (?, '2026-01-01T00:00:00+00:00')", (version,))
                conn.execute("COMMIT")
            conn.execute("INSERT INTO agents (id,name,status,created_at)"
                         " VALUES ('agent_1','a','active','2026-01-01T00:00:00+00:00')")
            conn.execute("INSERT INTO payees (id,agent_id,label,bank_code,"
                         "account_number,currency,created_at) VALUES"
                         " ('payee_1','agent_1','V','058','0690000031','NGN',"
                         "'2026-01-01T00:00:00+00:00')")
            conn.execute(
                "INSERT INTO payouts (id,agent_id,payee_id,amount_minor,fee_minor,"
                "currency,status,reference,created_at,updated_at) VALUES"
                " ('payout_1','agent_1','payee_1',1000,0,'NGN','pending_approval',"
                "'ref_1','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00')")
            conn.commit()

            D.migrate(conn)
            row = conn.execute(
                "SELECT dest_bank_code, dest_account_number FROM payouts"
                " WHERE id='payout_1'").fetchone()
            self.assertEqual(row["dest_bank_code"], "058")
            self.assertEqual(row["dest_account_number"], "0690000031")
        finally:
            conn.close()


class TestPayoutDestination(Base):
    """A parked payout must remain approvable, and must not leak the account.

    The bug: `approve_payout` re-resolved the destination by joining `payees`,
    which is NULL when the agent paid a raw bank_code/account_number. Those
    payouts could never be approved -- the funds sat held with no route
    forward and no record of where they were going.
    """

    def _setup(self):
        bank, _ = make_bank()
        u = U.create_user(bank, "owner@example.com", "correct-horse-battery")
        ag = bank.create_agent("a", user_id=u["user_id"],
                               require_approval_above="100")
        bank.deposit_to_user(u["user_id"], "100000", idempotency_key="d")
        bank.allocate_to_agent(u["user_id"], ag["agent_id"], "50000",
                               idempotency_key="al")
        return bank, u, ag

    def test_raw_destination_payout_can_still_be_approved(self):
        bank, u, ag = self._setup()
        out = bank.request_payout(ag["agent_id"], "5000", bank_code="058",
                                  account_number="0690000031",
                                  idempotency_key="k1")
        self.assertEqual(out["status"], "pending_approval")
        self.assertIsNone(out["payee_id"])
        done = bank.approve_payout(out["id"], user_id=u["user_id"])
        self.assertIn(done["status"], ("submitted", "successful"))
        self.assertTrue(bank.trial_balance()["balanced"])

    def test_destination_is_pinned_at_request_time(self):
        """Editing the payee while a payout waits must not redirect the money."""
        bank, u, ag = self._setup()
        pid = bank.add_payee(ag["agent_id"], "V", "058", "0690000031")
        out = bank.request_payout(ag["agent_id"], "5000", payee_id=pid,
                                  idempotency_key="k2")
        self.assertEqual(out["status"], "pending_approval")
        with bank.db.write() as conn:
            conn.execute("UPDATE payees SET account_number='9999999999'"
                         " WHERE id=?", (pid,))
        row = bank.conn.execute(
            "SELECT dest_account_number FROM payouts WHERE id=?",
            (out["id"],)).fetchone()
        self.assertEqual(row["dest_account_number"], "0690000031")

    def test_account_number_is_masked_in_the_api_view(self):
        bank, u, ag = self._setup()
        out = bank.request_payout(ag["agent_id"], "50", bank_code="058",
                                  account_number="0690000031",
                                  idempotency_key="k3")
        self.assertEqual(out["destination"], "******0031")
        self.assertNotIn("dest_account_number", out)
        # And nowhere in the serialised payload either.
        import json
        self.assertNotIn("0690000031", json.dumps(out, default=str))
        listed = bank.list_payouts(agent_id=ag["agent_id"])
        self.assertNotIn("0690000031", json.dumps(listed, default=str))


class TestPolicyRepresentation(Base):
    """`get_policy` must return display values, not only `*_minor` columns.

    The dashboard reads `per_txn_max`; when only `per_txn_max_minor` existed,
    a configured ceiling rendered as an empty form field -- i.e. as "no limit" --
    and saving that form back would have ERASED the limit. A silent widening of
    the agent's authority through the UI that was meant to constrain it.
    """

    def test_policy_exposes_major_units_for_every_limit(self):
        bank, _ = make_bank()
        ag = bank.create_agent("a", per_txn_max="500", daily_max="1000",
                               require_approval_above="250")
        pol = bank.get_policy(ag["agent_id"])
        self.assertEqual(pol["per_txn_max"], "500.00")
        self.assertEqual(pol["daily_max"], "1000.00")
        self.assertEqual(pol["require_approval_above"], "250.00")
        # Minor units stay available for exactness.
        self.assertEqual(pol["per_txn_max_minor"], 50000)

    def test_unset_limit_is_none_not_zero(self):
        """Zero would read as "may not spend at all"; None means unlimited."""
        bank, _ = make_bank()
        ag = bank.create_agent("a", per_txn_max="500")
        pol = bank.get_policy(ag["agent_id"])
        self.assertIsNone(pol["monthly_max"])
        self.assertIsNone(pol["monthly_max_minor"])

    def test_round_tripping_the_form_preserves_the_limits(self):
        """Read the policy, write it straight back, assert nothing widened."""
        bank, _ = make_bank()
        u = U.create_user(bank, "rt@example.com", "correct-horse-battery")
        ag = bank.create_agent("a", user_id=u["user_id"], per_txn_max="500",
                               daily_max="1000", max_payouts_per_day=3)
        before = bank.get_policy(ag["agent_id"])
        bank.set_policy(ag["agent_id"], currency=before["currency"],
                        per_txn_max=before["per_txn_max"],
                        daily_max=before["daily_max"],
                        monthly_max=before["monthly_max"],
                        require_approval_above=before["require_approval_above"],
                        max_payouts_per_day=before["max_payouts_per_day"],
                        allowlist_only=bool(before["allowlist_only"]),
                        tz_offset_minutes=before["tz_offset_minutes"],
                        user_id=u["user_id"])
        after = bank.get_policy(ag["agent_id"])
        for field in ("per_txn_max_minor", "daily_max_minor",
                      "monthly_max_minor", "require_approval_above_minor",
                      "max_payouts_per_day", "tz_offset_minutes"):
            self.assertEqual(before[field], after[field], field)


class TestAuth(Base):
    def test_register_normalises_email_and_hides_password(self):
        bank, _ = make_bank()
        u = U.create_user(bank, "  Kay@Example.COM ", "correct-horse-battery")
        self.assertEqual(u["email"], "kay@example.com")
        row = bank.conn.execute("SELECT * FROM users WHERE id=?", (u["user_id"],)).fetchone()
        self.assertNotIn("correct-horse-battery", str(dict(row)))

    def test_duplicate_email_rejected(self):
        bank, _ = make_bank()
        U.create_user(bank, "a@b.com", "correct-horse-battery")
        with self.assertRaises(U.AuthError):
            U.create_user(bank, "A@B.com", "another-long-password")

    def test_weak_password_rejected(self):
        bank, _ = make_bank()
        with self.assertRaises(U.AuthError):
            U.create_user(bank, "a@b.com", "short")

    def test_session_token_is_not_stored_in_plaintext(self):
        """A stolen database must not yield live sessions."""
        bank, _ = make_bank()
        _, s = self.user(bank)
        token = s["session_token"]
        rows = bank.conn.execute("SELECT token_hash FROM sessions").fetchall()
        self.assertTrue(rows)
        for r in rows:
            self.assertNotEqual(r["token_hash"], token)
            self.assertNotIn(token, r["token_hash"])

    def test_wrong_password_and_unknown_email_are_indistinguishable(self):
        bank, _ = make_bank()
        self.user(bank)
        with self.assertRaises(U.AuthError) as a:
            U.login(bank, "kay@example.com", "wrong-password-here")
        with self.assertRaises(U.AuthError) as b:
            U.login(bank, "nobody@example.com", "wrong-password-here")
        self.assertEqual(str(a.exception), str(b.exception))

    def test_lockout_after_repeated_failures(self):
        bank, _ = make_bank()
        self.user(bank)
        for _ in range(U.LOCKOUT_THRESHOLD):
            with self.assertRaises(U.AuthError):
                U.login(bank, "kay@example.com", "wrong-password-here")
        # Even the CORRECT password is refused once locked out.
        with self.assertRaises(U.LockedOut):
            U.login(bank, "kay@example.com", "correct-horse-battery")

    def test_logout_revokes_the_session(self):
        bank, _ = make_bank()
        _, s = self.user(bank)
        self.assertIsNotNone(U.authenticate_session(bank, s["session_token"]))
        U.logout(bank, s["session_token"])
        self.assertIsNone(U.authenticate_session(bank, s["session_token"]))

    def test_expired_session_is_rejected(self):
        bank, _ = make_bank()
        _, s = self.user(bank)
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        bank.conn.execute("UPDATE sessions SET expires_at=?", (past,))
        self.assertIsNone(U.authenticate_session(bank, s["session_token"]))

    def test_password_change_requires_current_password_and_kills_sessions(self):
        bank, _ = make_bank()
        _, s = self.user(bank)
        with self.assertRaises(U.AuthError):
            U.change_password(bank, s["user_id"], "not-the-password", "new-long-password")
        U.change_password(bank, s["user_id"], "correct-horse-battery", "new-long-password")
        self.assertIsNone(U.authenticate_session(bank, s["session_token"]))
        U.login(bank, "kay@example.com", "new-long-password")

    def test_suspended_user_cannot_authenticate(self):
        bank, _ = make_bank()
        u, s = self.user(bank)
        bank.conn.execute("UPDATE users SET status='suspended' WHERE id=?", (u["user_id"],))
        self.assertIsNone(U.authenticate_session(bank, s["session_token"]))


class TestOwnership(Base):
    def setUp(self):
        self.bank, self.fake = make_bank()
        self.u1, self.s1 = self.user(self.bank, "one@example.com")
        self.u2, self.s2 = self.user(self.bank, "two@example.com")
        self.a1 = self.bank.create_agent("a1", user_id=self.u1["user_id"],
                                         daily_max="1000000")
        self.a2 = self.bank.create_agent("a2", user_id=self.u2["user_id"],
                                         daily_max="1000000")

    def test_list_agents_is_scoped_to_owner(self):
        ids = [a["id"] for a in self.bank.list_agents(self.u1["user_id"])]
        self.assertEqual(ids, [self.a1["agent_id"]])

    def test_user_cannot_touch_another_users_agent(self):
        with self.assertRaises(NotFound):
            self.bank.require_agent_owner(self.u1["user_id"], self.a2["agent_id"])
        with self.assertRaises(NotFound):
            self.bank.allocate_to_agent(self.u1["user_id"], self.a2["agent_id"], "100")

    def test_admin_role_bypasses_ownership(self):
        self.bank.require_agent_owner(self.u1["user_id"], self.a2["agent_id"], role="admin")

    def test_payout_read_is_scoped_to_the_owning_agent(self):
        """TIER 1: GET /v1/payouts/<id> had no ownership filter, so any agent
        key could read any other agent's payout -- amount, reference, and
        destination account."""
        self.bank.fund_agent(self.a1["agent_id"], "5000")
        payee = self.bank.add_payee(self.a1["agent_id"], "p", "058", "0690000031")
        out = self.bank.request_payout(self.a1["agent_id"], "1000", payee_id=payee)

        # Owner reads it fine, by agent and by user.
        self.assertEqual(
            self.bank.get_payout(out["id"], agent_id=self.a1["agent_id"])["id"], out["id"])
        self.assertEqual(
            self.bank.get_payout(out["id"], user_id=self.u1["user_id"])["id"], out["id"])

        # The other tenant gets "not found", not the record.
        with self.assertRaises(NotFound):
            self.bank.get_payout(out["id"], agent_id=self.a2["agent_id"])
        with self.assertRaises(NotFound):
            self.bank.get_payout(out["id"], user_id=self.u2["user_id"])

    def test_payout_list_is_scoped(self):
        self.bank.fund_agent(self.a1["agent_id"], "5000")
        payee = self.bank.add_payee(self.a1["agent_id"], "p", "058", "0690000031")
        self.bank.request_payout(self.a1["agent_id"], "1000", payee_id=payee)
        self.assertEqual(len(self.bank.list_payouts(user_id=self.u1["user_id"])), 1)
        self.assertEqual(len(self.bank.list_payouts(user_id=self.u2["user_id"])), 0)

    def test_api_key_can_be_revoked(self):
        """Rotation was impossible before: revoked_at was never written."""
        extra = self.bank.issue_api_key(self.a1["agent_id"], label="ci")
        self.assertEqual(self.bank.authenticate(extra["api_key"]), self.a1["agent_id"])
        self.assertTrue(self.bank.revoke_api_key(self.a1["agent_id"], extra["key_prefix"]))
        self.assertIsNone(self.bank.authenticate(extra["api_key"]))
        # The original key still works -- revocation is per key, not per agent.
        self.assertEqual(self.bank.authenticate(self.a1["api_key"]), self.a1["agent_id"])

    def test_revoking_another_agents_key_does_nothing(self):
        extra = self.bank.issue_api_key(self.a1["agent_id"], label="ci")
        self.assertFalse(self.bank.revoke_api_key(self.a2["agent_id"], extra["key_prefix"]))
        self.assertEqual(self.bank.authenticate(extra["api_key"]), self.a1["agent_id"])


class TestUserMoneyFlow(Base):
    def setUp(self):
        self.bank, self.fake = make_bank()
        self.u, self.s = self.user(self.bank)
        self.ag = self.bank.create_agent("spender", user_id=self.u["user_id"],
                                         daily_max="1000000")

    def test_deposit_allocate_withdraw_conserves_value(self):
        self.bank.deposit_to_user(self.u["user_id"], "100000")
        self.assertEqual(self.bank.user_balance(self.u["user_id"])["balance_minor"],
                         10_000_000)

        self.bank.allocate_to_agent(self.u["user_id"], self.ag["agent_id"], "60000")
        self.assertEqual(self.bank.user_balance(self.u["user_id"])["balance_minor"],
                         4_000_000)
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["balance_minor"],
                         6_000_000)

        self.bank.withdraw_from_agent(self.u["user_id"], self.ag["agent_id"], "10000")
        self.assertEqual(self.bank.user_balance(self.u["user_id"])["balance_minor"],
                         5_000_000)
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["balance_minor"],
                         5_000_000)
        self.assertTrue(self.bank.trial_balance()["balanced"])

    def test_cannot_allocate_more_than_the_user_holds(self):
        self.bank.deposit_to_user(self.u["user_id"], "100")
        with self.assertRaises(InsufficientFunds):
            self.bank.allocate_to_agent(self.u["user_id"], self.ag["agent_id"], "500")

    def test_cannot_withdraw_money_the_agent_has_already_committed(self):
        self.bank.deposit_to_user(self.u["user_id"], "10000")
        self.bank.allocate_to_agent(self.u["user_id"], self.ag["agent_id"], "10000")
        payee = self.bank.add_payee(self.ag["agent_id"], "p", "058", "0690000031")
        self.bank.request_payout(self.ag["agent_id"], "9000", payee_id=payee)
        # 9,000 is held in flight; only 1,000 is withdrawable.
        with self.assertRaises(InsufficientFunds):
            self.bank.withdraw_from_agent(self.u["user_id"], self.ag["agent_id"], "5000")

    def test_statement_shows_a_running_balance(self):
        self.bank.deposit_to_user(self.u["user_id"], "10000")
        self.bank.allocate_to_agent(self.u["user_id"], self.ag["agent_id"], "10000")
        st = self.bank.statement(self.ag["agent_id"])
        self.assertEqual(st["lines"][-1]["running_minor"], 1_000_000)


class TestPolicyIsHumanOnly(Base):
    def setUp(self):
        self.bank, self.fake = make_bank()
        self.u, self.s = self.user(self.bank)
        self.ag = self.bank.create_agent("spender", user_id=self.u["user_id"],
                                         daily_max="5000", require_approval_above="2000")
        self.bank.fund_agent(self.ag["agent_id"], "100000")
        self.payee = self.bank.add_payee(self.ag["agent_id"], "p", "058", "0690000031")

    def test_agent_api_surface_has_no_policy_write(self):
        """Structural proof of the central invariant: nothing an agent key can
        reach mutates `policies`. If this fails, every limit is decoration."""
        import inspect
        from aibank import api
        src = inspect.getsource(api.make_handler)
        marker = "if tail == \"policy\" and method == \"POST\""
        self.assertIn(marker, src)
        # The whole /v1/agents/<id>/... block sits behind `self._user()` plus an
        # ownership check, and the policy write is inside it.
        prefix = src.split(marker)[0]
        agent_block = prefix.split("if path.startswith(\"/v1/agents/\")")[1]
        self.assertIn("s = self._user()", agent_block)
        self.assertIn("bank.require_agent_owner(", agent_block)
        # The policy write itself must attribute the change to the human and
        # must not re-authenticate as an agent.
        policy_block = src.split(marker)[1][:1200]
        self.assertIn("user_id=s[", policy_block)
        self.assertNotIn("self._agent()", policy_block)

    def test_user_can_tighten_limits_and_the_agent_obeys_immediately(self):
        self.bank.set_policy(self.ag["agent_id"], currency="NGN", daily_max="1000",
                             user_id=self.u["user_id"])
        with self.assertRaises(PolicyDenied):
            self.bank.request_payout(self.ag["agent_id"], "1500", payee_id=self.payee)

    def test_policy_change_is_attributed_to_the_human_in_the_audit_log(self):
        self.bank.set_policy(self.ag["agent_id"], currency="NGN", daily_max="1234",
                             user_id=self.u["user_id"])
        row = self.bank.conn.execute(
            "SELECT user_id FROM audit_log WHERE action='policy.set'"
            " ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["user_id"], self.u["user_id"])

    def test_suspending_the_human_stops_their_agents_spending(self):
        self.bank.conn.execute("UPDATE users SET status='suspended' WHERE id=?",
                               (self.u["user_id"],))
        with self.assertRaises(PolicyDenied) as e:
            self.bank.request_payout(self.ag["agent_id"], "100", payee_id=self.payee)
        self.assertIn("suspended", str(e.exception))

    def test_payout_count_ceiling_catches_a_retry_loop(self):
        self.bank.set_policy(self.ag["agent_id"], currency="NGN", daily_max="100000",
                             max_payouts_per_day=3, user_id=self.u["user_id"])
        for _ in range(3):
            self.bank.request_payout(self.ag["agent_id"], "10", payee_id=self.payee)
        with self.assertRaises(PolicyDenied) as e:
            self.bank.request_payout(self.ag["agent_id"], "10", payee_id=self.payee)
        self.assertIn("count", str(e.exception))

    def test_daily_window_uses_the_policy_timezone_not_utc(self):
        """A "daily" cap that resets at UTC midnight resets at 01:00 in Lagos,
        handing the agent a second allowance in that hour."""
        pol = P.get_policy(self.bank.conn, self.ag["agent_id"])
        self.assertEqual(pol["tz_offset_minutes"], 60)
        # 00:30 WAT on the 2nd == 23:30 UTC on the 1st.
        wat = timezone(timedelta(minutes=60))
        local_midnight_ish = datetime(2026, 3, 2, 0, 30, tzinfo=wat)
        self.assertEqual(P.day_start(local_midnight_ish, wat),
                         datetime(2026, 3, 1, 23, 0, tzinfo=timezone.utc).isoformat())
        # UTC would have put the boundary 1h later, inside the same local day.
        self.assertNotEqual(P.day_start(local_midnight_ish, wat),
                            P.day_start(local_midnight_ish, timezone.utc))

    def test_payee_currency_must_match_the_payout_currency(self):
        """TIER 1: a USD payout to an NGN account is a ~1,500x error, not a
        conversion."""
        usd_payee = self.bank.add_payee(self.ag["agent_id"], "usd", "058",
                                        "0690000099", currency="USD")
        with self.assertRaises(PolicyDenied) as e:
            self.bank.request_payout(self.ag["agent_id"], "10", currency="NGN",
                                     payee_id=usd_payee)
        self.assertIn("USD", str(e.exception))


class TestApprovalWorkflow(Base):
    def setUp(self):
        self.bank, self.fake = make_bank()
        self.u, self.s = self.user(self.bank)
        self.ag = self.bank.create_agent("spender", user_id=self.u["user_id"],
                                         daily_max="1000000",
                                         require_approval_above="1000")
        self.bank.fund_agent(self.ag["agent_id"], "100000")
        self.payee = self.bank.add_payee(self.ag["agent_id"], "p", "058", "0690000031")

    def test_large_payout_waits_for_a_human(self):
        out = self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        self.assertEqual(out["status"], "pending_approval")
        pending = self.bank.pending_approvals(self.u["user_id"])
        self.assertEqual([p["id"] for p in pending], [out["id"]])
        # Funds are held, not spent.
        bal = self.bank.balance(self.ag["agent_id"])
        self.assertEqual(bal["held_minor"], 500_000)
        self.assertEqual(bal["balance_minor"], 10_000_000)

    def test_approval_submits_and_records_who_decided(self):
        """TIER 2: approve_payout existed but no route reached it -- there was
        literally no way to approve a payout over HTTP."""
        out = self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        res = self.bank.approve_payout(out["id"], user_id=self.u["user_id"],
                                       reason="ok by me")
        self.assertEqual(res["status"], "submitted")
        self.assertEqual(res["approved_by"], self.u["user_id"])
        self.assertIsNotNone(res["approved_at"])

    def test_rejection_releases_the_hold(self):
        out = self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        res = self.bank.reject_payout(out["id"], user_id=self.u["user_id"])
        self.assertEqual(res["status"], "rejected")
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["held_minor"], 0)
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["available_minor"],
                         10_000_000)

    def test_cannot_approve_twice(self):
        out = self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        self.bank.approve_payout(out["id"], user_id=self.u["user_id"])
        with self.assertRaises(BankError):
            self.bank.approve_payout(out["id"], user_id=self.u["user_id"])

    def test_cannot_reject_an_already_approved_payout(self):
        out = self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        self.bank.approve_payout(out["id"], user_id=self.u["user_id"])
        with self.assertRaises(BankError):
            self.bank.reject_payout(out["id"], user_id=self.u["user_id"])

    def test_pending_approvals_are_scoped_to_the_owner(self):
        u2, _ = self.user(self.bank, "other@example.com")
        self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        self.assertEqual(self.bank.pending_approvals(u2["user_id"]), [])


class TestRefundsAndSweeper(Base):
    def setUp(self):
        self.bank, self.fake = make_bank()
        self.u, self.s = self.user(self.bank)
        self.ag = self.bank.create_agent("spender", user_id=self.u["user_id"],
                                         daily_max="1000000")
        self.bank.fund_agent(self.ag["agent_id"], "100000")
        self.payee = self.bank.add_payee(self.ag["agent_id"], "p", "058", "0690000031")

    def _settled(self, amount="5000"):
        out = self.bank.request_payout(self.ag["agent_id"], amount, payee_id=self.payee)
        self.bank.handle_webhook({"event": "transfer.completed",
            "data": {"id": 1, "reference": out["reference"], "status": "SUCCESSFUL"}})
        return out

    def test_refund_reverses_the_entry_and_restores_the_balance(self):
        """TIER 2: the README promised refunds; no code wrote one."""
        before = self.bank.balance(self.ag["agent_id"])["balance_minor"]
        out = self._settled("5000")
        after_payout = self.bank.balance(self.ag["agent_id"])["balance_minor"]
        self.assertEqual(after_payout, before - 500_000)

        res = self.bank.refund_payout(out["id"], user_id=self.u["user_id"])
        self.assertEqual(res["status"], "refunded")
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["balance_minor"], before)
        self.assertTrue(self.bank.trial_balance()["balanced"])

    def test_refund_keeps_both_entries_on_the_books(self):
        out = self._settled("5000")
        self.bank.refund_payout(out["id"], user_id=self.u["user_id"])
        orig = self.bank.conn.execute(
            "SELECT id, status FROM entries WHERE reference=? AND kind='payout'",
            (out["reference"],)).fetchone()
        self.assertEqual(orig["status"], "reversed")
        rev = self.bank.conn.execute(
            "SELECT id FROM entries WHERE reverses_entry_id=?", (orig["id"],)).fetchone()
        self.assertIsNotNone(rev)

    def test_double_refund_is_refused(self):
        out = self._settled("5000")
        self.bank.refund_payout(out["id"], user_id=self.u["user_id"])
        with self.assertRaises(BankError):
            self.bank.refund_payout(out["id"], user_id=self.u["user_id"])

    def test_unsettled_payout_cannot_be_refunded(self):
        out = self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        with self.assertRaises(BankError):
            self.bank.refund_payout(out["id"], user_id=self.u["user_id"])

    def test_sweeper_releases_a_hold_whose_webhook_never_came(self):
        """TIER 2: with no webhook and no sweeper, funds were held forever."""
        out = self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["held_minor"], 500_000)

        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.bank.conn.execute("UPDATE holds SET expires_at=? WHERE status='active'", (past,))

        res = self.bank.sweep_expired_holds()
        self.assertEqual(res["released"], 1)
        self.assertIn(out["id"], res["needs_reconciliation"])
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["held_minor"], 0)

    def test_sweeper_leaves_settled_payouts_alone(self):
        out = self._settled("5000")
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.bank.conn.execute("UPDATE holds SET expires_at=?", (past,))
        res = self.bank.sweep_expired_holds()
        self.assertEqual(res["released"], 0)
        self.assertEqual(
            self.bank.get_payout(out["id"], agent_id=self.ag["agent_id"])["status"],
            "successful")

    def test_holds_get_an_expiry_by_default(self):
        self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        row = self.bank.conn.execute(
            "SELECT expires_at FROM holds ORDER BY created_at DESC LIMIT 1").fetchone()
        self.assertIsNotNone(row["expires_at"])

    def _expire_and_sweep(self, out):
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        self.bank.conn.execute(
            "UPDATE holds SET expires_at=? WHERE status='active'", (past,))
        return self.bank.sweep_expired_holds()

    def test_swept_payout_appears_on_the_reconciliation_report(self):
        """The sweeper's refusal to guess creates an operator task; it has to
        be LISTABLE or the task is lost in a column nobody reads."""
        out = self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        self.assertEqual(self.bank.needs_reconciliation(), [])

        self._expire_and_sweep(out)
        rows = self.bank.needs_reconciliation()
        self.assertEqual([r["id"] for r in rows], [out["id"]])

    def test_reconciliation_report_drops_items_once_resolved(self):
        """A late webhook settles the payout. It must leave the report, or an
        operator chases a closed item -- and the historical failure_reason
        string stays on the record, so status has to be in the predicate."""
        out = self.bank.request_payout(self.ag["agent_id"], "5000", payee_id=self.payee)
        self._expire_and_sweep(out)
        self.assertEqual(len(self.bank.needs_reconciliation()), 1)

        self.bank.handle_webhook({"event": "transfer.completed",
            "data": {"id": 99, "reference": out["reference"], "status": "SUCCESSFUL"}})

        self.assertEqual(self.bank.needs_reconciliation(), [])
        row = self.bank.conn.execute(
            "SELECT failure_reason FROM payouts WHERE id=?", (out["id"],)).fetchone()
        self.assertIn("needs reconciliation", row["failure_reason"] or "")


class TestLedgerBackup(Base):
    """A self-hosting operator has no backup unless we ship one."""

    def setUp(self):
        self.bank, self.fake = make_bank()
        self.u, self.s = self.user(self.bank)
        self.ag = self.bank.create_agent("spender", user_id=self.u["user_id"],
                                         daily_max="1000000")
        self.bank.fund_agent(self.ag["agent_id"], "100000")

    def test_backup_is_verified_consistent_and_restorable(self):
        from aibank import db as D
        dest = os.path.join(self.scratch(), "copy.db")

        res = D.backup(self.bank.db.path, dest)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["integrity"], "ok")
        self.assertEqual(res["trial_balance"], 0)
        self.assertEqual(res["schema_version"], D.SCHEMA_VERSION)
        self.assertGreater(res["bytes"], 0)

        # Restorable means a Bank opens it at head and the money is there --
        # not merely that a file of nonzero size exists.
        restored = Bank(dest, flw=FlutterwaveClient(secret_key="FLWSECK_TEST-x",
                                                    opener=self.fake))
        _OPEN.append(restored)
        self.assertEqual(restored.balance(self.ag["agent_id"])["balance_minor"],
                         self.bank.balance(self.ag["agent_id"])["balance_minor"])

    def test_backup_is_a_snapshot_not_a_live_view(self):
        """Writes after the copy must not appear in it, or 'backup' means
        nothing -- this is what distinguishes a snapshot from a symlink."""
        from aibank import db as D
        dest = os.path.join(self.scratch(), "copy.db")
        D.backup(self.bank.db.path, dest)

        before = self.bank.balance(self.ag["agent_id"])["balance_minor"]
        self.bank.fund_agent(self.ag["agent_id"], "50000")
        self.assertGreater(self.bank.balance(self.ag["agent_id"])["balance_minor"], before)

        restored = Bank(dest, flw=FlutterwaveClient(secret_key="FLWSECK_TEST-x",
                                                    opener=self.fake))
        _OPEN.append(restored)
        self.assertEqual(restored.balance(self.ag["agent_id"])["balance_minor"], before)


class TestLoginRateLimiting(Base):
    """Per-account lockout does nothing against spraying one password across
    many accounts -- each account sees a single failure and we pay for every
    scrypt call."""

    def setUp(self):
        self.bank, self.fake = make_bank()

    def test_spraying_many_accounts_from_one_address_is_throttled(self):
        for i in range(5):
            U.create_user(self.bank, f"u{i}@example.com", "correct-horse-battery")

        locked_at = None
        for n in range(U.IP_LOCKOUT_THRESHOLD + 5):
            email = f"u{n % 5}@example.com"
            try:
                U.login(self.bank, email, "wrong-password-entirely",
                        client_ip="203.0.113.9")
            except U.LockedOut:
                locked_at = n
                break
            except U.AuthError:
                continue
        self.assertIsNotNone(
            locked_at, "spraying was never throttled by source address")
        assert locked_at is not None
        self.assertLessEqual(locked_at, U.IP_LOCKOUT_THRESHOLD + 1)

        # No individual account hit its own threshold -- which is the point.
        for i in range(5):
            n = self.bank.conn.execute(
                "SELECT COUNT(*) AS n FROM login_attempts"
                " WHERE email=? AND ok=0", (f"u{i}@example.com",)).fetchone()["n"]
            self.assertLess(n, U.LOCKOUT_THRESHOLD)

    def test_a_lockout_on_one_address_cannot_lock_out_another(self):
        """The bucket must be keyed on source, not global. If it were global,
        one attacker would deny service to every legitimate user -- turning our
        own defence into the outage. Proven by a SUCCESSFUL login from a clean
        address while the attacker's address is locked."""
        U.create_user(self.bank, "victim@example.com", "correct-horse-battery")
        U.create_user(self.bank, "elsewhere@example.com", "correct-horse-battery")

        # Burn the attacker's address past its threshold on a nonexistent
        # account, so no real account's own counter is involved at all.
        for _ in range(U.IP_LOCKOUT_THRESHOLD + 2):
            try:
                U.login(self.bank, "nobody@example.com", "wrong",
                        client_ip="203.0.113.9")
            except U.AuthError:
                pass
        with self.assertRaises(U.LockedOut):
            U.login(self.bank, "victim@example.com", "correct-horse-battery",
                    client_ip="203.0.113.9")

        # Clean address, correct password: must still work.
        s = U.login(self.bank, "elsewhere@example.com", "correct-horse-battery",
                    client_ip="198.51.100.4")
        self.assertTrue(s.get("session_token"))

    def test_the_ip_check_runs_before_any_key_derivation(self):
        """Ordering IS the defence: if scrypt ran first, a flood would still
        burn our CPU on every rejected attempt."""
        import inspect
        src = inspect.getsource(U.login)
        ip_check = src.index("_recent_failures_by_ip")
        first_scrypt = src.index("_scrypt(password")
        self.assertLess(
            ip_check, src.index("_recent_failures(db.conn"),
            "per-IP throttle must be checked before the per-email one")
        # The dummy scrypt for unknown emails sits further down the function;
        # the throttle must precede it.
        self.assertLess(ip_check, src.rindex("_scrypt(password"))
        self.assertGreater(first_scrypt, 0)


class TestForwardedForIsNotTrustedByDefault(Base):
    """The per-address throttle is only as sound as the address it keys on.

    Two opposite failures are possible and both are bad: behind a proxy,
    keying on the socket address puts every user in ONE bucket (one sprayer
    locks out the world), while trusting a client-supplied X-Forwarded-For
    gives an attacker unlimited fresh buckets and lets them frame any address
    in the audit log. The resolution is an explicit operator assertion.
    """

    def _resolve(self, headers: dict, trust: bool) -> str:
        """Drive api._client_ip without standing up a socket."""
        from aibank import api as A

        class FakeHeaders(dict):
            def get(self, k, d=None):
                for key, v in self.items():
                    if key.lower() == k.lower():
                        return v
                return d

        bank, _ = make_bank()
        handler_cls = A.make_handler(bank)
        h = handler_cls.__new__(handler_cls)        # no __init__: it would serve
        h.client_address = ("10.9.9.9", 51234)
        h.headers = FakeHeaders(headers)   # type: ignore[assignment]
        saved = A._TRUST_PROXY
        A._TRUST_PROXY = trust
        try:
            return handler_cls._client_ip(h)
        finally:
            A._TRUST_PROXY = saved

    def test_header_is_ignored_unless_the_operator_opts_in(self):
        got = self._resolve({"X-Forwarded-For": "1.2.3.4"}, trust=False)
        self.assertEqual(got, "10.9.9.9",
                         "a client-set header must not choose its own throttle bucket")

    def test_header_is_used_when_the_deployment_asserts_a_proxy(self):
        got = self._resolve({"X-Forwarded-For": "1.2.3.4"}, trust=True)
        self.assertEqual(got, "1.2.3.4")

    def test_leftmost_entry_wins_so_appended_values_cannot_hide_the_client(self):
        got = self._resolve({"X-Forwarded-For": "1.2.3.4, 10.0.0.7"}, trust=True)
        self.assertEqual(got, "1.2.3.4")

    def test_falls_back_to_the_socket_when_the_header_is_absent_or_empty(self):
        self.assertEqual(self._resolve({}, trust=True), "10.9.9.9")
        self.assertEqual(self._resolve({"X-Forwarded-For": "  "}, trust=True),
                         "10.9.9.9")


class TestFees(Base):
    def setUp(self):
        self.bank, self.fake = make_bank()
        self.u, self.s = self.user(self.bank)
        self.ag = self.bank.create_agent("spender", user_id=self.u["user_id"],
                                         daily_max="10000000")
        self.bank.fund_agent(self.ag["agent_id"], "1000000")
        self.payee = self.bank.add_payee(self.ag["agent_id"], "p", "058", "0690000031")

    def set_fee(self, **kw):
        with self.bank.db.write() as conn:
            F.set_schedule(conn, "NGN", **kw)

    def test_default_schedule_is_free(self):
        self.assertEqual(F.quote(self.bank.conn, 1_000_000, "NGN"), 0)

    def test_flat_plus_bps_with_floor_and_cap(self):
        self.set_fee(flat_minor=5000, bps=100, min_minor=0, cap_minor=20000)
        # 10,000 NGN = 1,000,000 kobo -> 5000 flat + 1% (10000) = 15000
        self.assertEqual(F.quote(self.bank.conn, 1_000_000, "NGN"), 15000)
        # Cap bites on a large amount.
        self.assertEqual(F.quote(self.bank.conn, 100_000_000, "NGN"), 20000)

    def test_floor_applies_to_tiny_amounts(self):
        self.set_fee(bps=100, min_minor=5000)
        self.assertEqual(F.quote(self.bank.conn, 100, "NGN"), 5000)

    def test_fee_is_integer_only_no_float_drift(self):
        self.set_fee(bps=333)
        # 3.33% of 1,000,001 kobo truncates, never rounds through a float.
        self.assertEqual(F.quote(self.bank.conn, 1_000_001, "NGN"),
                         (1_000_001 * 333) // 10_000)

    def test_agent_cannot_choose_the_fee(self):
        """TIER 3: the fee was caller-supplied, so the spender set our revenue."""
        self.set_fee(flat_minor=7500)
        out = self.bank.request_payout(self.ag["agent_id"], "1000",
                                       payee_id=self.payee, fee="0")
        self.assertEqual(out["fee_minor"], 7500)

    def test_fee_counts_against_the_spend_limit(self):
        self.set_fee(flat_minor=50_000)  # NGN 500
        self.bank.set_policy(self.ag["agent_id"], currency="NGN",
                             per_txn_max="1000", user_id=self.u["user_id"])
        # 900 + 500 fee = 1,400 > 1,000 per-txn cap.
        with self.assertRaises(PolicyDenied):
            self.bank.request_payout(self.ag["agent_id"], "900", payee_id=self.payee)

    def test_negative_schedule_is_rejected(self):
        with self.assertRaises(ValueError):
            self.set_fee(flat_minor=-1)
        with self.assertRaises(ValueError):
            self.set_fee(min_minor=500, cap_minor=100)


class TestSecretsFailClosed(Base):
    def test_admin_key_and_pepper_refuse_to_default_in_production(self):
        """TIER 1: both had working dev defaults, so a deployment that forgot
        to set them had a publicly known admin credential and no warning."""
        import importlib
        from aibank import bank as B
        saved = dict(os.environ)
        try:
            for k in ("AIBANK_ALLOW_DEV_SECRETS", "AIBANK_ADMIN_KEY", "AIBANK_KEY_PEPPER"):
                os.environ.pop(k, None)
            importlib.reload(B)
            with self.assertRaises(RuntimeError):
                B.key_pepper()
            from aibank import api as A
            importlib.reload(A)
            with self.assertRaises(RuntimeError):
                A.admin_key()
        finally:
            os.environ.clear()
            os.environ.update(saved)
            importlib.reload(B)
            from aibank import api as A2
            importlib.reload(A2)
            _rebind_reloaded(B)


def _rebind_reloaded(module) -> None:
    """Point every test module's imported names back at the reloaded classes.

    `importlib.reload` re-executes the module body in the same module object,
    so `aibank.bank.PolicyDenied` becomes a BRAND NEW class while every
    `from aibank.bank import PolicyDenied` done at test-collection time still
    references the old one. The two are not identical, so `assertRaises`
    stops matching and the exception escapes as an ERROR whose text is
    exactly what the test was waiting for -- a failure that accuses the
    product of a bug it does not have.

    This bit only the tests that happen to sort AFTER the reloading class in
    the same run, so the suite could pass or fail depending on nothing but a
    test's NAME. Rebinding here keeps that ordering dependency from silently
    deciding whether a money-movement guard looks broken.
    """
    for mod in list(sys.modules.values()):
        name = getattr(mod, "__name__", "")
        if not (name.startswith("test") or name.startswith("tests.")):
            continue
        for attr, old in list(vars(mod).items()):
            if (isinstance(old, type)
                    and getattr(old, "__module__", None) == module.__name__):
                fresh = getattr(module, attr, None)
                if isinstance(fresh, type) and fresh is not old:
                    setattr(mod, attr, fresh)


class TestConcurrentIdempotency(Base):
    def test_same_key_from_two_threads_yields_one_payout_not_a_500(self):
        """TIER 1: concurrent requests sharing an idempotency key raised a raw
        IntegrityError (HTTP 500) instead of returning the prior payout -- and a
        500 invites the client to retry, which is how double payments happen."""
        bank, _ = make_bank()
        u, _s = self.user(bank)
        ag = bank.create_agent("spender", user_id=u["user_id"], daily_max="1000000")
        bank.fund_agent(ag["agent_id"], "100000")
        payee = bank.add_payee(ag["agent_id"], "p", "058", "0690000031")

        results, errors = [], []
        start = threading.Barrier(6)

        def go():
            start.wait()
            try:
                results.append(bank.request_payout(
                    ag["agent_id"], "1000", payee_id=payee,
                    idempotency_key="same-key"))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=go) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"no request should error: {errors}")
        ids = {r["id"] for r in results}
        self.assertEqual(len(ids), 1, f"expected exactly one payout, got {ids}")
        rows = bank.conn.execute(
            "SELECT COUNT(*) AS n FROM payouts WHERE agent_id=?", (ag["agent_id"],)
        ).fetchone()
        self.assertEqual(rows["n"], 1)
        # And only ONE hold was placed, so the money was reserved once.
        held = bank.balance(ag["agent_id"])["held_minor"]
        self.assertEqual(held, 100_000)


class TestUnboundedPolicyDenies(Base):
    """An agent with no bound of any kind must not be able to spend.

    The bug: `create_agent` always INSERTs a policy row, so the
    `pol is None` guard in `policy.evaluate` was unreachable and an agent
    created without limits got a row of all-NULL ceilings -- which every
    limit check skips. The result was the exact inverse of the product's
    claim: the least-configured agent had the most authority, and could
    move its whole wallet in one payout with no approval.
    """

    def _agent_with(self, **policy_kwargs):
        bank, _ = make_bank()
        u = U.create_user(bank, "owner@example.com", "correct-horse-battery")
        ag = bank.create_agent("a", user_id=u["user_id"], **policy_kwargs)
        bank.deposit_to_user(u["user_id"], "100000", idempotency_key="d")
        bank.allocate_to_agent(u["user_id"], ag["agent_id"], "50000",
                               idempotency_key="al")
        return bank, u, ag

    def test_agent_created_with_no_limits_cannot_spend(self):
        bank, u, ag = self._agent_with()
        with self.assertRaises(PolicyDenied) as cm:
            bank.request_payout(ag["agent_id"], "40000", bank_code="058",
                                account_number="0690000031",
                                idempotency_key="k1")
        self.assertIn("no spend limit", str(cm.exception))

    def test_denial_is_about_the_missing_limit_not_the_amount(self):
        """A trivial payment is refused too -- the LIMIT is what is absent."""
        bank, u, ag = self._agent_with()
        with self.assertRaises(PolicyDenied):
            bank.request_payout(ag["agent_id"], "1", bank_code="058",
                                account_number="0690000031",
                                idempotency_key="k2")

    def test_any_single_bound_is_enough(self):
        """Partially configured policies must stay legal, one field at a time.

        Including `require_approval_above` alone: with it set, nothing above
        it moves without a human, so autonomous spend is bounded even though
        every amount ceiling is blank.
        """
        for kw in ({"per_txn_max": "10000"},
                   {"daily_max": "10000"},
                   {"monthly_max": "10000"},
                   {"require_approval_above": "10000"}):
            with self.subTest(**kw):
                bank, u, ag = self._agent_with(**kw)
                out = bank.request_payout(ag["agent_id"], "5000",
                                          bank_code="058",
                                          account_number="0690000031",
                                          idempotency_key="ok")
                self.assertIn(out["status"],
                              ("submitted", "successful", "pending_approval"))
                self.assertTrue(bank.trial_balance()["balanced"])

    def test_clearing_every_limit_later_also_denies(self):
        """The hole must stay shut when limits are REMOVED, not just at birth."""
        bank, u, ag = self._agent_with(per_txn_max="10000")
        bank.set_policy(ag["agent_id"], currency="NGN")   # all ceilings blank
        with self.assertRaises(PolicyDenied):
            bank.request_payout(ag["agent_id"], "5000", bank_code="058",
                                account_number="0690000031",
                                idempotency_key="k3")


class TestSuiteLeavesNoScratchBehind(Base):
    """A test that leaks disk is a slow outage with a passing status.

    Two backup tests used a bare `tempfile.mkdtemp` and never removed it, so
    every run left two directories containing a full copy of the ledger. On
    the development host -- a phone whose filesystem sits at 99% -- 38 had
    piled up before anyone looked. Nothing in a green suite would ever have
    reported it, which is why the invariant is asserted here rather than
    trusted to review.
    """

    def test_scratch_dirs_are_removed_on_teardown(self):
        d = self.scratch()
        self.assertTrue(os.path.isdir(d))
        self.assertIn(d, self._scratch)
        # Prove tearDown is what removes it, by running the same body.
        Base.tearDown(self)
        self.assertFalse(os.path.exists(d),
                         "scratch directory survived tearDown")

    def test_only_the_scratch_helper_calls_mkdtemp(self):
        """Guards the HABIT, not just today's two call sites.

        The next test needing a directory will be written by copying a
        neighbour, so the thing worth pinning is that no neighbour shows a
        bare mkdtemp to copy. Checked by AST rather than by counting the
        string, so prose in comments and docstrings cannot fail it.
        """
        import ast
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "test_users_and_policy.py")
        with open(src, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), src)

        offenders = []
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("mkdtemp", "mkstemp")
                        and fn.name != "scratch"):
                    offenders.append(f"{fn.name}:{node.lineno}")
        self.assertEqual(offenders, [],
                         "use self.scratch(); it is cleaned up in tearDown")


class TestConnectionsActuallyClose(Base):
    """`Database.close()` documented a guarantee it was not keeping.

    Every thread that touches the database gets its own connection, and worker
    threads exit without closing theirs -- which is precisely why `close()`
    walks `_all_conns`. But sqlite3 refuses EVERY operation on a connection
    from a foreign thread, `close()` included, and the `except sqlite3.Error`
    in that loop swallowed the resulting ProgrammingError. So it closed the
    caller's connection, silently failed on all the others, and returned as if
    it had succeeded. Under the threaded HTTP server that is a file descriptor
    and a WAL handle held per dead worker thread, for the life of the process.
    """

    def test_close_closes_connections_opened_by_other_threads(self):
        bank, _ = make_bank()
        opened = []
        barrier = threading.Barrier(5)

        def touch():
            barrier.wait()
            c = bank.db.conn
            c.execute("select 1").fetchone()
            opened.append(c)

        threads = [threading.Thread(target=touch) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(opened), 5)
        failed = bank.close()
        self.assertEqual(failed, 0, "close() could not close every connection")

        for c in opened:
            with self.assertRaises(sqlite3.ProgrammingError):
                c.execute("select 1")

    def test_close_reports_failures_instead_of_swallowing_them(self):
        """The count is the point: a close that cannot close must say so.

        Without a return value there is no difference, from the caller's side,
        between closing eleven connections and closing none of them.
        """
        bank, _ = make_bank()
        bank.db.conn.execute("select 1").fetchone()
        self.assertEqual(bank.close(), 0)
        # Idempotent: a second close has nothing left to do and still reports 0.
        self.assertEqual(bank.close(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
