"""Tests for the human layer: users, sessions, ownership, approvals, pricing.

These exist because of a specific pivot: the service became a real banking
product where a HUMAN sets the limits from a dashboard and the agent merely
spends under them. Every test below pins one half of that invariant --
either "the human can do X" or, more importantly, "the agent cannot".

Run: python -m unittest discover -s tests
"""
from __future__ import annotations

import os
import sys
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

    def user(self, bank, email="kay@example.com", pw="correct-horse-battery"):
        u = U.create_user(bank, email, pw, "Kay")
        s = U.login(bank, email, pw, client_ip="10.0.0.1")
        return u, s


class TestMigrations(Base):
    def test_fresh_db_is_at_head(self):
        bank, _ = make_bank()
        self.assertEqual(bank.schema_version(), 2)

    def test_migration_is_atomic_and_stamped(self):
        """Regression: executescript() issues an implicit COMMIT, which used to
        discard the BEGIN opened just before it. Migrations then ran outside any
        transaction (so a mid-script failure left a half-built schema) and the
        explicit COMMIT raised "cannot commit - no transaction is active"."""
        from aibank import db as D
        conn = D.connect(":memory:")
        try:
            applied = D.migrate(conn)
            self.assertEqual(applied, [1, 2])
            rows = conn.execute("SELECT version FROM schema_version ORDER BY version").fetchall()
            self.assertEqual([r[0] for r in rows], [1, 2])
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
        self.assertEqual(bank.schema_version(), 2)
        # The v2 rebuild of `accounts` must have carried the row (and its
        # postings, by id) across the DROP/RENAME.
        self.assertEqual(bank.balance("agent_old")["balance_minor"], 77700)
        self.assertTrue(bank.trial_balance()["balanced"])


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
