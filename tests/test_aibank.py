"""Behavioural tests. Run: python3 tests/test_aibank.py

No pytest dependency -- plain unittest so it runs on a bare Termux box.
"""
from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aibank import fees as F
from aibank import ledger as L
from aibank import policy as P
from aibank import users as U
from aibank.bank import Bank, NotFound, PolicyDenied
from aibank.flutterwave import FlutterwaveClient, dedupe_key, verify_webhook
from aibank.ledger import InsufficientFunds, Unbalanced, DuplicateIdempotencyKey
from aibank.money import MoneyError, to_major, to_minor
from tests.fake_flw import FakeFLW


_OPEN_BANKS: list = []


def make_bank(**flw_kwargs) -> tuple[Bank, FakeFLW]:
    fake = FakeFLW(**flw_kwargs)
    client = FlutterwaveClient(secret_key="FLWSECK_TEST-fake", opener=fake)
    bank = Bank(":memory:", flw=client)
    _OPEN_BANKS.append(bank)
    return bank, fake


class BankTestCase(unittest.TestCase):
    """Closes every scratch DB opened during a test (kills ResourceWarnings).

    Bank.close() closes EVERY thread's connection, not just this one's, so
    worker threads that exited without cleaning up don't leak descriptors.
    """

    def tearDown(self):
        while _OPEN_BANKS:
            try:
                _OPEN_BANKS.pop().close()
            except Exception:
                pass


class TestMoney(unittest.TestCase):
    def test_exact_conversion(self):
        self.assertEqual(to_minor("1234.56", "NGN"), 123456)
        self.assertEqual(to_minor(1234, "NGN"), 123400)
        self.assertEqual(to_major(123456, "NGN"), "1234.56")

    def test_half_up_rounding(self):
        self.assertEqual(to_minor("0.005", "NGN"), 1)
        self.assertEqual(to_minor("0.004", "NGN"), 0)

    def test_float_artifacts_do_not_leak(self):
        # 0.1 + 0.2 in float is 0.30000000000000004; our path must not care.
        self.assertEqual(to_minor("0.30", "NGN"), 30)
        self.assertEqual(to_minor(0.1, "NGN") + to_minor(0.2, "NGN"), 30)

    def test_six_dp_stablecoin(self):
        self.assertEqual(to_minor("1.000001", "USDC"), 1000001)

    def test_rejects_garbage(self):
        for bad in ("abc", "1.2.3", ""):
            with self.assertRaises(MoneyError):
                to_minor(bad, "NGN")
        with self.assertRaises(MoneyError):
            to_minor("1", "XXX")


class TestLedger(BankTestCase):
    def setUp(self):
        self.bank, _ = make_bank()
        self.conn = self.bank.conn

    def test_unbalanced_entry_rejected(self):
        a = L.get_or_create_account(self.conn, None, "external", "NGN")
        b = L.get_or_create_account(self.conn, None, "revenue_fees", "NGN")
        with self.assertRaises(Unbalanced):
            L.post_entry(self.conn, "bad", [(a, 100), (b, -99)], "NGN")

    def test_funding_moves_balance_and_nets_to_zero(self):
        ag = self.bank.create_agent("t", daily_max="100000")
        self.bank.fund_agent(ag["agent_id"], "5000.00")
        self.assertEqual(self.bank.balance(ag["agent_id"])["balance_minor"], 500000)
        self.assertEqual(L.trial_balance(self.conn), 0)

    def test_idempotent_funding(self):
        ag = self.bank.create_agent("t", daily_max="100000")
        self.bank.fund_agent(ag["agent_id"], "100", idempotency_key="fund-1")
        with self.assertRaises(DuplicateIdempotencyKey):
            self.bank.fund_agent(ag["agent_id"], "100", idempotency_key="fund-1")
        self.assertEqual(self.bank.balance(ag["agent_id"])["balance_minor"], 10000)

    def test_hold_reduces_available_not_balance(self):
        ag = self.bank.create_agent("t", daily_max="100000")
        self.bank.fund_agent(ag["agent_id"], "1000")
        wallet = self.bank.wallet_id(ag["agent_id"])
        L.place_hold(self.conn, ag["agent_id"], wallet, 40000, "NGN")
        bal = self.bank.balance(ag["agent_id"])
        self.assertEqual(bal["balance_minor"], 100000)
        self.assertEqual(bal["available_minor"], 60000)

    def test_cannot_hold_more_than_available(self):
        ag = self.bank.create_agent("t", daily_max="100000")
        self.bank.fund_agent(ag["agent_id"], "100")
        wallet = self.bank.wallet_id(ag["agent_id"])
        with self.assertRaises(InsufficientFunds):
            L.place_hold(self.conn, ag["agent_id"], wallet, 10001, "NGN")


class TestPolicy(BankTestCase):
    def setUp(self):
        self.bank, self.fake = make_bank()

    def test_no_policy_means_no_spending(self):
        aid = L.new_id("agent")
        self.bank.conn.execute(
            "INSERT INTO agents (id,name,status,created_at) VALUES (?,?,'active',?)",
            (aid, "naked", L.now_iso()))
        d = P.evaluate(self.bank.conn, aid, 100, 0, "NGN", None)
        self.assertFalse(d.allowed)
        self.assertIn("no spend policy", d.reason)

    def test_per_txn_ceiling(self):
        ag = self.bank.create_agent("t", per_txn_max="5000", daily_max="100000")
        self.bank.fund_agent(ag["agent_id"], "50000")
        with self.assertRaises(PolicyDenied) as ctx:
            self.bank.request_payout(ag["agent_id"], "5000.01",
                                     bank_code="044", account_number="1234567890")
        self.assertIn("per-transaction", str(ctx.exception))

    def test_daily_cap_accumulates(self):
        ag = self.bank.create_agent("t", per_txn_max="10000", daily_max="15000")
        self.bank.fund_agent(ag["agent_id"], "50000")
        self.bank.request_payout(ag["agent_id"], "10000",
                                 bank_code="044", account_number="1234567890")
        with self.assertRaises(PolicyDenied) as ctx:
            self.bank.request_payout(ag["agent_id"], "6000",
                                     bank_code="044", account_number="1234567890")
        self.assertIn("daily limit", str(ctx.exception))

    def test_frozen_agent_cannot_spend(self):
        ag = self.bank.create_agent("t", daily_max="100000")
        self.bank.fund_agent(ag["agent_id"], "10000")
        self.bank.freeze_agent(ag["agent_id"])
        with self.assertRaises(PolicyDenied):
            self.bank.request_payout(ag["agent_id"], "100",
                                     bank_code="044", account_number="1234567890")

    def test_allowlist_blocks_arbitrary_account(self):
        ag = self.bank.create_agent("t", daily_max="100000", allowlist_only=True)
        self.bank.fund_agent(ag["agent_id"], "10000")
        with self.assertRaises(PolicyDenied) as ctx:
            self.bank.request_payout(ag["agent_id"], "100",
                                     bank_code="044", account_number="9999999999")
        self.assertIn("saved payees", str(ctx.exception))

    def test_cannot_pay_another_agents_payee(self):
        a = self.bank.create_agent("a", daily_max="100000")
        b = self.bank.create_agent("b", daily_max="100000")
        self.bank.fund_agent(a["agent_id"], "10000")
        victim = self.bank.add_payee(b["agent_id"], "theirs", "044", "1111111111")
        with self.assertRaises(PolicyDenied):
            self.bank.request_payout(a["agent_id"], "100", payee_id=victim)

    def test_approval_threshold(self):
        ag = self.bank.create_agent("t", daily_max="1000000",
                                    require_approval_above="50000")
        self.bank.fund_agent(ag["agent_id"], "200000")
        payee = self.bank.add_payee(ag["agent_id"], "vendor", "044", "1234567890")
        out = self.bank.request_payout(ag["agent_id"], "60000", payee_id=payee)
        self.assertEqual(out["status"], "pending_approval")
        self.assertEqual(len(self.fake.requests), 0)  # nothing sent to provider yet
        approved = self.bank.approve_payout(out["id"])
        self.assertEqual(approved["status"], "submitted")
        self.assertEqual(len(self.fake.requests), 1)


class TestPayoutLifecycle(BankTestCase):
    def setUp(self):
        self.bank, self.fake = make_bank()
        self.ag = self.bank.create_agent("worker", per_txn_max="50000", daily_max="200000")
        self.bank.fund_agent(self.ag["agent_id"], "100000")
        self.payee = self.bank.add_payee(self.ag["agent_id"], "vendor", "044", "1234567890")

    def test_submit_holds_funds_before_settlement(self):
        out = self.bank.request_payout(self.ag["agent_id"], "20000", payee_id=self.payee)
        self.assertEqual(out["status"], "submitted")
        bal = self.bank.balance(self.ag["agent_id"])
        self.assertEqual(bal["balance_minor"], 10000000)   # not yet debited
        self.assertEqual(bal["held_minor"], 2000000)       # but reserved
        self.assertEqual(bal["available_minor"], 8000000)

    def test_provider_receives_major_units(self):
        self.bank.request_payout(self.ag["agent_id"], "20000", payee_id=self.payee)
        sent = self.fake.requests[0]["body"]
        self.assertEqual(sent["amount"], "20000.00")   # naira, not kobo
        self.assertEqual(sent["account_bank"], "044")
        self.assertEqual(sent["currency"], "NGN")
        auth = dict(self.fake.requests[0]["headers"])
        self.assertTrue(any("Bearer" in str(v) for v in auth.values()))

    def test_success_webhook_settles_and_debits(self):
        out = self.bank.request_payout(self.ag["agent_id"], "20000", payee_id=self.payee)
        res = self.bank.handle_webhook({
            "event": "transfer.completed",
            "data": {"id": 99, "reference": out["reference"], "status": "SUCCESSFUL",
                     "amount": 20000, "currency": "NGN"}})
        self.assertEqual(res["result"], "settled")
        bal = self.bank.balance(self.ag["agent_id"])
        self.assertEqual(bal["balance_minor"], 8000000)
        self.assertEqual(bal["held_minor"], 0)
        self.assertEqual(L.trial_balance(self.bank.conn), 0)

    def test_failed_webhook_releases_hold_money_never_leaves(self):
        out = self.bank.request_payout(self.ag["agent_id"], "20000", payee_id=self.payee)
        self.bank.handle_webhook({
            "event": "transfer.completed",
            "data": {"id": 100, "reference": out["reference"], "status": "FAILED",
                     "complete_message": "Bank declined"}})
        bal = self.bank.balance(self.ag["agent_id"])
        self.assertEqual(bal["available_minor"], 10000000)  # fully restored
        self.assertEqual(self.bank.get_payout(out["id"])["status"], "failed")

    def test_duplicate_webhook_is_noop(self):
        out = self.bank.request_payout(self.ag["agent_id"], "20000", payee_id=self.payee)
        evt = {"event": "transfer.completed",
               "data": {"id": 77, "reference": out["reference"], "status": "SUCCESSFUL"}}
        first = self.bank.handle_webhook(evt)
        second = self.bank.handle_webhook(evt)
        self.assertEqual(first["result"], "settled")
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["balance_minor"], 8000000)

    def test_replayed_webhook_with_new_id_still_cannot_double_debit(self):
        out = self.bank.request_payout(self.ag["agent_id"], "20000", payee_id=self.payee)
        for eid in (1, 2, 3):
            self.bank.handle_webhook({
                "event": "transfer.completed",
                "data": {"id": eid, "reference": out["reference"], "status": "SUCCESSFUL"}})
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["balance_minor"], 8000000)
        self.assertEqual(L.trial_balance(self.bank.conn), 0)

    def test_idempotent_payout_request(self):
        a = self.bank.request_payout(self.ag["agent_id"], "1000", payee_id=self.payee,
                                     idempotency_key="job-42")
        b = self.bank.request_payout(self.ag["agent_id"], "1000", payee_id=self.payee,
                                     idempotency_key="job-42")
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(len(self.fake.requests), 1)  # only ONE real transfer
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["held_minor"], 100000)

    def test_idempotency_key_is_scoped_per_agent(self):
        """Two agents using the SAME key must get two DIFFERENT payouts.

        Regression: a global key namespace leaked one agent's payout to another.
        """
        other = self.bank.create_agent("other", per_txn_max="50000", daily_max="200000")
        self.bank.fund_agent(other["agent_id"], "100000")
        other_payee = self.bank.add_payee(other["agent_id"], "v2", "044", "2222222222")
        a = self.bank.request_payout(self.ag["agent_id"], "1000", payee_id=self.payee,
                                     idempotency_key="shared-key")
        b = self.bank.request_payout(other["agent_id"], "1000", payee_id=other_payee,
                                     idempotency_key="shared-key")
        self.assertNotEqual(a["id"], b["id"])
        self.assertNotEqual(a["reference"], b["reference"])
        self.assertEqual(a["agent_id"], self.ag["agent_id"])
        self.assertEqual(b["agent_id"], other["agent_id"])
        self.assertEqual(len(self.fake.requests), 2)

    def test_agent_cannot_overspend_balance(self):
        with self.assertRaises(InsufficientFunds):
            for _ in range(10):
                self.bank.request_payout(self.ag["agent_id"], "30000", payee_id=self.payee)

    def test_network_failure_releases_hold(self):
        bank, fake = make_bank(fail_on_transfer=True)
        ag = bank.create_agent("t", per_txn_max="50000", daily_max="200000")
        bank.fund_agent(ag["agent_id"], "100000")
        payee = bank.add_payee(ag["agent_id"], "v", "044", "1234567890")
        out = bank.request_payout(ag["agent_id"], "20000", payee_id=payee)
        self.assertEqual(out["status"], "failed")
        self.assertEqual(bank.balance(ag["agent_id"])["available_minor"], 10000000)

    def test_provider_http_error_releases_hold(self):
        bank, fake = make_bank(http_error=400)
        ag = bank.create_agent("t", per_txn_max="50000", daily_max="200000")
        bank.fund_agent(ag["agent_id"], "100000")
        payee = bank.add_payee(ag["agent_id"], "v", "044", "1234567890")
        out = bank.request_payout(ag["agent_id"], "20000", payee_id=payee)
        self.assertEqual(out["status"], "failed")
        self.assertIn("Insufficient funds", out["failure_reason"])
        self.assertEqual(bank.balance(ag["agent_id"])["available_minor"], 10000000)

    def test_reconcile_when_webhook_never_arrives(self):
        out = self.bank.request_payout(self.ag["agent_id"], "20000", payee_id=self.payee)
        res = self.bank.reconcile(out["id"])
        self.assertEqual(res["status"], "SUCCESSFUL")
        self.assertEqual(self.bank.balance(self.ag["agent_id"])["balance_minor"], 8000000)

    def test_fee_is_booked_to_revenue(self):
        # The fee is now SERVER-side: `fee=` in the request is ignored, so this
        # configures the schedule instead. A flat NGN 50 on this payout.
        with self.bank.db.write() as conn:
            F.set_schedule(conn, "NGN", flat_minor=5000)
        out = self.bank.request_payout(self.ag["agent_id"], "10000", payee_id=self.payee,
                                       fee="50")
        self.assertEqual(out["fee_minor"], 5000)
        self.bank.handle_webhook({"event": "transfer.completed",
            "data": {"id": 55, "reference": out["reference"], "status": "SUCCESSFUL"}})
        bal = self.bank.balance(self.ag["agent_id"])
        self.assertEqual(bal["balance_minor"], 10000000 - 1000000 - 5000)
        fees = L.get_or_create_account(self.bank.conn, None, "revenue_fees", "NGN")
        self.assertEqual(L.balance(self.bank.conn, fees), 5000)
        self.assertEqual(L.trial_balance(self.bank.conn), 0)

    def test_caller_supplied_fee_is_ignored(self):
        """The spender must not be able to choose the platform's revenue."""
        with self.bank.db.write() as conn:
            F.set_schedule(conn, "NGN", flat_minor=0, bps=100)  # 1%
        out = self.bank.request_payout(self.ag["agent_id"], "10000", payee_id=self.payee,
                                       fee="0")
        self.assertEqual(out["fee_minor"], 10000)  # 1% of 1,000,000 kobo


class TestAuthAndWebhookSecurity(BankTestCase):
    def setUp(self):
        self.bank, _ = make_bank()

    def test_api_key_authenticates_only_its_owner(self):
        a = self.bank.create_agent("a", daily_max="1000")
        b = self.bank.create_agent("b", daily_max="1000")
        self.assertEqual(self.bank.authenticate(a["api_key"]), a["agent_id"])
        self.assertNotEqual(self.bank.authenticate(b["api_key"]), a["agent_id"])
        self.assertIsNone(self.bank.authenticate("sk_agent_wrong"))
        self.assertIsNone(self.bank.authenticate(""))

    def test_plaintext_key_is_never_stored(self):
        ag = self.bank.create_agent("a", daily_max="1000")
        rows = self.bank.conn.execute("SELECT key_hash FROM api_keys").fetchall()
        self.assertTrue(all(ag["api_key"] not in r["key_hash"] for r in rows))

    def test_v3_plain_secret_header(self):
        self.assertTrue(verify_webhook(b"{}", {"verif-hash": "s3cret"}, "s3cret"))
        self.assertFalse(verify_webhook(b"{}", {"verif-hash": "wrong"}, "s3cret"))

    def test_v4_hmac_signature(self):
        import base64, hashlib, hmac
        body = b'{"event":"transfer.completed"}'
        sig = base64.b64encode(hmac.new(b"s3cret", body, hashlib.sha256).digest()).decode()
        self.assertTrue(verify_webhook(body, {"flutterwave-signature": sig}, "s3cret"))
        self.assertFalse(verify_webhook(b'{"tampered":1}',
                                        {"flutterwave-signature": sig}, "s3cret"))

    def test_missing_signature_rejected(self):
        self.assertFalse(verify_webhook(b"{}", {}, "s3cret"))
        self.assertFalse(verify_webhook(b"{}", {"verif-hash": "x"}, ""))

    def test_dedupe_key_is_stable_and_distinct(self):
        e1 = {"event": "transfer.completed", "data": {"id": 1, "reference": "r"}}
        e2 = {"event": "transfer.completed", "data": {"id": 2, "reference": "r"}}
        self.assertEqual(dedupe_key(e1), dedupe_key(dict(e1)))
        self.assertNotEqual(dedupe_key(e1), dedupe_key(e2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
