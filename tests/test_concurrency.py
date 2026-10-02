"""Concurrency: the failure mode that actually loses real money.

A looping or parallelised agent will fire simultaneous payouts. If the policy
check and the hold are not atomic, several requests each see "funds available"
and together overspend the wallet.
"""
from __future__ import annotations

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aibank import ledger as L
from aibank.bank import Bank, PolicyDenied
from aibank.flutterwave import FlutterwaveClient
from aibank.ledger import InsufficientFunds
from tests.fake_flw import FakeFLW


class TestConcurrentSpend(unittest.TestCase):
    def test_parallel_payouts_cannot_overspend(self):
        fake = FakeFLW()
        bank = Bank(":memory:", flw=FlutterwaveClient(secret_key="k", opener=fake))
        ag = bank.create_agent("racer", per_txn_max="10000", daily_max="1000000")
        bank.fund_agent(ag["agent_id"], "50000")          # NGN 50,000 total
        payee = bank.add_payee(ag["agent_id"], "v", "044", "1234567890")

        ok, denied, errors = [], [], []
        barrier = threading.Barrier(20)

        def spend():
            barrier.wait()   # maximise the race
            try:
                ok.append(bank.request_payout(ag["agent_id"], "10000", payee_id=payee))
            except (InsufficientFunds, PolicyDenied):
                denied.append(1)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=spend) for _ in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(errors, [], f"unexpected errors: {errors}")
        # 50,000 balance / 10,000 each == AT MOST 5 may succeed. Never 6.
        self.assertLessEqual(len(ok), 5, "OVERSPEND: more payouts than funds allowed")
        self.assertEqual(len(ok) + len(denied), 20)
        self.assertEqual(len(fake.requests), len(ok),
                         "provider calls must match successful authorisations")

        bal = bank.balance(ag["agent_id"])
        self.assertGreaterEqual(bal["available_minor"], 0, "available went NEGATIVE")
        self.assertEqual(bal["held_minor"], len(ok) * 1000000)
        self.assertEqual(L.trial_balance(bank.conn), 0)
        bank.close()

    def test_parallel_duplicate_webhooks_settle_once(self):
        fake = FakeFLW()
        bank = Bank(":memory:", flw=FlutterwaveClient(secret_key="k", opener=fake))
        ag = bank.create_agent("w", per_txn_max="50000", daily_max="1000000")
        bank.fund_agent(ag["agent_id"], "100000")
        payee = bank.add_payee(ag["agent_id"], "v", "044", "1234567890")
        out = bank.request_payout(ag["agent_id"], "20000", payee_id=payee)

        evt = {"event": "transfer.completed",
               "data": {"id": 4242, "reference": out["reference"], "status": "SUCCESSFUL"}}
        results, errors = [], []
        barrier = threading.Barrier(12)

        def deliver():
            barrier.wait()
            try:
                results.append(bank.handle_webhook(dict(evt)))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=deliver) for _ in range(12)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(errors, [], f"unexpected errors: {errors}")
        settled = [r for r in results if r.get("result") == "settled"]
        self.assertEqual(len(settled), 1, "event settled more than once")
        # Debited exactly once: 100,000 - 20,000
        self.assertEqual(bank.balance(ag["agent_id"])["balance_minor"], 8000000)
        self.assertEqual(L.trial_balance(bank.conn), 0)
        bank.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
