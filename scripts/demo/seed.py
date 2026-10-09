#!/usr/bin/env python3
"""Seed a demo database with data that exercises every panel of the dashboard.

An empty dashboard proves nothing about layout. A review needs real content:
several agents, limits set and unset, a frozen agent, settled history, a
refund, and payouts actually parked waiting for the human's approval.

Every amount here is NGN and fictional. The payment provider is the test fake,
so nothing in this file can move real money.
"""
from __future__ import annotations

from aibank import ledger as L
from aibank import users as U

DEMO_EMAIL = "demo@aibank.local"
DEMO_PASSWORD = "demo-password-1234"
DEMO_NAME = "Demo Operator"


def _settle(bank, payout) -> None:
    """Drive the webhook path rather than writing 'successful' into the row.

    Seeding a settled payout by UPDATE would produce a database the real code
    could never have produced — no ledger capture, no webhook_events row — so
    the page would be rendering a state that cannot occur. Going through
    handle_webhook keeps the books honest: the trial balance still nets to 0.
    """
    bank.handle_webhook({
        "event": "transfer.completed",
        "data": {"id": abs(hash(payout["reference"])) % 10**7,
                 "reference": payout["reference"], "status": "SUCCESSFUL"},
    })


def seed(bank) -> dict:
    print("seeding demo data...")

    user = U.create_user(bank, DEMO_EMAIL, DEMO_PASSWORD, DEMO_NAME)
    uid = user["user_id"]

    # Money arriving from the outside world. Admin-gated in the API because
    # crediting a wallet from nothing is not something a customer may do for
    # themselves; here we call the method directly.
    bank.deposit_to_user(uid, "2500000", "NGN", memo="opening deposit")
    bank.deposit_to_user(uid, "750000", "NGN", memo="settlement")

    out = {"user_id": uid, "agents": []}

    # ---- agent 1: the normal case — limits set, history, one parked approval
    a1 = bank.create_agent("invoice-payer", user_id=uid)
    bank.set_policy(a1["agent_id"], currency="NGN",
                    per_txn_max="150000", daily_max="400000",
                    monthly_max="2000000", require_approval_above="100000",
                    max_payouts_per_day=20, tz_offset_minutes=60)
    bank.allocate_to_agent(uid, a1["agent_id"], "900000")
    p1 = bank.add_payee(a1["agent_id"], "Lagos Office Rent", "058", "0690000031")
    p2 = bank.add_payee(a1["agent_id"], "Adeyemi Printing", "044", "0690000032")

    # Settled history, through the real webhook path.
    for amt, payee in (("45000", p2), ("12500", p2), ("78000", p1)):
        po = bank.request_payout(a1["agent_id"], amt, payee_id=payee,
                                 narration="vendor payment")
        _settle(bank, po)

    # Over the approval threshold -> parks in pending_approval. This is the
    # panel that matters most in review: it is the one moment a human can
    # catch an agent paying the wrong account, so the masked destination has
    # to be legible on the card.
    bank.request_payout(a1["agent_id"], "120000", payee_id=p1,
                        narration="Q4 rent instalment")

    # A refund, so the history shows a reversal and not only happy paths.
    refunded = bank.request_payout(a1["agent_id"], "30000", payee_id=p2,
                                   narration="duplicate invoice")
    _settle(bank, refunded)
    bank.refund_payout(refunded["id"], user_id=uid)
    out["agents"].append(a1)

    # ---- agent 2: a SECOND parked approval, and a raw destination
    a2 = bank.create_agent("ops-bot", user_id=uid)
    bank.set_policy(a2["agent_id"], currency="NGN",
                    per_txn_max="200000", daily_max="500000",
                    require_approval_above="50000", tz_offset_minutes=60)
    bank.allocate_to_agent(uid, a2["agent_id"], "600000")
    # Straight to a bank code + account number with no saved payee. This case
    # used to be unapprovable because nothing recorded the destination; worth
    # seeing it render on the approval card.
    bank.request_payout(a2["agent_id"], "95000",
                        bank_code="033", account_number="0690000033",
                        narration="contractor payout")
    out["agents"].append(a2)

    # ---- agent 3: NO LIMITS AT ALL. Deny-by-default means it cannot spend a
    # single naira: with no amount ceiling and no approval threshold there is
    # nothing bounding it, so every payout is refused. Worth rendering because
    # an unconfigured agent must not read as "unlimited" on the page.
    a3 = bank.create_agent("sandbox-agent", user_id=uid)
    bank.allocate_to_agent(uid, a3["agent_id"], "50000")
    out["agents"].append(a3)

    # ---- agent 4: FROZEN. A frozen agent cannot spend regardless of limits.
    a4 = bank.create_agent("deprecated-scraper", user_id=uid)
    bank.set_policy(a4["agent_id"], currency="NGN", per_txn_max="10000",
                    daily_max="20000", tz_offset_minutes=60)
    bank.allocate_to_agent(uid, a4["agent_id"], "25000")
    bank.freeze_agent(a4["agent_id"], frozen=True)
    out["agents"].append(a4)

    net = L.trial_balance(bank.conn)
    print(f"  user: {DEMO_EMAIL} / {DEMO_PASSWORD}")
    print("  4 agents, 2 payouts awaiting approval, 1 refund on the books")
    print(f"  trial balance: {net} ({'balanced' if net == 0 else 'CORRUPT'})")
    if net != 0:
        raise SystemExit("seed produced unbalanced books — refusing to serve")
    return out


if __name__ == "__main__":
    raise SystemExit("run serve_demo.py; it seeds on first start")
