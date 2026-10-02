"""The Bank service: agents, keys, funding, payouts, webhooks.

Payout lifecycle (the part that makes this safe for autonomous agents):

  request -> policy check -> HOLD funds -> submit to Flutterwave
          -> webhook says SUCCESSFUL -> capture hold + post ledger entry
          -> webhook says FAILED     -> release hold, money never left

The hold is what stops a looping agent from spending the same naira twice
while the provider is still thinking.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone

from . import ledger as L
from . import policy as P
from .db import Database
from .flutterwave import FlutterwaveClient, FlutterwaveError, dedupe_key
from .money import check_currency, to_major, to_minor

KEY_PEPPER = os.environ.get("AIBANK_KEY_PEPPER", "dev-pepper-change-me")


def hash_key(plaintext: str) -> str:
    return hashlib.sha256((KEY_PEPPER + plaintext).encode()).hexdigest()


class BankError(Exception):
    pass


class PolicyDenied(BankError):
    pass


class Bank:
    def __init__(self, db_path: str = "aibank.db", flw: FlutterwaveClient | None = None,
                 callback_url: str | None = None):
        self.db = Database(db_path)
        self.flw = flw or FlutterwaveClient()
        self.callback_url = callback_url or os.environ.get("AIBANK_CALLBACK_URL")

    @property
    def conn(self):
        """Per-thread connection -- safe under the threaded HTTP server."""
        return self.db.conn

    def close(self):
        self.db.close()

    # ---------- agents & auth ----------
    def create_agent(self, name: str, currency: str = "NGN", **policy_kwargs) -> dict:
        currency = check_currency(currency)
        agent_id = L.new_id("agent")
        raw_key = "sk_agent_" + secrets.token_urlsafe(32)
        with self.db.write() as conn:
            conn.execute(
                "INSERT INTO agents (id, name, status, created_at) VALUES (?,?,'active',?)",
                (agent_id, name, L.now_iso()),
            )
            wallet = L.get_or_create_account(conn, agent_id, "agent_wallet", currency)
            conn.execute(
                "INSERT INTO api_keys (id, agent_id, key_prefix, key_hash, created_at)"
                " VALUES (?,?,?,?,?)",
                (L.new_id("key"), agent_id, raw_key[:16], hash_key(raw_key), L.now_iso()),
            )
            L.audit(conn, agent_id, "agent.create", "ok", {"name": name})
        self.set_policy(agent_id, currency=currency, **policy_kwargs)
        return {"agent_id": agent_id, "name": name, "wallet_account_id": wallet,
                "currency": currency, "api_key": raw_key}

    def authenticate(self, api_key: str) -> str | None:
        row = self.conn.execute(
            "SELECT agent_id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
            (hash_key(api_key or ""),),
        ).fetchone()
        return row["agent_id"] if row else None

    def freeze_agent(self, agent_id: str, frozen: bool = True) -> None:
        self.conn.execute("UPDATE agents SET status = ? WHERE id = ?",
                          ("frozen" if frozen else "active", agent_id))
        L.audit(self.conn, agent_id, "agent.freeze", str(frozen))

    def set_policy(self, agent_id: str, currency: str = "NGN", per_txn_max=None,
                   daily_max=None, monthly_max=None, allowlist_only: bool = False,
                   require_approval_above=None) -> None:
        currency = check_currency(currency)
        conv = lambda v: None if v is None else to_minor(v, currency)
        self.conn.execute(
            "INSERT INTO policies (agent_id, currency, per_txn_max_minor, daily_max_minor,"
            " monthly_max_minor, allowlist_only, require_approval_above_minor, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET"
            " currency=excluded.currency, per_txn_max_minor=excluded.per_txn_max_minor,"
            " daily_max_minor=excluded.daily_max_minor,"
            " monthly_max_minor=excluded.monthly_max_minor,"
            " allowlist_only=excluded.allowlist_only,"
            " require_approval_above_minor=excluded.require_approval_above_minor,"
            " updated_at=excluded.updated_at",
            (agent_id, currency, conv(per_txn_max), conv(daily_max), conv(monthly_max),
             1 if allowlist_only else 0, conv(require_approval_above), L.now_iso()),
        )

    def wallet_id(self, agent_id: str, currency: str = "NGN") -> str:
        return L.get_or_create_account(self.conn, agent_id, "agent_wallet", currency)

    def add_payee(self, agent_id: str, label: str, bank_code: str,
                  account_number: str, currency: str = "NGN") -> str:
        currency = check_currency(currency)
        payee_id = L.new_id("payee")
        self.conn.execute(
            "INSERT INTO payees (id, agent_id, label, bank_code, account_number, currency,"
            " created_at) VALUES (?,?,?,?,?,?,?)",
            (payee_id, agent_id, label, bank_code, account_number, currency, L.now_iso()),
        )
        return payee_id

    # ---------- balances ----------
    def balance(self, agent_id: str, currency: str = "NGN") -> dict:
        acct = self.wallet_id(agent_id, currency)
        bal, hold = L.balance(self.conn, acct), L.held(self.conn, acct)
        return {"currency": currency, "balance_minor": bal, "held_minor": hold,
                "available_minor": bal - hold, "balance": to_major(bal, currency),
                "held": to_major(hold, currency), "available": to_major(bal - hold, currency)}

    def fund_agent(self, agent_id: str, amount, currency: str = "NGN",
                   memo: str = "funding", idempotency_key: str | None = None) -> str:
        """Move money from our Flutterwave settlement balance into an agent wallet."""
        currency = check_currency(currency)
        minor = to_minor(amount, currency)
        if minor <= 0:
            raise BankError("funding amount must be positive")
        with self.db.write() as conn:
            wallet = L.get_or_create_account(conn, agent_id, "agent_wallet", currency)
            settle = L.get_or_create_account(conn, None, "flw_settlement", currency)
            # Debit the agent wallet (value in), credit settlement (value out).
            entry = L.post_entry(
                conn, "funding", [(wallet, minor), (settle, -minor)], currency,
                agent_id=agent_id, memo=memo, idempotency_key=idempotency_key,
            )
            L.audit(conn, agent_id, "wallet.fund", "ok", {"amount_minor": minor})
        return entry

    # ---------- payouts ----------
    def request_payout(self, agent_id: str, amount, currency: str = "NGN",
                       payee_id: str | None = None, bank_code: str | None = None,
                       account_number: str | None = None, narration: str = "",
                       fee=0, idempotency_key: str | None = None,
                       submit: bool = True) -> dict:
        currency = check_currency(currency)
        minor = to_minor(amount, currency)
        fee_minor = to_minor(fee, currency)

        # Idempotency keys are scoped PER AGENT. A global namespace would let one
        # agent's key collide with another's -- returning someone else's payout.
        scoped_ref = f"ref_{agent_id[-12:]}_{idempotency_key}" if idempotency_key else None
        if scoped_ref:
            prior = self.conn.execute(
                "SELECT id FROM payouts WHERE reference = ? AND agent_id = ?",
                (scoped_ref, agent_id),
            ).fetchone()
            if prior:
                return self.get_payout(prior["id"])

        if payee_id:
            payee = self.conn.execute(
                "SELECT * FROM payees WHERE id = ? AND agent_id = ?", (payee_id, agent_id)
            ).fetchone()
            if not payee:
                raise PolicyDenied("payee does not belong to this agent")
            bank_code, account_number = payee["bank_code"], payee["account_number"]
        if not (bank_code and account_number):
            raise BankError("need payee_id or bank_code + account_number")

        # Policy check and the hold it authorises must be ONE atomic step, or two
        # concurrent requests could each pass the check and together overspend.
        payout_id = L.new_id("payout")
        with self.db.write() as conn:
            decision = P.evaluate(conn, agent_id, minor, fee_minor, currency, payee_id)
            if not decision.allowed:
                L.audit(conn, agent_id, "payout.request", "denied",
                        {"reason": decision.reason, "amount_minor": minor})
                raise PolicyDenied(decision.reason)

            wallet = L.get_or_create_account(conn, agent_id, "agent_wallet", currency)
            hold_id = L.place_hold(conn, agent_id, wallet, minor + fee_minor, currency)

            reference = scoped_ref or f"aibank_{payout_id[-16:]}"
            status = "pending_approval" if decision.requires_approval else "submitted"
            ts = L.now_iso()
            conn.execute(
                "INSERT INTO payouts (id, agent_id, payee_id, amount_minor, fee_minor,"
                " currency, status, reference, hold_id, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (payout_id, agent_id, payee_id, minor, fee_minor, currency, status,
                 reference, hold_id, ts, ts),
            )
            L.audit(conn, agent_id, "payout.request", status,
                    {"payout_id": payout_id, "amount_minor": minor})

        # Network call happens AFTER commit -- never hold a DB write lock across I/O.
        if decision.requires_approval or not submit:
            return self.get_payout(payout_id)
        return self._submit(payout_id, bank_code, account_number, narration)

    def approve_payout(self, payout_id: str, narration: str = "") -> dict:
        p = self.conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
        if not p:
            raise BankError("unknown payout")
        if p["status"] != "pending_approval":
            raise BankError(f"payout is {p['status']}, not awaiting approval")
        payee = self.conn.execute("SELECT * FROM payees WHERE id = ?", (p["payee_id"],)).fetchone()
        if not payee:
            raise BankError("payout has no resolvable payee")
        L.audit(self.conn, p["agent_id"], "payout.approve", "ok", {"payout_id": payout_id})
        return self._submit(payout_id, payee["bank_code"], payee["account_number"], narration)

    def _submit(self, payout_id: str, bank_code: str, account_number: str,
                narration: str) -> dict:
        p = self.conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
        currency = p["currency"]
        try:
            resp = self.flw.initiate_transfer(
                bank_code=bank_code, account_number=account_number,
                amount_major=to_major(p["amount_minor"], currency),
                currency=currency, reference=p["reference"],
                narration=narration or "aibank payout",
                callback_url=self.callback_url,
                meta={"payout_id": payout_id, "agent_id": p["agent_id"]},
            )
        except FlutterwaveError as exc:
            # Provider rejected it outright -> nothing left, release the hold.
            self._fail(payout_id, f"provider error: {exc}")
            return self.get_payout(payout_id)

        data = (resp or {}).get("data") or {}
        self.conn.execute(
            "UPDATE payouts SET status='submitted', provider_id=?, provider_status=?,"
            " updated_at=? WHERE id=?",
            (str(data.get("id")) if data.get("id") is not None else None,
             data.get("status"), L.now_iso(), payout_id),
        )
        return self.get_payout(payout_id)

    def _settle(self, payout_id: str, conn=None) -> None:
        """Money truly left. Capture the hold and write the real ledger entry.

        Guarded by the payout status check: settling twice is impossible, so a
        duplicate webhook can never debit the agent twice.
        """
        owns_txn = conn is None
        if owns_txn:
            ctx = self.db.write(); conn = ctx.__enter__()
        try:
            p = conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
            if p["status"] == "successful":
                return
            currency = p["currency"]
            wallet = L.get_or_create_account(conn, p["agent_id"], "agent_wallet", currency)
            external = L.get_or_create_account(conn, None, "external", currency)
            legs = [(wallet, -(p["amount_minor"] + p["fee_minor"])),
                    (external, p["amount_minor"])]
            if p["fee_minor"]:
                fees = L.get_or_create_account(conn, None, "revenue_fees", currency)
                legs.append((fees, p["fee_minor"]))
            entry = L.post_entry(conn, "payout", legs, currency, agent_id=p["agent_id"],
                                 reference=p["reference"], memo="payout settled")
            L.capture_hold(conn, p["hold_id"], entry)
            conn.execute(
                "UPDATE payouts SET status='successful', provider_status='SUCCESSFUL',"
                " updated_at=? WHERE id=?", (L.now_iso(), payout_id))
            L.audit(conn, p["agent_id"], "payout.settled", "ok", {"payout_id": payout_id})
        finally:
            if owns_txn:
                ctx.__exit__(None, None, None)

    def _fail(self, payout_id: str, reason: str, conn=None) -> None:
        owns_txn = conn is None
        if owns_txn:
            ctx = self.db.write(); conn = ctx.__enter__()
        try:
            p = conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
            if p["status"] in ("failed", "successful"):
                return
            L.release_hold(conn, p["hold_id"])
            conn.execute(
                "UPDATE payouts SET status='failed', failure_reason=?, updated_at=? WHERE id=?",
                (reason, L.now_iso(), payout_id))
            L.audit(conn, p["agent_id"], "payout.failed", reason, {"payout_id": payout_id})
        finally:
            if owns_txn:
                ctx.__exit__(None, None, None)

    def get_payout(self, payout_id: str) -> dict:
        p = self.conn.execute("SELECT * FROM payouts WHERE id = ?", (payout_id,)).fetchone()
        if not p:
            raise BankError("unknown payout")
        d = dict(p)
        d["amount"] = to_major(p["amount_minor"], p["currency"])
        return d

    # ---------- webhooks ----------
    def handle_webhook(self, payload: dict) -> dict:
        """Idempotent by provider event identity: replays are no-ops.

        The claim INSERT is inside a write transaction, so two simultaneous
        deliveries of the same event cannot both proceed to settlement.
        """
        import sqlite3 as _sq
        key = dedupe_key(payload)
        event_id = L.new_id("evt")
        try:
            with self.db.write() as conn:
                prior = conn.execute(
                    "SELECT result FROM webhook_events WHERE dedupe_key = ?", (key,)
                ).fetchone()
                if prior:
                    return {"status": "duplicate", "result": prior["result"]}
                conn.execute(
                    "INSERT INTO webhook_events (id, provider, dedupe_key, payload, created_at)"
                    " VALUES (?,?,?,?,?)",
                    (event_id, "flutterwave", key, json.dumps(payload), L.now_iso()))
        except _sq.IntegrityError:
            return {"status": "duplicate", "result": "concurrent"}

        data = payload.get("data") or {}
        reference = data.get("reference")
        provider_status = str(data.get("status", "")).upper()
        result = "ignored"

        if reference:
            with self.db.write() as conn:
                p = conn.execute(
                    "SELECT * FROM payouts WHERE reference = ?", (reference,)).fetchone()
                if p:
                    if provider_status == "SUCCESSFUL":
                        self._settle(p["id"], conn); result = "settled"
                    elif provider_status in ("FAILED", "CANCELLED", "REVERSED"):
                        self._fail(p["id"], data.get("complete_message") or provider_status,
                                   conn)
                        result = "failed"
                    else:
                        conn.execute(
                            "UPDATE payouts SET provider_status=?, updated_at=? WHERE id=?",
                            (provider_status, L.now_iso(), p["id"]))
                        result = "status_updated"

        self.conn.execute(
            "UPDATE webhook_events SET processed_at=?, result=? WHERE id=?",
            (L.now_iso(), result, event_id))
        return {"status": "processed", "result": result}

    def reconcile(self, payout_id: str) -> dict:
        """Ask Flutterwave the truth when a webhook never arrived."""
        p = self.get_payout(payout_id)
        resp = self.flw.verify_by_reference(p["reference"])
        items = (resp or {}).get("data") or []
        if isinstance(items, dict):
            items = [items]
        if not items:
            return {"status": "not_found_at_provider"}
        status = str(items[0].get("status", "")).upper()
        if status == "SUCCESSFUL":
            self._settle(payout_id)
        elif status in ("FAILED", "CANCELLED"):
            self._fail(payout_id, "reconciled as failed")
        return {"status": status, "payout": self.get_payout(payout_id)}
