"""Spend policy: the hard ceilings an AI agent cannot argue its way past.

Checked server-side, before money moves, on every payout. A compromised or
hallucinating agent still cannot exceed these limits.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class Decision:
    allowed: bool
    reason: str = "ok"
    requires_approval: bool = False

    def __bool__(self) -> bool:
        return self.allowed


def _window_spent(conn, agent_id: str, since_iso: str) -> int:
    """Money that actually left (or is committed to leave) in the window."""
    row = conn.execute(
        "SELECT COALESCE(SUM(amount_minor + fee_minor), 0) AS s FROM payouts "
        "WHERE agent_id = ? AND created_at >= ? "
        "AND status IN ('submitted','successful','pending_approval')",
        (agent_id, since_iso),
    ).fetchone()
    return int(row["s"])


def day_start(nowdt: datetime) -> str:
    return nowdt.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def month_start(nowdt: datetime) -> str:
    return nowdt.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()


def get_policy(conn, agent_id: str):
    return conn.execute("SELECT * FROM policies WHERE agent_id = ?", (agent_id,)).fetchone()


def evaluate(conn, agent_id: str, amount_minor: int, fee_minor: int,
             currency: str, payee_id: str | None, nowdt: datetime | None = None) -> Decision:
    """Deny-by-default on anything unusual. Order matters: cheapest checks first."""
    nowdt = nowdt or datetime.now(timezone.utc)
    total = amount_minor + fee_minor

    if amount_minor <= 0:
        return Decision(False, "amount must be positive")

    agent = conn.execute("SELECT status FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if agent is None:
        return Decision(False, "unknown agent")
    if agent["status"] != "active":
        return Decision(False, f"agent is {agent['status']}")

    pol = get_policy(conn, agent_id)
    if pol is None:
        # No policy configured == no authority to spend. Fail closed.
        return Decision(False, "no spend policy configured for agent")

    if pol["currency"] != currency:
        return Decision(False, f"policy covers {pol['currency']}, not {currency}")

    if pol["allowlist_only"] and payee_id is None:
        return Decision(False, "policy allows transfers to saved payees only")
    if payee_id is not None:
        owned = conn.execute(
            "SELECT 1 FROM payees WHERE id = ? AND agent_id = ?", (payee_id, agent_id)
        ).fetchone()
        if not owned:
            return Decision(False, "payee does not belong to this agent")

    if pol["per_txn_max_minor"] is not None and total > pol["per_txn_max_minor"]:
        return Decision(False, f"exceeds per-transaction limit ({pol['per_txn_max_minor']})")

    if pol["daily_max_minor"] is not None:
        spent = _window_spent(conn, agent_id, day_start(nowdt))
        if spent + total > pol["daily_max_minor"]:
            return Decision(False,
                f"exceeds daily limit: spent={spent} + {total} > {pol['daily_max_minor']}")

    if pol["monthly_max_minor"] is not None:
        spent = _window_spent(conn, agent_id, month_start(nowdt))
        if spent + total > pol["monthly_max_minor"]:
            return Decision(False,
                f"exceeds monthly limit: spent={spent} + {total} > {pol['monthly_max_minor']}")

    thresh = pol["require_approval_above_minor"]
    if thresh is not None and total > thresh:
        return Decision(True, "requires human approval", requires_approval=True)

    return Decision(True)
