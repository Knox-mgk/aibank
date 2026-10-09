"""Spend policy: the hard ceilings an AI agent cannot argue its way past.

Checked server-side, before money moves, on every payout. A compromised or
hallucinating agent still cannot exceed these limits.

THE CENTRAL INVARIANT of the dashboard model: a human sets these limits and the
agent merely operates under them. Nothing in this module is reachable with an
agent API key -- `set_policy` lives behind a user session, and policy is read
here but never written. If an agent could edit its own policy, every limit
below would be decoration.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


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


def _window_count(conn, agent_id: str, since_iso: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM payouts "
        "WHERE agent_id = ? AND created_at >= ? "
        "AND status IN ('submitted','successful','pending_approval')",
        (agent_id, since_iso),
    ).fetchone()
    return int(row["n"])


def _tz(pol) -> timezone:
    """The policy's timezone as a fixed offset.

    WHY NOT zoneinfo: the stored `tz_offset_minutes` is used as the source of
    truth because this service must run on hosts with no tzdata installed
    (Android/Termux has none -- ZoneInfo('Africa/Lagos') raises there). Falling
    back to UTC on such a host would move a Lagos customer's "daily" reset to
    01:00 local without any error, quietly handing the agent a second daily
    allowance in the hour after midnight. A fixed offset is always available
    and is exactly right for zones without DST, which includes all of WAT.
    """
    try:
        minutes = int(pol["tz_offset_minutes"])
    except (KeyError, IndexError, TypeError, ValueError):
        minutes = 0
    return timezone(timedelta(minutes=minutes))


def day_start(nowdt: datetime, tz: timezone | None = None) -> str:
    """Start of the local day, expressed as a UTC ISO timestamp for comparison.

    Rows are stored as UTC ISO strings, so the boundary must be converted back
    to UTC after being computed in local time -- otherwise the string compare
    silently compares a +01:00 timestamp against +00:00 ones.
    """
    tz = tz or timezone.utc
    local = nowdt.astimezone(tz)
    boundary = local.replace(hour=0, minute=0, second=0, microsecond=0)
    return boundary.astimezone(timezone.utc).isoformat()


def month_start(nowdt: datetime, tz: timezone | None = None) -> str:
    tz = tz or timezone.utc
    local = nowdt.astimezone(tz)
    boundary = local.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return boundary.astimezone(timezone.utc).isoformat()


def get_policy(conn, agent_id: str):
    return conn.execute("SELECT * FROM policies WHERE agent_id = ?", (agent_id,)).fetchone()


def evaluate(conn, agent_id: str, amount_minor: int, fee_minor: int,
             currency: str, payee_id: str | None, nowdt: datetime | None = None) -> Decision:
    """Deny-by-default on anything unusual. Order matters: cheapest checks first."""
    nowdt = nowdt or datetime.now(timezone.utc)
    total = amount_minor + fee_minor

    if amount_minor <= 0:
        return Decision(False, "amount must be positive")

    agent = conn.execute(
        "SELECT status, user_id FROM agents WHERE id = ?", (agent_id,)).fetchone()
    if agent is None:
        return Decision(False, "unknown agent")
    if agent["status"] != "active":
        return Decision(False, f"agent is {agent['status']}")

    # An agent whose owning human is suspended must stop spending immediately.
    # Without this, freezing a fraudulent account would leave its agents happily
    # draining the wallet under limits nobody can now change.
    if agent["user_id"]:
        owner = conn.execute(
            "SELECT status FROM users WHERE id = ?", (agent["user_id"],)).fetchone()
        if owner is None:
            return Decision(False, "agent's owner no longer exists")
        if owner["status"] != "active":
            return Decision(False, f"account holder is {owner['status']}")

    pol = get_policy(conn, agent_id)
    if pol is None:
        # No policy configured == no authority to spend. Fail closed.
        return Decision(False, "no spend policy configured for agent")

    # A policy ROW with no bound of any kind is the same thing as no policy,
    # and it is the state `create_agent` produces when called without limits --
    # so the check above was dead code and an agent could be born able to drain
    # its whole wallet in one unapproved payout. The product's entire claim is
    # a ceiling the agent cannot raise; no ceiling must therefore deny.
    #
    # `require_approval_above` counts as a bound: with it set, no payout above
    # it proceeds without a human, so autonomous spend is capped even with
    # every amount limit blank. Any ONE of these is enough, so partially
    # configured policies stay legal.
    #
    # NOT closed here: a threshold alone still permits unlimited payouts just
    # under it. `max_payouts_per_day` is the control for that drip, and it is
    # independent of this check.
    if (pol["per_txn_max_minor"] is None
            and pol["daily_max_minor"] is None
            and pol["monthly_max_minor"] is None
            and pol["require_approval_above_minor"] is None):
        return Decision(False, "no spend limit configured for agent")

    if pol["currency"] != currency:
        return Decision(False, f"policy covers {pol['currency']}, not {currency}")

    if pol["allowlist_only"] and payee_id is None:
        return Decision(False, "policy allows transfers to saved payees only")
    if payee_id is not None:
        payee = conn.execute(
            "SELECT currency FROM payees WHERE id = ? AND agent_id = ?",
            (payee_id, agent_id)).fetchone()
        if not payee:
            return Decision(False, "payee does not belong to this agent")
        # A USD payout to an NGN bank account is not a currency conversion, it
        # is a 1:1 transfer of the wrong number -- roughly a 1,500x error.
        if payee["currency"] != currency:
            return Decision(
                False, f"payee is a {payee['currency']} account, not {currency}")

    tz = _tz(pol)

    if pol["per_txn_max_minor"] is not None and total > pol["per_txn_max_minor"]:
        return Decision(False, f"exceeds per-transaction limit ({pol['per_txn_max_minor']})")

    if pol["daily_max_minor"] is not None:
        spent = _window_spent(conn, agent_id, day_start(nowdt, tz))
        if spent + total > pol["daily_max_minor"]:
            return Decision(False,
                f"exceeds daily limit: spent={spent} + {total} > {pol['daily_max_minor']}")

    if pol["monthly_max_minor"] is not None:
        spent = _window_spent(conn, agent_id, month_start(nowdt, tz))
        if spent + total > pol["monthly_max_minor"]:
            return Decision(False,
                f"exceeds monthly limit: spent={spent} + {total} > {pol['monthly_max_minor']}")

    # A velocity ceiling catches the failure an amount cap cannot: an agent in a
    # retry loop making a thousand small, individually-legal payments.
    if pol["max_payouts_per_day"] is not None:
        n = _window_count(conn, agent_id, day_start(nowdt, tz))
        if n + 1 > pol["max_payouts_per_day"]:
            return Decision(False,
                f"exceeds daily payout count limit ({pol['max_payouts_per_day']})")

    thresh = pol["require_approval_above_minor"]
    if thresh is not None and total > thresh:
        return Decision(True, "requires human approval", requires_approval=True)

    return Decision(True)
