"""Server-side pricing.

WHY this module exists: the fee used to be whatever the caller put in the
request body. The caller is the agent spending the money, which meant the
spender set the platform's own revenue -- and could set it to zero. Pricing is
now read from the `fee_schedule` table and the request's `fee` field is ignored
entirely.

The schedule is per-currency: a flat component, a basis-point component, a
floor, and an optional cap. All integer minor units, all exact.
"""
from __future__ import annotations

from . import ledger as L
from .money import check_currency

# Applied when a currency has no row. Zero is the safe default: charging a fee
# nobody configured is worse than charging none.
DEFAULT = {"flat_minor": 0, "bps": 0, "min_minor": 0, "cap_minor": None}


def get_schedule(conn, currency: str) -> dict:
    currency = check_currency(currency)
    row = conn.execute(
        "SELECT flat_minor, bps, min_minor, cap_minor FROM fee_schedule WHERE currency = ?",
        (currency,)).fetchone()
    return dict(row) if row else dict(DEFAULT)


def set_schedule(conn, currency: str, flat_minor: int = 0, bps: int = 0,
                 min_minor: int = 0, cap_minor: int | None = None,
                 user_id: str | None = None) -> None:
    currency = check_currency(currency)
    for name, v in (("flat_minor", flat_minor), ("bps", bps), ("min_minor", min_minor)):
        if int(v) < 0:
            raise ValueError(f"{name} must not be negative")
    if cap_minor is not None and int(cap_minor) < int(min_minor):
        raise ValueError("cap_minor must not be below min_minor")
    conn.execute(
        "INSERT INTO fee_schedule (currency, flat_minor, bps, min_minor, cap_minor,"
        " updated_at) VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(currency) DO UPDATE SET flat_minor=excluded.flat_minor,"
        " bps=excluded.bps, min_minor=excluded.min_minor,"
        " cap_minor=excluded.cap_minor, updated_at=excluded.updated_at",
        (currency, int(flat_minor), int(bps), int(min_minor),
         None if cap_minor is None else int(cap_minor), L.now_iso()))
    L.audit(conn, None, "fee_schedule.set", "ok",
            {"currency": currency, "flat_minor": flat_minor, "bps": bps,
             "min_minor": min_minor, "cap_minor": cap_minor}, user_id=user_id)


def quote(conn, amount_minor: int, currency: str) -> int:
    """The fee WE charge for moving `amount_minor`. Never caller-supplied.

    Integer-only: the bps component truncates with floor division rather than
    rounding through a float, so the same inputs always produce the same fee
    and the total can never gain a half-kobo that does not exist.
    """
    s = get_schedule(conn, currency)
    if amount_minor <= 0:
        return 0
    fee = int(s["flat_minor"]) + (int(amount_minor) * int(s["bps"])) // 10_000
    fee = max(fee, int(s["min_minor"]))
    if s["cap_minor"] is not None:
        fee = min(fee, int(s["cap_minor"]))
    return fee
