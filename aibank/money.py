"""Money is integer minor units. Never floats, never binary rounding.

NGN 1,234.56 -> 123456 kobo. All arithmetic is exact integer arithmetic.
"""
from __future__ import annotations

EXPONENT = {"NGN": 2, "USD": 2, "GHS": 2, "KES": 2, "ZAR": 2, "USDC": 6, "USDT": 6}
SUPPORTED = frozenset(EXPONENT)


class MoneyError(ValueError):
    pass


def check_currency(currency: str) -> str:
    c = (currency or "").upper()
    if c not in SUPPORTED:
        raise MoneyError(f"unsupported currency: {currency!r}")
    return c


def to_minor(major, currency: str) -> int:
    """Accept '1234.56' / 1234.56 / 1234 -> minor units, half-up, exact.

    Strings are parsed digit-wise so we never round-trip through binary float.
    """
    c = check_currency(currency)
    exp = EXPONENT[c]
    s = str(major).strip()
    if not s:
        raise MoneyError("empty amount")
    neg = s.startswith("-")
    if neg or s.startswith("+"):
        s = s[1:]
    if "." in s:
        whole, _, frac = s.partition(".")
    else:
        whole, frac = s, ""
    if not (whole + frac).isdigit():
        raise MoneyError(f"not a valid amount: {major!r}")
    whole = whole or "0"
    if len(frac) > exp:
        keep, rest = frac[:exp], frac[exp:]
        value = int(whole + keep) if keep else int(whole)
        if rest and int(rest[0]) >= 5:  # half-up
            value += 1
    else:
        value = int(whole + frac.ljust(exp, "0"))
    return -value if neg else value


def to_major(minor: int, currency: str) -> str:
    """Exact decimal string for display. 123456 NGN -> '1234.56'."""
    c = check_currency(currency)
    exp = EXPONENT[c]
    sign = "-" if minor < 0 else ""
    v = abs(int(minor))
    if exp == 0:
        return f"{sign}{v}"
    whole, frac = divmod(v, 10 ** exp)
    return f"{sign}{whole}.{str(frac).zfill(exp)}"


def fmt(minor: int, currency: str) -> str:
    return f"{to_major(minor, currency)} {check_currency(currency)}"
