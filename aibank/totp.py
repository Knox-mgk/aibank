"""TOTP second factor (RFC 6238 / RFC 4226), implemented from the spec.

WHY THIS MODULE EXISTS
----------------------
The whole product claim is "a human sets limits the agent cannot reach". That
claim rests on exactly one credential: the human's dashboard session. A
phished or reused password is therefore not an account problem, it is a
*policy* problem -- the attacker signs in and raises every agent's ceiling to
whatever they like, then spends the wallet through a perfectly legitimate agent
key. Circle requires an OTP merely to CHANGE a limit; we required a password.

WHY NOT A LIBRARY
-----------------
`pyotp` would be one line, but this service ships with zero pip dependencies on
purpose (Termux has no wheel for half of PyPI, and the deploy story is "python
and nothing else"). TOTP is HMAC plus a truncation rule; the entire algorithm
is below in ~30 lines and is pinned against the RFC's published test vectors,
which is stronger verification than trusting a dependency's own test suite.

SECRETS AT REST
---------------
A TOTP secret is *symmetric*: whoever can read it can mint valid codes forever.
Storing it in plaintext would mean a stolen database hands the attacker the
second factor -- and since passwords are scrypt-hashed, the TOTP secret would
become the EASIEST thing to steal from a dump, which is backwards.

So secrets are sealed with `AIBANK_KEY_PEPPER`, which lives in the environment
and never in the database (the same reasoning that already protects API key
hashes). Sealing is HMAC-SHA256 in counter mode for confidentiality plus a
separate HMAC tag for integrity -- encrypt-then-MAC, with the two keys derived
from different domain-separated labels so neither can be used to attack the
other. No AES: the stdlib has no AES, and a keystream from a PRF is a
construction we can state and verify rather than a cipher we would have to
hand-roll.

Consequence to state plainly: a database dump alone yields nothing, but a dump
*plus* the environment yields the secrets. That is the same trust boundary the
API key pepper already defines, and it is the best available without a KMS.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

# RFC 6238 defaults. 30-second steps, 6 digits, SHA-1 -- SHA-1 not because it
# is a good hash in 2026 but because it is what every authenticator app
# implements, and HMAC-SHA1's security does not rest on collision resistance.
STEP_SECONDS = 30
DIGITS = 6

# How many steps either side of "now" are accepted. One step = 30s of tolerance
# in each direction, which covers ordinary phone clock drift. Widening this
# multiplies the number of simultaneously-valid codes an online guesser can
# hit, so it stays at 1.
SKEW_STEPS = 1

_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class TotpError(Exception):
    """Malformed secret, code, or sealed blob."""


class CodeReused(TotpError):
    """The code was arithmetically CORRECT but has already been spent.

    Distinct from a wrong code because the two need opposite advice. A wrong
    code means "check you typed it right"; a reused one means "your
    authenticator is fine, wait for the next code" -- and the user hits this
    legitimately, not just under attack: confirming enrolment spends the code
    on screen, so signing in during that same 30-second window presents an
    already-used code through no fault of theirs.

    Collapsing both into "invalid code" tells a user whose setup is working
    that it is broken, which is how people conclude 2FA is unreliable and turn
    it off.
    """


# ---------------------------------------------------------------------------
# base32, without the padding mistakes
# ---------------------------------------------------------------------------
def b32encode(data: bytes) -> str:
    """Unpadded uppercase base32, which is what authenticator apps expect.

    `base64.b32encode` appends `=` padding; several apps (and most QR
    scanners) reject or mangle it inside an `otpauth://` URI, so the padding
    is dropped here rather than at every call site.
    """
    bits = 0
    acc = 0
    out: list[str] = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_B32_ALPHABET[(acc >> bits) & 31])
    if bits:
        out.append(_B32_ALPHABET[(acc << (5 - bits)) & 31])
    return "".join(out)


def b32decode(text: str) -> bytes:
    """Decode base32 tolerantly: ignore spaces, case, and padding.

    Users retype secrets by hand off a screen, in groups of four with spaces,
    and sometimes in lowercase. Rejecting that is a support ticket, not
    security.
    """
    acc = 0
    bits = 0
    out = bytearray()
    for ch in (text or "").strip().replace(" ", "").replace("-", "").upper():
        if ch == "=":
            continue
        idx = _B32_ALPHABET.find(ch)
        if idx < 0:
            raise TotpError("secret is not valid base32")
        acc = (acc << 5) | idx
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if not out:
        raise TotpError("secret is empty")
    return bytes(out)


# ---------------------------------------------------------------------------
# the algorithm itself
# ---------------------------------------------------------------------------
def new_secret(num_bytes: int = 20) -> str:
    """A fresh base32 secret. 20 bytes = 160 bits, the RFC 4226 recommendation."""
    return b32encode(secrets.token_bytes(num_bytes))


def hotp(secret_b32: str, counter: int, digits: int = DIGITS,
         algorithm: str = "sha1") -> str:
    """RFC 4226 HOTP: HMAC, dynamic truncation, modulo 10**digits."""
    key = b32decode(secret_b32)
    mac = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algorithm)).digest()
    # Dynamic truncation: the low nibble of the last byte picks the offset of
    # the 4 bytes to read, and the top bit is masked off so the result is a
    # positive 31-bit integer regardless of platform signedness.
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFF_FFFF
    return str(code % (10 ** digits)).zfill(digits)


def counter_for(timestamp: float | None = None, step: int = STEP_SECONDS) -> int:
    return int((time.time() if timestamp is None else timestamp) // step)


def totp(secret_b32: str, timestamp: float | None = None, digits: int = DIGITS,
         step: int = STEP_SECONDS, algorithm: str = "sha1") -> str:
    return hotp(secret_b32, counter_for(timestamp, step), digits, algorithm)


def verify(secret_b32: str, code: str, timestamp: float | None = None,
           skew: int = SKEW_STEPS, last_counter: int | None = None,
           digits: int = DIGITS, step: int = STEP_SECONDS) -> int:
    """Return the matched counter, or raise TotpError.

    `last_counter` is REPLAY PROTECTION and is not optional in practice. A
    6-digit code stays valid for 30-90 seconds, which is ample time for anyone
    who can read it -- shoulder-surfing, a phished page relaying it, a proxy on
    an http deployment -- to reuse it. Refusing any counter at or below the
    last accepted one makes each code strictly single-use, which is what turns
    "something you have" into something an observer cannot replay.

    Returning the counter rather than True is deliberate: the caller MUST
    persist it, and a bool makes forgetting silent.
    """
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != digits:
        raise TotpError(f"code must be {digits} digits")
    now = counter_for(timestamp, step)
    # Oldest first, so a code valid at two counters (impossible with distinct
    # HMACs, but cheap to be deterministic about) resolves predictably.
    for counter in range(now - skew, now + skew + 1):
        if hmac.compare_digest(hotp(secret_b32, counter, digits), code):
            if last_counter is not None and counter <= last_counter:
                raise CodeReused("that code has already been used; wait for your "
                                 "authenticator to show the next one")
            return counter
    raise TotpError("invalid code")


def provisioning_uri(secret_b32: str, account: str, issuer: str = "aibank") -> str:
    """`otpauth://` URI for an authenticator app (QR or manual entry).

    Both issuer label and the `issuer=` parameter are set: apps disagree about
    which they read, and omitting either shows the user an unlabelled entry
    called "aibank" with no hint of which account it belongs to.
    """
    label = quote(f"{issuer}:{account}", safe="")
    return (f"otpauth://totp/{label}?secret={secret_b32}"
            f"&issuer={quote(issuer, safe='')}&algorithm=SHA1"
            f"&digits={DIGITS}&period={STEP_SECONDS}")


# ---------------------------------------------------------------------------
# sealing secrets at rest (encrypt-then-MAC with the deployment pepper)
# ---------------------------------------------------------------------------
_SEAL_VERSION = "v1"


def _derive(pepper: str, nonce: bytes, label: bytes) -> bytes:
    return hmac.new(pepper.encode(), label + nonce, hashlib.sha256).digest()


def _keystream(key: bytes, nbytes: int) -> bytes:
    out = bytearray()
    block = 0
    while len(out) < nbytes:
        out += hmac.new(key, struct.pack(">I", block), hashlib.sha256).digest()
        block += 1
    return bytes(out[:nbytes])


def seal(plaintext: str, pepper: str) -> str:
    """`v1.<nonce>.<ciphertext>.<tag>`, all hex.

    Encrypt-then-MAC: the tag covers the version, nonce and ciphertext, so a
    database with write access cannot swap in a secret of its choosing without
    the pepper. Keys for the two operations come from different labels, so the
    MAC key is never the keystream key.
    """
    if not pepper:
        raise TotpError("cannot seal without a pepper")
    nonce = secrets.token_bytes(16)
    data = plaintext.encode()
    ct = bytes(a ^ b for a, b in zip(data, _keystream(_derive(pepper, nonce, b"enc"),
                                                      len(data))))
    body = f"{_SEAL_VERSION}.{nonce.hex()}.{ct.hex()}"
    tag = hmac.new(_derive(pepper, nonce, b"mac"), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{tag}"


def unseal(blob: str, pepper: str) -> str:
    """Reverse `seal`, verifying the tag BEFORE decrypting.

    A failure here is not a user error: it means the pepper changed or the row
    was tampered with. Both deserve a loud failure rather than a silently wrong
    secret that would reject every correct code the user types.
    """
    if not pepper:
        raise TotpError("cannot unseal without a pepper")
    parts = (blob or "").split(".")
    if len(parts) != 4 or parts[0] != _SEAL_VERSION:
        raise TotpError("sealed secret is malformed")
    _, nonce_hex, ct_hex, tag = parts
    try:
        nonce = bytes.fromhex(nonce_hex)
        ct = bytes.fromhex(ct_hex)
    except ValueError as exc:
        raise TotpError("sealed secret is not hex") from exc
    body = f"{_SEAL_VERSION}.{nonce_hex}.{ct_hex}"
    expect = hmac.new(_derive(pepper, nonce, b"mac"), body.encode(),
                      hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, tag):
        raise TotpError(
            "sealed TOTP secret failed its integrity check -- the key pepper "
            "has changed, or the row was modified outside the application")
    key = _derive(pepper, nonce, b"enc")
    return bytes(a ^ b for a, b in zip(ct, _keystream(key, len(ct)))).decode()


# ---------------------------------------------------------------------------
# recovery codes
# ---------------------------------------------------------------------------
# Why these exist: a lost phone must not mean a permanently unreachable wallet
# with live agents still spending under limits nobody can now change. Without
# recovery, our own second factor becomes a denial-of-service on the account
# holder, and the realistic workaround users invent -- a screenshot of the QR
# in their photo roll -- is worse than the problem.
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no l/i/o/0/1


def new_recovery_code() -> str:
    """~49 bits over three readable groups, e.g. `k3mq-7xzp-2rtv`.

    High-entropy by construction, so these are stored under a fast peppered
    hash rather than scrypt -- the same reasoning as session tokens. There is
    no human-guessable distribution to attack.
    """
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(12))
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


def normalize_recovery_code(code: str) -> str:
    return (code or "").strip().lower().replace(" ", "").replace("-", "")
