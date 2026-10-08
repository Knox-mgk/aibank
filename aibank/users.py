"""Human account holders: registration, sign-in, sessions, lockout.

Why this module exists at all: the limits an autonomous agent spends under are
only meaningful if a *human* sets them and the agent cannot reach them. That
requires a real account holder with real credentials, which is a different
trust domain from an API key handed to a bot.

Threat model, stated plainly:
  * A stolen database must not yield usable passwords -> scrypt, per-user salt.
  * A stolen database must not yield live dashboard sessions -> session tokens
    are stored hashed, exactly like API keys.
  * Password guessing must be throttled durably, not in process memory, or a
    restart resets the attacker's budget -> attempts are a table.
  * Timing must not reveal whether an email exists -> unknown users still pay
    for a dummy KDF run.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from . import ledger as L

# scrypt cost. n=2**14, r=8, p=1 costs ~16 MB and tens of ms -- deliberately
# slow. Tests may lower it; production must not.
SCRYPT_N = int(os.environ.get("AIBANK_SCRYPT_N", 1 << 14))
SCRYPT_R = int(os.environ.get("AIBANK_SCRYPT_R", 8))
SCRYPT_P = int(os.environ.get("AIBANK_SCRYPT_P", 1))
SCRYPT_LEN = 32

SESSION_TTL_HOURS = int(os.environ.get("AIBANK_SESSION_TTL_HOURS", 12))
LOCKOUT_WINDOW_MIN = int(os.environ.get("AIBANK_LOCKOUT_WINDOW_MIN", 15))
LOCKOUT_THRESHOLD = int(os.environ.get("AIBANK_LOCKOUT_THRESHOLD", 8))
MIN_PASSWORD_LEN = 10

# A fixed salt for the dummy hash burned when an email does not exist.
_DUMMY_SALT = b"aibank-timing-equalizer"


class AuthError(Exception):
    """Authentication or registration failure. Message is safe to return."""


class LockedOut(AuthError):
    pass


def _scrypt(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                          p=SCRYPT_P, dklen=SCRYPT_LEN).hex()


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    return _scrypt(password, salt), salt.hex()


def verify_password(password: str, password_hash: str, salt_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    return hmac.compare_digest(_scrypt(password, salt), password_hash)


def hash_token(token: str) -> str:
    """Session tokens are high-entropy already, so a plain SHA-256 is enough.

    Unlike a password, there is nothing to brute-force: 256 bits of
    `secrets.token_urlsafe` has no guessable distribution to attack.
    """
    return hashlib.sha256((token or "").encode()).hexdigest()


def normalize_email(email: str) -> str:
    e = (email or "").strip().lower()
    if "@" not in e or e.startswith("@") or e.endswith("@") or " " in e:
        raise AuthError("invalid email address")
    return e


def check_password_strength(password: str) -> None:
    if len(password or "") < MIN_PASSWORD_LEN:
        raise AuthError(f"password must be at least {MIN_PASSWORD_LEN} characters")


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------
def create_user(db, email: str, password: str, display_name: str | None = None,
                role: str = "user") -> dict:
    email = normalize_email(email)
    check_password_strength(password)
    if role not in ("user", "admin"):
        raise AuthError("role must be 'user' or 'admin'")
    pw_hash, salt = hash_password(password)
    user_id = L.new_id("user")
    try:
        with db.write() as conn:
            conn.execute(
                "INSERT INTO users (id, email, password_hash, password_salt, kdf,"
                " role, status, display_name, created_at)"
                " VALUES (?,?,?,?,'scrypt',?, 'active', ?, ?)",
                (user_id, email, pw_hash, salt, role, display_name or email.split("@")[0],
                 L.now_iso()))
            L.audit(conn, None, "user.create", "ok", {"email": email, "role": role},
                    user_id=user_id)
    except sqlite3.IntegrityError as exc:
        raise AuthError("an account with that email already exists") from exc
    return {"user_id": user_id, "email": email, "role": role}


def set_password(db, user_id: str, new_password: str) -> None:
    check_password_strength(new_password)
    pw_hash, salt = hash_password(new_password)
    with db.write() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash=?, password_salt=? WHERE id=?",
            (pw_hash, salt, user_id))
        if cur.rowcount == 0:
            raise AuthError("unknown user")
        # Changing a password invalidates every existing session: that is the
        # only way "sign out everywhere" can be trusted after a compromise.
        conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                     (L.now_iso(), user_id))
        L.audit(conn, None, "user.password_change", "ok", None, user_id=user_id)


def change_password(db, user_id: str, current_password: str, new_password: str) -> None:
    """Rotate a password, proving knowledge of the old one first.

    Requiring the current password is what stops a stolen session token from
    being upgraded into permanent account ownership: the thief holds a token
    that expires, not a credential they can change.
    """
    row = db.conn.execute(
        "SELECT password_hash, password_salt FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        raise AuthError("unknown user")
    if not verify_password(current_password or "", row["password_hash"],
                           row["password_salt"]):
        raise AuthError("current password is incorrect")
    if (new_password or "") == (current_password or ""):
        raise AuthError("new password must differ from the current one")
    set_password(db, user_id, new_password)


# ---------------------------------------------------------------------------
# lockout
# ---------------------------------------------------------------------------
def _recent_failures(conn, email: str, nowdt: datetime) -> int:
    since = (nowdt - timedelta(minutes=LOCKOUT_WINDOW_MIN)).isoformat()
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM login_attempts"
        " WHERE email=? AND ok=0 AND created_at >= ?", (email, since)).fetchone()
    return int(row["n"])


def _record_attempt(conn, email: str, ip: str | None, ok: bool) -> None:
    conn.execute(
        "INSERT INTO login_attempts (email, client_ip, ok, created_at) VALUES (?,?,?,?)",
        (email, ip, 1 if ok else 0, L.now_iso()))


def _record_failure(db, email: str, ip: str | None, audit_detail: dict | None = None,
                    user_id: str | None = None) -> None:
    """Commit a failed attempt in its OWN transaction.

    WHY this is separate: recording the failure inside the same transaction
    that then raises AuthError means the rollback erases the record. Lockout
    counted rows that were never committed, so the durable brute-force
    throttle silently did nothing -- an attacker got unlimited guesses. The
    write must outlive the rejection.
    """
    with db.write() as conn:
        _record_attempt(conn, email, ip, False)
        if audit_detail is not None:
            L.audit(conn, None, "user.login", "denied", audit_detail,
                    user_id=user_id, ip=ip)


# ---------------------------------------------------------------------------
# sign-in / sessions
# ---------------------------------------------------------------------------
def login(db, email: str, password: str, client_ip: str | None = None,
          user_agent: str | None = None) -> dict:
    """Return a session token, or raise AuthError with a deliberately vague message.

    Structure note: every failure path records its attempt OUTSIDE the main
    write transaction (see `_record_failure`), because raising from inside it
    would roll the record back and disable lockout entirely.
    """
    try:
        email = normalize_email(email)
    except AuthError:
        _scrypt(password or "", _DUMMY_SALT)  # equalise timing
        raise AuthError("invalid email or password")

    nowdt = datetime.now(timezone.utc)

    # Read the throttle state and the user first; no writes yet.
    if _recent_failures(db.conn, email, nowdt) >= LOCKOUT_THRESHOLD:
        _record_failure(db, email, client_ip)
        raise LockedOut(
            f"too many failed sign-ins; try again in {LOCKOUT_WINDOW_MIN} minutes")

    row = db.conn.execute(
        "SELECT id, password_hash, password_salt, status, role FROM users WHERE email=?",
        (email,)).fetchone()

    if row is None:
        # Burn the same work an existing user would, so response time does
        # not disclose which emails are registered.
        _scrypt(password or "", _DUMMY_SALT)
        _record_failure(db, email, client_ip)
        raise AuthError("invalid email or password")

    if not verify_password(password or "", row["password_hash"], row["password_salt"]):
        _record_failure(db, email, client_ip, {"reason": "bad password"},
                        user_id=row["id"])
        raise AuthError("invalid email or password")

    if row["status"] != "active":
        _record_failure(db, email, client_ip, {"reason": f"account {row['status']}"},
                        user_id=row["id"])
        raise AuthError(f"account is {row['status']}")

    token = "sess_" + secrets.token_urlsafe(32)
    session_id = L.new_id("sess")
    expires = (nowdt + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    with db.write() as conn:
        conn.execute(
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at,"
            " last_seen_at, client_ip, user_agent) VALUES (?,?,?,?,?,?,?,?)",
            (session_id, row["id"], hash_token(token), L.now_iso(), expires,
             L.now_iso(), client_ip, (user_agent or "")[:200]))
        conn.execute("UPDATE users SET last_login_at=? WHERE id=?",
                     (L.now_iso(), row["id"]))
        _record_attempt(conn, email, client_ip, True)
        L.audit(conn, None, "user.login", "ok", None, user_id=row["id"], ip=client_ip)

    return {"session_token": token, "user_id": row["id"], "role": row["role"],
            "expires_at": expires}


def authenticate_session(db, token: str) -> dict | None:
    """Resolve a session token to its user, or None. Refreshes last_seen_at."""
    if not token:
        return None
    row = db.conn.execute(
        "SELECT s.id AS sid, s.expires_at, u.id AS user_id, u.role, u.status, u.email"
        " FROM sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash = ? AND s.revoked_at IS NULL",
        (hash_token(token),)).fetchone()
    if row is None:
        return None
    if row["expires_at"] <= L.now_iso():
        return None
    if row["status"] != "active":
        return None
    db.conn.execute("UPDATE sessions SET last_seen_at=? WHERE id=?",
                    (L.now_iso(), row["sid"]))
    return {"user_id": row["user_id"], "role": row["role"], "email": row["email"],
            "session_id": row["sid"]}


def logout(db, token: str) -> bool:
    cur = db.conn.execute(
        "UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
        (L.now_iso(), hash_token(token)))
    return cur.rowcount > 0


def logout_all(db, user_id: str) -> int:
    cur = db.conn.execute(
        "UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
        (L.now_iso(), user_id))
    return cur.rowcount


def get_user(db, user_id: str) -> dict | None:
    row = db.conn.execute(
        "SELECT id, email, role, status, display_name, created_at, last_login_at"
        " FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(row) if row else None
