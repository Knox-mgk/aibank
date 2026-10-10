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
  * A password alone must not be enough to reach the limits -> once a user
    enrols TOTP, `login` returns a CHALLENGE, never a session.

THE TWO-STEP SIGN-IN, and why it is shaped this way
---------------------------------------------------
`login()` returns one of exactly two things:

    {"session_token": ...}                           -- no second factor
    {"mfa_required": True, "challenge_token": ...}   -- enrolled

The session is minted in exactly ONE place (`_issue_session`), reached either
by a password on a non-enrolled account or by `complete_mfa`. There is no
branch where a correct password plus an enrolled account yields a session, so
the factor cannot be bypassed by a caller that forgets to check a flag --
which is the usual way a bolted-on second factor gets quietly defeated.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from . import ledger as L
from . import totp as T

# scrypt cost. n=2**14, r=8, p=1 costs ~16 MB and tens of ms -- deliberately
# slow. Tests may lower it; production must not.
SCRYPT_N = int(os.environ.get("AIBANK_SCRYPT_N", 1 << 14))
SCRYPT_R = int(os.environ.get("AIBANK_SCRYPT_R", 8))
SCRYPT_P = int(os.environ.get("AIBANK_SCRYPT_P", 1))
SCRYPT_LEN = 32

SESSION_TTL_HOURS = int(os.environ.get("AIBANK_SESSION_TTL_HOURS", 12))
LOCKOUT_WINDOW_MIN = int(os.environ.get("AIBANK_LOCKOUT_WINDOW_MIN", 15))
LOCKOUT_THRESHOLD = int(os.environ.get("AIBANK_LOCKOUT_THRESHOLD", 8))
# Per-SOURCE-ADDRESS threshold, deliberately higher than the per-account one:
# a NAT'd office or a shared mobile gateway puts many legitimate users behind
# one address, so this has to tolerate several people fumbling passwords while
# still cutting off a sprayer. It is a ceiling on attack RATE, not an identity
# check -- an attacker with a botnet gets one bucket per source, which is why
# the per-account threshold stays in place underneath it.
IP_LOCKOUT_THRESHOLD = int(os.environ.get("AIBANK_IP_LOCKOUT_THRESHOLD", 30))
MIN_PASSWORD_LEN = 10

# A second-factor challenge is short-lived on purpose: it is a half-authenticated
# credential, so the window in which a stolen one is useful must be minutes, not
# the session lifetime.
MFA_CHALLENGE_TTL_MINUTES = int(os.environ.get("AIBANK_MFA_CHALLENGE_TTL_MIN", 5))
# Wrong codes tolerated per challenge before it is burned. A 6-digit code with
# +/-1 step of skew leaves 3 valid codes out of a million, so 5 tries is ~1 in
# 67,000 per challenge -- and burning the challenge forces the attacker back
# through the password and the per-IP login throttle for each new attempt.
MFA_MAX_ATTEMPTS = int(os.environ.get("AIBANK_MFA_MAX_ATTEMPTS", 5))

# A fixed salt for the dummy hash burned when an email does not exist.
_DUMMY_SALT = b"aibank-timing-equalizer"


class AuthError(Exception):
    """Authentication or registration failure. Message is safe to return."""


class LockedOut(AuthError):
    pass


class MfaRequired(AuthError):
    """Password was correct but a second factor is enrolled.

    Carries the challenge so the HTTP layer can hand it to the client without
    reaching back into the database. Raised only by paths that must NOT return
    a session; `login` returns the challenge in its payload instead.
    """

    def __init__(self, challenge: dict):
        super().__init__("second factor required")
        self.challenge = challenge


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


def _recent_failures_by_ip(conn, ip: str | None, nowdt: datetime) -> int:
    """Failed attempts from one source address, across ALL accounts.

    WHY this exists alongside the per-email counter: per-account lockout does
    nothing against password SPRAYING -- one common password tried once each
    against a thousand accounts never trips any single account's threshold, and
    every attempt is a free scrypt run on our CPU. The attack is cheap for the
    attacker and expensive for us, which is backwards.
    """
    if not ip or ip == "?":
        return 0
    since = (nowdt - timedelta(minutes=LOCKOUT_WINDOW_MIN)).isoformat()
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM login_attempts"
        " WHERE client_ip=? AND ok=0 AND created_at >= ?", (ip, since)).fetchone()
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
    #
    # The per-IP check runs BEFORE any scrypt call, including the dummy one.
    # That ordering is the point: it makes a flood cost the attacker a SQL
    # COUNT instead of a key derivation, so hammering this endpoint can no
    # longer be used to burn our CPU. Checked before the per-email counter
    # because the spraying attacker never trips that one at all.
    if _recent_failures_by_ip(db.conn, client_ip, nowdt) >= IP_LOCKOUT_THRESHOLD:
        _record_failure(db, email, client_ip)
        raise LockedOut(
            f"too many failed sign-ins from this address; try again in "
            f"{LOCKOUT_WINDOW_MIN} minutes")

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

    # The password is now proven. Record the successful ATTEMPT regardless of
    # what happens next, so the lockout counters reset for a legitimate user
    # who is about to type a TOTP code -- otherwise a slow authenticator could
    # leave stale failures counting against them.
    with db.write() as conn:
        _record_attempt(conn, email, client_ip, True)

    if is_mfa_enrolled(db, row["id"]):
        # THE WHOLE POINT: no session is created here. A correct password on an
        # enrolled account yields only a short-lived challenge, so a phished or
        # reused password cannot reach the policy routes.
        challenge = _create_challenge(db, row["id"], client_ip, user_agent)
        return {"mfa_required": True, **challenge}

    return _issue_session(db, row["id"], row["role"], email, client_ip, user_agent,
                          nowdt, mfa=False)


def _issue_session(db, user_id: str, role: str, email: str, client_ip: str | None,
                   user_agent: str | None, nowdt: datetime, mfa: bool) -> dict:
    """The ONLY place a session token is minted.

    Keeping this single-exit matters more than the few lines it saves: a second
    factor that can be skipped by one forgetful code path is not a second
    factor. Every caller must have already proven whatever the account requires.
    """
    token = "sess_" + secrets.token_urlsafe(32)
    session_id = L.new_id("sess")
    expires = (nowdt + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    with db.write() as conn:
        conn.execute(
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at,"
            " last_seen_at, client_ip, user_agent) VALUES (?,?,?,?,?,?,?,?)",
            (session_id, user_id, hash_token(token), L.now_iso(), expires,
             L.now_iso(), client_ip, (user_agent or "")[:200]))
        conn.execute("UPDATE users SET last_login_at=? WHERE id=?",
                     (L.now_iso(), user_id))
        L.audit(conn, None, "user.login", "ok", {"mfa": mfa}, user_id=user_id,
                ip=client_ip)

    return {"session_token": token, "user_id": user_id, "role": role,
            "expires_at": expires, "mfa": mfa}


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
        "SELECT id, email, role, status, display_name, created_at, last_login_at,"
        " totp_enrolled_at FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        return None
    out = dict(row)
    # The dashboard needs to know whether to offer "enable" or "disable", and a
    # boolean is the honest shape for that; the timestamp stays for the audit view.
    out["mfa_enabled"] = out.get("totp_enrolled_at") is not None
    return out


# ---------------------------------------------------------------------------
# second factor: enrolment
# ---------------------------------------------------------------------------
def _pepper() -> str:
    """The deployment pepper, imported lazily.

    `bank` imports nothing from this module, but importing `bank` at module
    scope here would make `users` -> `bank` -> `db` a load-order constraint for
    every caller, including the CLI's `--help`. The pepper is also read lazily
    there for the same reason: a missing secret must fail when it is USED, not
    when a module is imported.
    """
    from .bank import key_pepper
    return key_pepper()


def is_mfa_enrolled(db, user_id: str) -> bool:
    row = db.conn.execute(
        "SELECT totp_enrolled_at FROM users WHERE id=?", (user_id,)).fetchone()
    return bool(row and row["totp_enrolled_at"])


def begin_totp_enrolment(db, user_id: str, current_password: str) -> dict:
    """Generate a secret and return it with its provisioning URI. NOT yet active.

    Two deliberate properties:

    1. **The current password is required.** Otherwise a stolen session token
       could bind an attacker's own authenticator to the account and lock the
       real owner out permanently -- turning our second factor into the
       attacker's. This is the same reasoning as `change_password`.

    2. **Enrolment is two-phase.** The secret is stored but `totp_enrolled_at`
       stays NULL until the user proves a working code. Enabling on generation
       is how people lock themselves out of their own accounts: a mistyped
       secret, a clock-skewed phone, or a scanner that mangled the QR all
       produce an account whose second factor nobody can satisfy.
    """
    row = db.conn.execute(
        "SELECT password_hash, password_salt, email, totp_enrolled_at"
        " FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        raise AuthError("unknown user")
    if not verify_password(current_password or "", row["password_hash"],
                           row["password_salt"]):
        raise AuthError("current password is incorrect")
    if row["totp_enrolled_at"]:
        raise AuthError("two-factor authentication is already enabled; "
                        "disable it first to re-enrol")

    secret = T.new_secret()
    sealed = T.seal(secret, _pepper())
    with db.write() as conn:
        conn.execute(
            "UPDATE users SET totp_secret_sealed=?, totp_enrolled_at=NULL,"
            " totp_last_counter=NULL WHERE id=?", (sealed, user_id))
        L.audit(conn, None, "user.mfa_enrol_begin", "ok", None, user_id=user_id)
    return {"secret": secret, "issuer": "aibank",
            "account": row["email"],
            "otpauth_uri": T.provisioning_uri(secret, row["email"]),
            "digits": T.DIGITS, "period": T.STEP_SECONDS,
            "enrolled": False}


def confirm_totp_enrolment(db, user_id: str, code: str) -> dict:
    """Activate the factor by proving one working code. Returns recovery codes.

    Recovery codes are shown exactly once, here, and only their hashes are
    kept. Returning them at any later point would mean we could still read
    them, which makes the hash pointless.
    """
    row = db.conn.execute(
        "SELECT totp_secret_sealed, totp_enrolled_at FROM users WHERE id=?",
        (user_id,)).fetchone()
    if row is None:
        raise AuthError("unknown user")
    if row["totp_enrolled_at"]:
        raise AuthError("two-factor authentication is already enabled")
    if not row["totp_secret_sealed"]:
        raise AuthError("no pending enrolment; start one first")

    secret = T.unseal(row["totp_secret_sealed"], _pepper())
    try:
        counter = T.verify(secret, code)
    except T.TotpError as exc:
        raise AuthError(str(exc)) from exc

    codes = [T.new_recovery_code() for _ in range(T.RECOVERY_CODE_COUNT)]
    with db.write() as conn:
        conn.execute("UPDATE users SET totp_enrolled_at=?, totp_last_counter=?"
                     " WHERE id=?", (L.now_iso(), counter, user_id))
        # Any pre-existing recovery codes belong to a previous enrolment and
        # must not survive it, or an old printout still bypasses the new factor.
        conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        for c in codes:
            conn.execute(
                "INSERT INTO recovery_codes (id, user_id, code_hash, created_at)"
                " VALUES (?,?,?,?)",
                (L.new_id("rec"), user_id, _hash_recovery(c), L.now_iso()))
        L.audit(conn, None, "user.mfa_enabled", "ok",
                {"recovery_codes": len(codes)}, user_id=user_id)
    return {"enrolled": True, "recovery_codes": codes}


def disable_totp(db, user_id: str, current_password: str, code: str | None = None) -> None:
    """Turn the factor off. Requires the password AND a current code or recovery code.

    WHY BOTH: if the password alone could disable it, the second factor would
    be worth nothing against exactly the attack it exists to stop -- a thief
    with the password would simply switch it off. Requiring possession of the
    factor to remove the factor is what makes it load-bearing.
    """
    row = db.conn.execute(
        "SELECT password_hash, password_salt, totp_secret_sealed, totp_enrolled_at,"
        " totp_last_counter FROM users WHERE id=?", (user_id,)).fetchone()
    if row is None:
        raise AuthError("unknown user")
    if not verify_password(current_password or "", row["password_hash"],
                           row["password_salt"]):
        raise AuthError("current password is incorrect")
    if not row["totp_enrolled_at"]:
        raise AuthError("two-factor authentication is not enabled")

    secret = T.unseal(row["totp_secret_sealed"], _pepper())
    ok = False
    try:
        T.verify(secret, code or "", last_counter=row["totp_last_counter"])
        ok = True
    except T.CodeReused as exc:
        # Same trap as `complete_mfa`: signing in spends a code, so a user who
        # immediately goes to turn the factor off presents the code they just
        # used. Telling them it is invalid sends them hunting for a problem
        # that does not exist.
        raise AuthError(str(exc)) from exc
    except T.TotpError:
        ok = _consume_recovery_code(db, user_id, code or "", None)
    if not ok:
        raise AuthError("a valid authenticator code or recovery code is required")

    with db.write() as conn:
        conn.execute(
            "UPDATE users SET totp_secret_sealed=NULL, totp_enrolled_at=NULL,"
            " totp_last_counter=NULL WHERE id=?", (user_id,))
        conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        # Disabling the factor is a security-relevant downgrade, so every live
        # session goes with it: if this was done by an attacker, the owner's
        # next page load fails and tells them something happened.
        conn.execute("UPDATE sessions SET revoked_at=? WHERE user_id=?"
                     " AND revoked_at IS NULL", (L.now_iso(), user_id))
        L.audit(conn, None, "user.mfa_disabled", "ok", None, user_id=user_id)


# ---------------------------------------------------------------------------
# second factor: challenge / completion
# ---------------------------------------------------------------------------
def _hash_recovery(code: str) -> str:
    """Peppered hash of a recovery code.

    Peppered rather than bare SHA-256 so a database dump cannot be attacked
    offline with a precomputed table of the (small, known) code alphabet, and
    fast rather than scrypt because 49 bits of random is not guessable anyway.
    """
    return hashlib.sha256(
        (_pepper() + "recovery:" + T.normalize_recovery_code(code)).encode()).hexdigest()


def _create_challenge(db, user_id: str, client_ip: str | None,
                      user_agent: str | None) -> dict:
    token = "mfa_" + secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc)
               + timedelta(minutes=MFA_CHALLENGE_TTL_MINUTES)).isoformat()
    with db.write() as conn:
        # One live challenge per user: leaving old ones valid would let an
        # attacker who captured an earlier challenge keep guessing against it
        # while the real user signs in normally.
        conn.execute("UPDATE mfa_challenges SET consumed_at=? WHERE user_id=?"
                     " AND consumed_at IS NULL", (L.now_iso(), user_id))
        conn.execute(
            "INSERT INTO mfa_challenges (id, user_id, token_hash, created_at,"
            " expires_at, client_ip, user_agent) VALUES (?,?,?,?,?,?,?)",
            (L.new_id("mfac"), user_id, hash_token(token), L.now_iso(), expires,
             client_ip, (user_agent or "")[:200]))
        L.audit(conn, None, "user.mfa_challenge", "ok", None, user_id=user_id,
                ip=client_ip)
    return {"challenge_token": token, "expires_at": expires,
            "max_attempts": MFA_MAX_ATTEMPTS}


def complete_mfa(db, challenge_token: str, code: str, client_ip: str | None = None,
                 user_agent: str | None = None) -> dict:
    """Exchange a challenge plus a TOTP (or recovery) code for a session.

    Failure messages stay vague about WHY beyond what the user must act on: an
    expired challenge needs re-authentication, a wrong code needs retyping, and
    distinguishing "no such challenge" from "wrong code" tells an attacker
    which half they got right.
    """
    row = db.conn.execute(
        "SELECT c.id AS cid, c.user_id, c.expires_at, c.attempts, c.consumed_at,"
        " u.role, u.email, u.status, u.totp_secret_sealed, u.totp_last_counter"
        " FROM mfa_challenges c JOIN users u ON u.id = c.user_id"
        " WHERE c.token_hash=?", (hash_token(challenge_token or ""),)).fetchone()
    if row is None or row["consumed_at"] or row["expires_at"] <= L.now_iso():
        raise AuthError("this sign-in attempt expired; please sign in again")
    if row["status"] != "active":
        raise AuthError(f"account is {row['status']}")

    if row["attempts"] >= MFA_MAX_ATTEMPTS:
        with db.write() as conn:
            conn.execute("UPDATE mfa_challenges SET consumed_at=? WHERE id=?",
                         (L.now_iso(), row["cid"]))
        raise LockedOut("too many incorrect codes; please sign in again")

    # Count the attempt BEFORE checking, in its own committed transaction. The
    # same rollback trap that once disabled login lockout applies here: an
    # increment inside the transaction that raises is an increment that never
    # happened, and the cap becomes decorative.
    with db.write() as conn:
        conn.execute("UPDATE mfa_challenges SET attempts=attempts+1 WHERE id=?",
                     (row["cid"],))

    secret = T.unseal(row["totp_secret_sealed"], _pepper())
    used_recovery = False
    try:
        counter = T.verify(secret, code or "", last_counter=row["totp_last_counter"])
    except T.CodeReused as exc:
        # A correct-but-spent code is NOT a failed guess: the user's
        # authenticator is working and they are about to wait 30 seconds and
        # succeed. Say so, and do not spend the challenge -- burning it here
        # would force a full re-login on someone who did nothing wrong, which
        # is exactly what happens right after enrolment (the confirm step spends
        # the code still on their screen).
        with db.write() as conn:
            L.audit(conn, None, "user.mfa_verify", "denied", {"reason": "reused"},
                    user_id=row["user_id"], ip=client_ip)
        raise AuthError(str(exc)) from exc
    except T.TotpError as exc:
        if _consume_recovery_code(db, row["user_id"], code or "", client_ip):
            used_recovery = True
            counter = None
        else:
            with db.write() as conn:
                L.audit(conn, None, "user.mfa_verify", "denied", {"reason": str(exc)},
                        user_id=row["user_id"], ip=client_ip)
            raise AuthError("invalid code") from exc

    with db.write() as conn:
        conn.execute("UPDATE mfa_challenges SET consumed_at=? WHERE id=?",
                     (L.now_iso(), row["cid"]))
        if counter is not None:
            conn.execute("UPDATE users SET totp_last_counter=? WHERE id=?",
                         (counter, row["user_id"]))

    out = _issue_session(db, row["user_id"], row["role"], row["email"], client_ip,
                         user_agent, datetime.now(timezone.utc), mfa=True)
    out["used_recovery_code"] = used_recovery
    if used_recovery:
        out["recovery_codes_remaining"] = count_recovery_codes(db, row["user_id"])
    return out


def _consume_recovery_code(db, user_id: str, code: str, client_ip: str | None) -> bool:
    """Burn a recovery code if it matches. Returns whether one was consumed.

    The UPDATE is guarded by `used_at IS NULL` and checked via rowcount rather
    than being preceded by a SELECT, so two concurrent requests presenting the
    same code cannot both succeed -- SQLite serialises the write and the loser
    sees rowcount 0.
    """
    normalized = T.normalize_recovery_code(code)
    if len(normalized) != 12:
        return False
    with db.write() as conn:
        cur = conn.execute(
            "UPDATE recovery_codes SET used_at=?, used_ip=?"
            " WHERE user_id=? AND code_hash=? AND used_at IS NULL",
            (L.now_iso(), client_ip, user_id, _hash_recovery(code)))
        if cur.rowcount == 0:
            return False
        L.audit(conn, None, "user.recovery_code_used", "ok", None, user_id=user_id,
                ip=client_ip)
    return True


def count_recovery_codes(db, user_id: str) -> int:
    row = db.conn.execute(
        "SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id=? AND used_at IS NULL",
        (user_id,)).fetchone()
    return int(row["n"])


def regenerate_recovery_codes(db, user_id: str, current_password: str) -> list[str]:
    """Replace every recovery code. Requires the password.

    Needed after one is used or a printout is lost: a user who cannot rotate
    these will instead disable the factor entirely, which is the worse outcome.
    """
    row = db.conn.execute(
        "SELECT password_hash, password_salt, totp_enrolled_at FROM users WHERE id=?",
        (user_id,)).fetchone()
    if row is None:
        raise AuthError("unknown user")
    if not verify_password(current_password or "", row["password_hash"],
                           row["password_salt"]):
        raise AuthError("current password is incorrect")
    if not row["totp_enrolled_at"]:
        raise AuthError("two-factor authentication is not enabled")
    codes = [T.new_recovery_code() for _ in range(T.RECOVERY_CODE_COUNT)]
    with db.write() as conn:
        conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        for c in codes:
            conn.execute(
                "INSERT INTO recovery_codes (id, user_id, code_hash, created_at)"
                " VALUES (?,?,?,?)",
                (L.new_id("rec"), user_id, _hash_recovery(c), L.now_iso()))
        L.audit(conn, None, "user.recovery_codes_regenerated", "ok",
                {"count": len(codes)}, user_id=user_id)
    return codes

