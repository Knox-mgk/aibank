"""Tests for the second factor on the human session.

The session that sets agent limits is the single credential the whole product
rests on, so these tests are written as ATTACKS rather than demonstrations.
Each one pins a property that, if it broke, would make the factor decorative:

  * a correct password alone must never yield a session (bypass)
  * a code must not be reusable (replay)
  * guesses against one challenge must be finite (online brute force)
  * a stolen database must not yield the secret (offline)
  * the password alone must not remove the factor (downgrade)
  * a lost phone must still be recoverable (self-inflicted denial of service)

Run: python -m unittest discover -s tests
"""
from __future__ import annotations

import os
import sqlite3
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("AIBANK_SCRYPT_N", "1024")
os.environ.setdefault("AIBANK_ALLOW_DEV_SECRETS", "1")

from aibank import totp as T
from aibank import users as U
from aibank.bank import Bank
from aibank.flutterwave import FlutterwaveClient
from tests.fake_flw import FakeFLW

PASSWORD = "correct-horse-battery"


class Base(unittest.TestCase):
    def setUp(self):
        self.bank = Bank(":memory:", flw=FlutterwaveClient(
            secret_key="FLWSECK_TEST-x", opener=FakeFLW()))
        self.user = U.create_user(self.bank, "kay@example.com", PASSWORD)
        self.uid = self.user["user_id"]

    def tearDown(self):
        try:
            self.bank.close()
        except Exception:
            pass

    def enrol(self) -> tuple[str, list[str]]:
        """Complete a full enrolment. Returns (secret, recovery_codes)."""
        start = U.begin_totp_enrolment(self.bank, self.uid, PASSWORD)
        secret = start["secret"]
        out = U.confirm_totp_enrolment(self.bank, self.uid, T.totp(secret))
        return secret, out["recovery_codes"]

    @staticmethod
    def fresh_code(secret: str) -> str:
        """A code the account has not spent yet.

        Confirming enrolment SPENDS the code that was on screen, so the very
        next sign-in inside that same 30-second step presents an already-used
        code. One step ahead is still inside the accepted skew window, which is
        what a real user's next refresh gives them.
        """
        return T.totp(secret, timestamp=time.time() + T.STEP_SECONDS)


class TestAlgorithm(Base):
    """The primitive, against the RFCs' own published vectors.

    These are the only numbers in this file that are not ours: if a refactor
    breaks the truncation rule or the counter arithmetic, every authenticator
    app in the world disagrees with us and only a vector catches it.
    """

    RFC6238 = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
               (1234567890, "89005924"), (2000000000, "69279037"),
               (20000000000, "65353130")]
    RFC4226 = ["755224", "287082", "359152", "969429", "338314",
               "254676", "287922", "162583", "399871", "520489"]

    def test_rfc6238_sha1_vectors(self):
        secret = T.b32encode(b"12345678901234567890")
        for ts, expect in self.RFC6238:
            self.assertEqual(T.totp(secret, timestamp=ts, digits=8), expect,
                             f"RFC 6238 vector failed at t={ts}")

    def test_rfc4226_hotp_vectors(self):
        secret = T.b32encode(b"12345678901234567890")
        for counter, expect in enumerate(self.RFC4226):
            self.assertEqual(T.hotp(secret, counter), expect)

    def test_base32_matches_stdlib_and_is_tolerant(self):
        import base64
        for n in (1, 2, 3, 4, 5, 10, 16, 20, 32):
            raw = os.urandom(n)
            enc = T.b32encode(raw)
            self.assertEqual(enc, base64.b32encode(raw).decode().rstrip("="))
            self.assertEqual(T.b32decode(enc), raw)
            # Users retype secrets in lowercase, in groups of four, with spaces.
            self.assertEqual(T.b32decode(enc.lower()), raw)
            spaced = " ".join(enc[i:i + 4] for i in range(0, len(enc), 4))
            self.assertEqual(T.b32decode(spaced), raw)

    def test_clock_skew_window_is_bounded(self):
        secret = T.new_secret()
        now = 1_700_000_000
        # one step either side is accepted...
        for offset in (-T.STEP_SECONDS, 0, T.STEP_SECONDS):
            code = T.totp(secret, timestamp=now + offset)
            self.assertIsInstance(T.verify(secret, code, timestamp=now), int)
        # ...two steps is not. A wider window multiplies the codes a guesser
        # can hit simultaneously.
        far = T.totp(secret, timestamp=now + 3 * T.STEP_SECONDS)
        with self.assertRaises(T.TotpError):
            T.verify(secret, far, timestamp=now)

    def test_malformed_codes_rejected_before_any_hmac(self):
        secret = T.new_secret()
        for bad in ("", "abc", "12345", "1234567", "12 34 56", None):
            with self.assertRaises(T.TotpError):
                T.verify(secret, bad)


class TestSealing(Base):
    def test_secret_is_never_stored_in_plaintext(self):
        """The attack: read the database file, mint codes forever.

        A TOTP secret is symmetric, so plaintext storage would make it the
        EASIEST credential to steal from a dump -- easier than the
        scrypt-hashed password it is supposed to reinforce.
        """
        secret, _ = self.enrol()
        row = self.bank.conn.execute(
            "SELECT totp_secret_sealed FROM users WHERE id=?", (self.uid,)).fetchone()
        blob = row["totp_secret_sealed"]
        self.assertNotIn(secret, blob)
        # Nor any decodable fragment of it.
        self.assertNotIn(secret[:8], blob)
        self.assertTrue(blob.startswith("v1."))

    def test_seal_is_nonce_randomised(self):
        p = "pep"
        s = T.new_secret()
        self.assertNotEqual(T.seal(s, p), T.seal(s, p))
        self.assertEqual(T.unseal(T.seal(s, p), p), s)

    def test_tampered_blob_is_refused_not_silently_wrong(self):
        """Encrypt-then-MAC: write access to the DB must not swap the secret.

        Without the tag, an attacker with only an UPDATE could install their
        own secret. With it, they need the pepper too.
        """
        p = "pep"
        blob = T.seal(T.new_secret(), p)
        head, nonce, ct, tag = blob.split(".")
        flipped = ("0" if ct[0] != "0" else "1") + ct[1:]
        with self.assertRaises(T.TotpError):
            T.unseal(".".join([head, nonce, flipped, tag]), p)
        with self.assertRaises(T.TotpError):
            T.unseal(blob, "different-pepper")

    def test_unseal_failure_surfaces_as_operator_error(self):
        """A rotated pepper must not look like a user typing a bad code.

        If it did, the user would retry forever against a secret that can never
        be read, and the real fault -- a changed deployment secret -- would
        never be named.
        """
        self.enrol()
        with self.bank.write() as conn:
            conn.execute("UPDATE users SET totp_secret_sealed=? WHERE id=?",
                         ("v1.00.00.00", self.uid))
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        with self.assertRaises(T.TotpError):
            U.complete_mfa(self.bank, out["challenge_token"], "000000")


class TestEnrolment(Base):
    def test_enrolment_requires_the_current_password(self):
        """A stolen session token must not be able to bind a new authenticator.

        Otherwise the attacker enrols their own factor and the real owner is
        locked out of their own wallet permanently.
        """
        with self.assertRaises(U.AuthError):
            U.begin_totp_enrolment(self.bank, self.uid, "wrong-password")

    def test_factor_is_not_active_until_a_code_is_proven(self):
        """Two-phase enrolment: a mangled QR must not lock the account.

        Activating on generation is the standard way users lock themselves out
        -- a mistyped secret or a skewed phone clock yields an account whose
        factor nobody can satisfy.
        """
        start = U.begin_totp_enrolment(self.bank, self.uid, PASSWORD)
        self.assertFalse(start["enrolled"])
        self.assertFalse(U.is_mfa_enrolled(self.bank, self.uid))
        # A password login still works at this point, by design.
        self.assertIn("session_token", U.login(self.bank, "kay@example.com", PASSWORD))

        U.confirm_totp_enrolment(self.bank, self.uid, T.totp(start["secret"]))
        self.assertTrue(U.is_mfa_enrolled(self.bank, self.uid))

    def test_confirm_with_a_wrong_code_does_not_enable(self):
        U.begin_totp_enrolment(self.bank, self.uid, PASSWORD)
        with self.assertRaises(U.AuthError):
            U.confirm_totp_enrolment(self.bank, self.uid, "000000")
        self.assertFalse(U.is_mfa_enrolled(self.bank, self.uid))

    def test_confirm_without_begin_is_refused(self):
        with self.assertRaises(U.AuthError):
            U.confirm_totp_enrolment(self.bank, self.uid, "123456")

    def test_cannot_re_enrol_over_a_live_factor(self):
        """Re-enrolling silently would be a downgrade path.

        Begin-enrolment requires only the password; if it could overwrite a
        live secret, a password thief would replace the factor instead of
        defeating it.
        """
        self.enrol()
        with self.assertRaises(U.AuthError):
            U.begin_totp_enrolment(self.bank, self.uid, PASSWORD)

    def test_the_qr_encodes_THIS_user_s_secret(self):
        """Decode the symbol the route actually returns, like a phone camera.

        `tests/test_qr.py` proves the encoder round-trips, and the page is
        proven to draw what it is handed. Neither proves the WIRING: that the
        symbol on the enrolment card carries this user's freshly minted secret
        rather than a stale one, the URI's unescaped form, or some other
        account's. A user who scans a QR bound to the wrong secret gets codes
        the server rejects while the key printed beside it would have worked —
        indistinguishable, from their side, from 2FA being broken.
        """
        from tests.test_qr import _Decoder

        start = U.begin_totp_enrolment(self.bank, self.uid, PASSWORD)
        rows = start["qr_rows"]
        self.assertTrue(rows, "enrolment must return a scannable symbol")
        matrix = [[ch == "1" for ch in row] for row in rows]
        scanned = _Decoder(matrix).payload().decode()

        self.assertEqual(scanned, start["otpauth_uri"])
        self.assertIn(f"secret={start['secret']}", scanned)
        # And the scanned secret must actually drive the factor, not merely
        # match a string in the response.
        U.confirm_totp_enrolment(
            self.bank, self.uid,
            T.totp(scanned.split("secret=")[1].split("&")[0]))
        self.assertTrue(U.is_mfa_enrolled(self.bank, self.uid))

    def test_re_enrolment_returns_a_fresh_symbol(self):
        """A cached QR would hand out a secret the server no longer accepts."""
        a = U.begin_totp_enrolment(self.bank, self.uid, PASSWORD)
        U.confirm_totp_enrolment(self.bank, self.uid, T.totp(a["secret"]))
        U.disable_totp(self.bank, self.uid, PASSWORD,
                       self.fresh_code(a["secret"]))
        b = U.begin_totp_enrolment(self.bank, self.uid, PASSWORD)
        self.assertNotEqual(a["secret"], b["secret"])
        self.assertNotEqual(a["qr_rows"], b["qr_rows"])

    def test_provisioning_uri_is_well_formed(self):
        start = U.begin_totp_enrolment(self.bank, self.uid, PASSWORD)
        uri = start["otpauth_uri"]
        self.assertTrue(uri.startswith("otpauth://totp/aibank%3Akay%40example.com?"))
        self.assertIn(f"secret={start['secret']}", uri)
        self.assertIn("issuer=aibank", uri)
        self.assertIn(f"period={T.STEP_SECONDS}", uri)


class TestLoginBypass(Base):
    """The central property: a password alone cannot reach the limits."""

    def test_password_alone_yields_no_session(self):
        self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        self.assertTrue(out["mfa_required"])
        self.assertNotIn("session_token", out)
        # And no session row was created as a side effect.
        n = self.bank.conn.execute(
            "SELECT COUNT(*) AS n FROM sessions WHERE user_id=?",
            (self.uid,)).fetchone()["n"]
        self.assertEqual(n, 0)

    def test_challenge_token_is_not_a_session_token(self):
        """The half-authenticated credential must not authenticate anything."""
        self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        self.assertIsNone(U.authenticate_session(self.bank, out["challenge_token"]))

    def test_challenge_plus_code_yields_a_session(self):
        secret, _ = self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        done = U.complete_mfa(self.bank, out["challenge_token"],
                              self.fresh_code(secret))
        self.assertIn("session_token", done)
        self.assertTrue(done["mfa"])
        sess = U.authenticate_session(self.bank, done["session_token"])
        self.assertEqual(sess["user_id"], self.uid)

    def test_challenge_is_single_use(self):
        """Replaying a captured challenge must not mint a second session."""
        secret, _ = self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        U.complete_mfa(self.bank, out["challenge_token"], self.fresh_code(secret))
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, out["challenge_token"], self.fresh_code(secret))

    def test_a_new_login_invalidates_the_previous_challenge(self):
        """An attacker holding an old challenge must not keep guessing it."""
        secret, _ = self.enrol()
        first = U.login(self.bank, "kay@example.com", PASSWORD)
        U.login(self.bank, "kay@example.com", PASSWORD)
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, first["challenge_token"], self.fresh_code(secret))

    def test_expired_challenge_is_refused(self):
        secret, _ = self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        with self.bank.write() as conn:
            conn.execute("UPDATE mfa_challenges SET expires_at='2000-01-01T00:00:00'"
                         " WHERE user_id=?", (self.uid,))
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, out["challenge_token"], self.fresh_code(secret))

    def test_unknown_challenge_token_is_refused(self):
        self.enrol()
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, "mfa_not-a-real-token", "123456")

    def test_wrong_password_never_reaches_the_challenge_stage(self):
        """Failing at step one must not disclose that a factor is enrolled."""
        self.enrol()
        with self.assertRaises(U.AuthError):
            U.login(self.bank, "kay@example.com", "wrong-password")
        n = self.bank.conn.execute(
            "SELECT COUNT(*) AS n FROM mfa_challenges").fetchone()["n"]
        self.assertEqual(n, 0)

    def test_suspended_account_cannot_complete_mfa(self):
        secret, _ = self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        with self.bank.write() as conn:
            conn.execute("UPDATE users SET status='suspended' WHERE id=?", (self.uid,))
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, out["challenge_token"], self.fresh_code(secret))


class TestReplayAndBruteForce(Base):
    def test_a_code_cannot_be_reused(self):
        """The attack: observe one code (shoulder-surf, proxy, phish) and reuse it.

        Codes stay valid for up to 90 seconds, which is ample. The high-water
        counter makes each one single-use.
        """
        secret, _ = self.enrol()
        code = self.fresh_code(secret)
        first = U.login(self.bank, "kay@example.com", PASSWORD)
        U.complete_mfa(self.bank, first["challenge_token"], code)

        second = U.login(self.bank, "kay@example.com", PASSWORD)
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, second["challenge_token"], code)

    def test_replay_protection_survives_a_restart(self):
        """In-memory replay tracking would reset with the process.

        The counter lives in the database precisely so a restart is not a free
        replay window -- the same reasoning as durable login lockout.
        """
        secret, _ = self.enrol()
        when = time.time() + T.STEP_SECONDS
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        U.complete_mfa(self.bank, out["challenge_token"], T.totp(secret, timestamp=when))
        stored = self.bank.conn.execute(
            "SELECT totp_last_counter FROM users WHERE id=?",
            (self.uid,)).fetchone()["totp_last_counter"]
        self.assertEqual(stored, T.counter_for(when))

    def test_guesses_per_challenge_are_capped(self):
        """Without a cap, a 6-digit code falls to an online guesser."""
        self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        for _ in range(U.MFA_MAX_ATTEMPTS):
            with self.assertRaises(U.AuthError):
                U.complete_mfa(self.bank, out["challenge_token"], "000000")
        with self.assertRaises(U.LockedOut):
            U.complete_mfa(self.bank, out["challenge_token"], "000000")

    def test_a_burned_challenge_stays_dead_even_with_the_right_code(self):
        secret, _ = self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        for _ in range(U.MFA_MAX_ATTEMPTS):
            with self.assertRaises(U.AuthError):
                U.complete_mfa(self.bank, out["challenge_token"], "000000")
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, out["challenge_token"], self.fresh_code(secret))

    def test_failed_attempts_are_committed_not_rolled_back(self):
        """The bug that once made login lockout dead code, re-checked here.

        An increment inside the transaction that raises is an increment that
        never happened, and the cap becomes decorative.
        """
        self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, out["challenge_token"], "000000")
        attempts = self.bank.conn.execute(
            "SELECT attempts FROM mfa_challenges WHERE user_id=?",
            (self.uid,)).fetchone()["attempts"]
        self.assertEqual(attempts, 1)

    def test_a_spent_code_is_distinguished_from_a_wrong_one(self):
        """FOUND BY RUNNING IT: a working authenticator reported as invalid.

        Confirming enrolment spends the code on screen, so a user who signs in
        within that same 30-second step presents a correct-but-used code. The
        first implementation collapsed that into "invalid code" and ALSO spent
        an attempt against the brute-force cap -- telling a user whose setup is
        perfectly fine that it is broken, which is how people decide 2FA is
        flaky and switch it off.

        Two properties are pinned: the message tells them to wait, and the
        challenge is NOT burned, so their next code works without a re-login.
        """
        start = U.begin_totp_enrolment(self.bank, self.uid, PASSWORD)
        secret = start["secret"]
        code = T.totp(secret)
        U.confirm_totp_enrolment(self.bank, self.uid, code)

        out = U.login(self.bank, "kay@example.com", PASSWORD)
        with self.assertRaises(U.AuthError) as ctx:
            U.complete_mfa(self.bank, out["challenge_token"], code)
        self.assertIn("already been used", str(ctx.exception))
        self.assertNotIn("invalid", str(ctx.exception).lower())

        # The SAME challenge still works with the next code: no re-login.
        done = U.complete_mfa(self.bank, out["challenge_token"],
                              self.fresh_code(secret))
        self.assertIn("session_token", done)

    def test_a_spent_code_raises_the_specific_type(self):
        secret = T.new_secret()
        counter = T.counter_for()
        with self.assertRaises(T.CodeReused):
            T.verify(secret, T.totp(secret), last_counter=counter)
        # and a genuinely wrong code is still the generic error
        with self.assertRaises(T.TotpError):
            T.verify(secret, "000000", last_counter=None)


class TestRecoveryCodes(Base):
    def test_codes_are_issued_once_and_stored_hashed(self):
        _, codes = self.enrol()
        self.assertEqual(len(codes), T.RECOVERY_CODE_COUNT)
        rows = self.bank.conn.execute(
            "SELECT code_hash FROM recovery_codes WHERE user_id=?",
            (self.uid,)).fetchall()
        hashes = {r["code_hash"] for r in rows}
        for c in codes:
            self.assertNotIn(c, hashes)
            self.assertNotIn(T.normalize_recovery_code(c), hashes)

    def test_a_recovery_code_substitutes_for_the_authenticator(self):
        """A lost phone must not mean a frozen wallet with live agents.

        Without recovery, our own factor becomes a denial of service on the
        account holder, and users work around it by screenshotting the QR --
        which is worse than the problem.
        """
        _, codes = self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        done = U.complete_mfa(self.bank, out["challenge_token"], codes[0])
        self.assertIn("session_token", done)
        self.assertTrue(done["used_recovery_code"])
        self.assertEqual(done["recovery_codes_remaining"], T.RECOVERY_CODE_COUNT - 1)

    def test_a_recovery_code_is_single_use(self):
        _, codes = self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        U.complete_mfa(self.bank, out["challenge_token"], codes[0])
        again = U.login(self.bank, "kay@example.com", PASSWORD)
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, again["challenge_token"], codes[0])

    def test_recovery_codes_are_accepted_in_any_readable_form(self):
        _, codes = self.enrol()
        messy = f"  {codes[0].upper().replace('-', ' ')}  "
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        self.assertIn("session_token",
                      U.complete_mfa(self.bank, out["challenge_token"], messy))

    def test_regenerating_invalidates_every_old_code(self):
        _, old = self.enrol()
        new = U.regenerate_recovery_codes(self.bank, self.uid, PASSWORD)
        self.assertEqual(len(new), T.RECOVERY_CODE_COUNT)
        self.assertFalse(set(new) & set(old))
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, out["challenge_token"], old[0])

    def test_regeneration_requires_the_password(self):
        self.enrol()
        with self.assertRaises(U.AuthError):
            U.regenerate_recovery_codes(self.bank, self.uid, "wrong-password")

    def test_recovery_codes_do_not_survive_re_enrolment(self):
        """An old printout must not bypass a NEW factor."""
        _, old = self.enrol()
        U.disable_totp(self.bank, self.uid, PASSWORD, old[0])
        _, new = self.enrol()
        self.assertFalse(set(new) & set(old))
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, out["challenge_token"], old[1])

    def test_code_alphabet_excludes_ambiguous_characters(self):
        """These get read off a screen and retyped; 0/O and 1/l/I cause tickets."""
        for _ in range(50):
            code = T.new_recovery_code()
            self.assertNotRegex(code, r"[01loiLOI]")
            self.assertRegex(code, r"^[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}$")


class TestDisable(Base):
    def test_password_alone_cannot_remove_the_factor(self):
        """The downgrade attack, and the reason the factor exists at all.

        If a password could switch it off, a password thief would simply
        disable it rather than defeat it, and the factor would protect nothing.
        """
        self.enrol()
        with self.assertRaises(U.AuthError):
            U.disable_totp(self.bank, self.uid, PASSWORD, None)
        with self.assertRaises(U.AuthError):
            U.disable_totp(self.bank, self.uid, PASSWORD, "000000")
        self.assertTrue(U.is_mfa_enrolled(self.bank, self.uid))

    def test_a_code_alone_cannot_remove_the_factor(self):
        secret, _ = self.enrol()
        with self.assertRaises(U.AuthError):
            U.disable_totp(self.bank, self.uid, "wrong-password",
                           self.fresh_code(secret))
        self.assertTrue(U.is_mfa_enrolled(self.bank, self.uid))

    def test_password_plus_code_removes_it_and_revokes_sessions(self):
        """Disabling is a security downgrade, so live sessions must not survive.

        If an attacker did this, the owner's next page load fails -- which is
        how they find out.

        Signing in with a RECOVERY code here rather than a TOTP code is
        deliberate: it leaves the TOTP counter unspent, so the disable step can
        present a real authenticator code without the test having to wait out a
        30-second window.
        """
        secret, codes = self.enrol()
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        done = U.complete_mfa(self.bank, out["challenge_token"], codes[0])
        token = done["session_token"]
        self.assertIsNotNone(U.authenticate_session(self.bank, token))

        U.disable_totp(self.bank, self.uid, PASSWORD, self.fresh_code(secret))

        self.assertFalse(U.is_mfa_enrolled(self.bank, self.uid))
        self.assertIsNone(U.authenticate_session(self.bank, token))
        self.assertEqual(U.count_recovery_codes(self.bank, self.uid), 0)
        # And the password-only path works again, as expected after removal.
        self.assertIn("session_token", U.login(self.bank, "kay@example.com", PASSWORD))

    def test_a_spent_code_when_disabling_says_wait_not_invalid(self):
        """The same misleading-message bug, on the disable path.

        A user who signs in and immediately turns the factor off presents the
        code they just spent. Reporting that as "invalid" sends them looking
        for a broken authenticator.
        """
        secret, _ = self.enrol()
        code = self.fresh_code(secret)
        out = U.login(self.bank, "kay@example.com", PASSWORD)
        U.complete_mfa(self.bank, out["challenge_token"], code)
        with self.assertRaises(U.AuthError) as ctx:
            U.disable_totp(self.bank, self.uid, PASSWORD, code)
        self.assertIn("already been used", str(ctx.exception))
        self.assertTrue(U.is_mfa_enrolled(self.bank, self.uid))

    def test_a_recovery_code_can_remove_it(self):
        _, codes = self.enrol()
        U.disable_totp(self.bank, self.uid, PASSWORD, codes[0])
        self.assertFalse(U.is_mfa_enrolled(self.bank, self.uid))

    def test_disabling_when_not_enrolled_is_an_error_not_a_noop(self):
        with self.assertRaises(U.AuthError):
            U.disable_totp(self.bank, self.uid, PASSWORD, "123456")


class TestSchemaAndIntegration(Base):
    def test_existing_databases_migrate_without_losing_users(self):
        """An upgrade must not be a data-loss event.

        v5 adds columns to `users`, which is the table every other row
        references. A migration that rebuilt it wrongly would orphan agents,
        policies and payouts.
        """
        from aibank import db as D
        path = D.ephemeral_path()
        conn = D.connect(path)
        # Stand up a v4 database, then migrate forward.
        for version, sql in D.MIGRATIONS:
            if version > 4:
                break
            conn.executescript(sql)
        conn.execute("INSERT INTO users (id, email, password_hash, password_salt,"
                     " kdf, role, status, created_at) VALUES"
                     " ('user_old','old@example.com','h','s','scrypt','user',"
                     "'active','2026-01-01T00:00:00')")
        conn.commit()
        conn.execute("CREATE TABLE IF NOT EXISTS schema_version ("
                     " version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        conn.execute("INSERT INTO schema_version VALUES (4, '2026-01-01T00:00:00')")
        conn.commit()

        applied = D.migrate(conn)
        self.assertIn(5, applied)
        self.assertEqual(D.current_version(conn), D.SCHEMA_VERSION)
        row = conn.execute("SELECT email, totp_enrolled_at FROM users"
                           " WHERE id='user_old'").fetchone()
        self.assertEqual(row[0], "old@example.com")
        self.assertIsNone(row[1])   # pre-existing users are not enrolled
        self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
        conn.close()

    def test_mfa_state_is_visible_to_the_owner(self):
        self.assertFalse(U.get_user(self.bank, self.uid)["mfa_enabled"])
        self.enrol()
        me = U.get_user(self.bank, self.uid)
        self.assertTrue(me["mfa_enabled"])
        self.assertIsNotNone(me["totp_enrolled_at"])

    def test_changing_a_password_does_not_remove_the_factor(self):
        """A password reset must not be a factor reset.

        If it were, the password-recovery path would become the bypass.
        """
        secret, _ = self.enrol()
        U.change_password(self.bank, self.uid, PASSWORD, "another-long-password")
        self.assertTrue(U.is_mfa_enrolled(self.bank, self.uid))
        out = U.login(self.bank, "kay@example.com", "another-long-password")
        self.assertTrue(out["mfa_required"])
        self.assertIn("session_token", U.complete_mfa(
            self.bank, out["challenge_token"], self.fresh_code(secret)))

    def test_recovery_code_hashes_are_unique_across_the_table(self):
        """A collision would let one user's code open another's account."""
        self.enrol()
        second = U.create_user(self.bank, "two@example.com", PASSWORD)
        start = U.begin_totp_enrolment(self.bank, second["user_id"], PASSWORD)
        U.confirm_totp_enrolment(self.bank, second["user_id"], T.totp(start["secret"]))
        rows = self.bank.conn.execute("SELECT code_hash FROM recovery_codes").fetchall()
        hashes = [r["code_hash"] for r in rows]
        self.assertEqual(len(hashes), len(set(hashes)))
        self.assertEqual(len(hashes), 2 * T.RECOVERY_CODE_COUNT)

    def test_another_users_recovery_code_does_not_work(self):
        _, mine = self.enrol()
        other = U.create_user(self.bank, "two@example.com", PASSWORD)
        start = U.begin_totp_enrolment(self.bank, other["user_id"], PASSWORD)
        U.confirm_totp_enrolment(self.bank, other["user_id"], T.totp(start["secret"]))
        out = U.login(self.bank, "two@example.com", PASSWORD)
        with self.assertRaises(U.AuthError):
            U.complete_mfa(self.bank, out["challenge_token"], mine[0])


if __name__ == "__main__":
    unittest.main()
