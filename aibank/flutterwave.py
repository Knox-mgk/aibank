"""Flutterwave adapter (v3 transfers) using only stdlib urllib.

Two things future-you will care about:

1. WEBHOOK SIGNATURES ARE INCONSISTENT ACROSS FLUTTERWAVE VERSIONS.
   - v3 sends header `verif-hash` containing the PLAIN secret hash.
   - v4 sends header `flutterwave-signature` = base64(HMAC-SHA256(raw_body, secret)).
   Their own docs show both. We accept either, in constant time, so the service
   works no matter which your account emits.

2. NEVER trust a 200 from /transfers as "money delivered". A transfer is queued
   (status NEW/PENDING) and only the webhook or a requery tells you the truth.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import urllib.error
import urllib.request

API_BASE = os.environ.get("FLW_BASE_URL", "https://api.flutterwave.com/v3")


class FlutterwaveError(Exception):
    """A provider call failed.

    `indeterminate` is the load-bearing field, and the distinction is the
    difference between releasing money correctly and releasing money that has
    already left:

    - An HTTP error carries a REPLY. Flutterwave parsed the request and
      refused it ("invalid account", "Insufficient funds in merchant
      balance", "Please enable IP Whitelisting" — all real, all observed
      against the live sandbox). Nothing was queued, so failing the payout and
      releasing the hold is correct.
    - A NETWORK error carries no reply. The request may have arrived and the
      transfer may be queued; the response is simply lost. Declaring that
      failed and releasing the hold lets the agent respend money that is on
      its way out, and the second spend is backed by nothing.

    So: HTTP -> definite, network/timeout -> indeterminate. Callers must branch
    on it rather than treating every exception as a rejection.
    """

    def __init__(self, message: str, status: int | None = None, payload=None,
                 indeterminate: bool = False):
        super().__init__(message)
        self.status, self.payload = status, payload
        self.indeterminate = indeterminate


class FlutterwaveClient:
    def __init__(self, secret_key: str | None = None, base_url: str | None = None,
                 timeout: float = 30.0, opener=None):
        self.secret_key = secret_key or os.environ.get("FLW_SECRET_KEY", "")
        self.base_url = (base_url or API_BASE).rstrip("/")
        self.timeout = timeout
        self._opener = opener  # injectable for tests

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        if not self.secret_key:
            raise FlutterwaveError("FLW_SECRET_KEY is not set")
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.secret_key}")
        req.add_header("Content-Type", "application/json")
        opener = self._opener or urllib.request.urlopen
        try:
            with opener(req, timeout=self.timeout) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = {"raw": raw}
            # A reply arrived: the provider decided. Definite.
            raise FlutterwaveError(
                payload.get("message", f"HTTP {exc.code}"), exc.code, payload) from exc
        except urllib.error.URLError as exc:
            # No reply. Reachability failed, or the response was lost in
            # flight — we cannot know whether the provider acted.
            raise FlutterwaveError(f"network error: {exc.reason}",
                                   indeterminate=True) from exc
        except (TimeoutError, socket.timeout) as exc:
            # urllib raises a bare timeout rather than URLError when the socket
            # times out mid-read, which is EXACTLY the case where a transfer is
            # most likely already queued. Missing this branch is what made a
            # lost response indistinguishable from a refusal.
            raise FlutterwaveError(f"timeout after {self.timeout}s",
                                   indeterminate=True) from exc
        except (json.JSONDecodeError, ValueError) as exc:
            # 200 with an unparseable body (an HTML error page from a proxy, a
            # truncated read). The call may well have succeeded.
            raise FlutterwaveError(f"unreadable provider response: {exc}",
                                   indeterminate=True) from exc

    # --- payouts -------------------------------------------------------
    def initiate_transfer(self, *, bank_code: str, account_number: str,
                          amount_major, currency: str, reference: str,
                          narration: str = "", callback_url: str | None = None,
                          meta: dict | None = None) -> dict:
        """amount is MAJOR units here -- Flutterwave's API takes naira, not kobo."""
        body = {
            "account_bank": bank_code,
            "account_number": account_number,
            "amount": amount_major,
            "currency": currency,
            "reference": reference,
            "narration": narration or "aibank payout",
        }
        if callback_url:
            body["callback_url"] = callback_url
        if meta:
            body["meta"] = meta
        return self._request("POST", "/transfers", body)

    def get_transfer(self, transfer_id: str | int) -> dict:
        return self._request("GET", f"/transfers/{transfer_id}")

    def verify_by_reference(self, reference: str) -> dict:
        return self._request("GET", f"/transfers?reference={reference}")

    def get_banks(self, country: str = "NG") -> dict:
        return self._request("GET", f"/banks/{country}")

    def resolve_account(self, account_number: str, bank_code: str) -> dict:
        return self._request("POST", "/accounts/resolve",
                             {"account_number": account_number, "account_bank": bank_code})

    def get_balance(self, currency: str = "NGN") -> dict:
        return self._request("GET", f"/balances/{currency}")


def verify_webhook(raw_body: bytes, headers: dict, secret_hash: str) -> bool:
    """Accept BOTH Flutterwave signature schemes, constant-time."""
    if not secret_hash:
        return False
    lower = {k.lower(): v for k, v in headers.items() if v is not None}

    v3 = lower.get("verif-hash") or lower.get("verifi-hash")
    if v3 and hmac.compare_digest(str(v3).strip(), secret_hash):
        return True

    v4 = lower.get("flutterwave-signature")
    if v4:
        expected = base64.b64encode(
            hmac.new(secret_hash.encode(), raw_body, hashlib.sha256).digest()
        ).decode()
        if hmac.compare_digest(str(v4).strip(), expected):
            return True
        hex_expected = hmac.new(secret_hash.encode(), raw_body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(str(v4).strip(), hex_expected):
            return True
    return False


def dedupe_key(payload: dict) -> str:
    """Stable identity for an event so redelivery cannot double-apply it."""
    data = payload.get("data") or {}
    for candidate in (payload.get("id"), data.get("id")):
        if candidate is not None:
            return f"flw:{payload.get('event','event')}:{candidate}"
    ref = data.get("reference") or data.get("tx_ref") or ""
    status = data.get("status", "")
    if ref:
        return f"flw:{payload.get('event','event')}:{ref}:{status}"
    blob = json.dumps(payload, sort_keys=True).encode()
    return "flw:sha:" + hashlib.sha256(blob).hexdigest()[:32]
