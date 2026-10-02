"""In-process fake of Flutterwave's HTTP layer.

We patch the urlopen-level transport, not our own client methods, so the real
request building, auth header, JSON encoding and error handling are exercised.
"""
from __future__ import annotations

import io
import json
import urllib.error


class FakeResponse(io.BytesIO):
    def __init__(self, payload: dict, status: int = 200):
        super().__init__(json.dumps(payload).encode())
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


class FakeFLW:
    """Records requests; replies with Flutterwave-shaped payloads."""

    def __init__(self, fail_on_transfer: bool = False, http_error: int | None = None):
        self.requests: list[dict] = []
        self.fail_on_transfer = fail_on_transfer
        self.http_error = http_error
        self._next_id = 128286

    def __call__(self, req, timeout=None):
        body = json.loads(req.data.decode()) if req.data else None
        self.requests.append({"method": req.get_method(), "url": req.full_url,
                              "body": body, "headers": dict(req.header_items())})

        if "/transfers" in req.full_url and req.get_method() == "POST":
            if self.http_error:
                raise urllib.error.HTTPError(
                    req.full_url, self.http_error, "Bad Request", {},
                    io.BytesIO(json.dumps(
                        {"status": "error", "message": "Insufficient funds in merchant balance"}
                    ).encode()))
            if self.fail_on_transfer:
                raise urllib.error.URLError("connection reset")
            self._next_id += 1
            return FakeResponse({
                "status": "success", "message": "Transfer Queued Successfully",
                "data": {"id": self._next_id, "account_number": body["account_number"],
                         "bank_code": body["account_bank"], "amount": body["amount"],
                         "currency": body["currency"], "fee": 26.875, "status": "NEW",
                         "reference": body["reference"], "narration": body.get("narration")},
            })

        if "/transfers?reference=" in req.full_url:
            ref = req.full_url.split("reference=")[-1]
            return FakeResponse({"status": "success",
                                 "data": [{"id": 1, "reference": ref, "status": "SUCCESSFUL"}]})

        if "/banks/" in req.full_url:
            return FakeResponse({"status": "success",
                                 "data": [{"id": 1, "code": "044", "name": "Access Bank"}]})

        return FakeResponse({"status": "success", "data": {}})
