"""HTTP API on stdlib http.server. No framework, no wheels to compile.

Agent-facing endpoints authenticate with `Authorization: Bearer sk_agent_...`.
Admin endpoints use X-Admin-Key. The webhook endpoint verifies provider
signatures over the RAW body before parsing.
"""
from __future__ import annotations

import json
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .bank import Bank, BankError, PolicyDenied
from .flutterwave import verify_webhook
from .ledger import LedgerError, InsufficientFunds, DuplicateIdempotencyKey
from .money import MoneyError

ADMIN_KEY = os.environ.get("AIBANK_ADMIN_KEY", "admin-dev-key")
SECRET_HASH = os.environ.get("FLW_SECRET_HASH", "")


def make_handler(bank: Bank):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "aibank/0.1"

        def log_message(self, fmt, *args):
            print(f"[api] {self.address_string()} {fmt % args}")

        # -- plumbing --
        def _send(self, code: int, obj: dict):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _raw(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _json(self, raw: bytes) -> dict:
            if not raw:
                return {}
            try:
                return json.loads(raw)
            except ValueError:
                raise BankError("body is not valid JSON")

        def _agent(self) -> str:
            auth = self.headers.get("Authorization", "")
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            agent_id = bank.authenticate(token)
            if not agent_id:
                raise PermissionError("invalid or missing agent API key")
            return agent_id

        def _admin(self):
            if self.headers.get("X-Admin-Key") != ADMIN_KEY:
                raise PermissionError("admin key required")

        # -- routes --
        def do_GET(self):
            self._route("GET", self.path, b"")

        def do_POST(self):
            self._route("POST", self.path, self._raw())

        def _route(self, method: str, path: str, raw: bytes):
            try:
                if path == "/health":
                    return self._send(200, {"ok": True, "service": "aibank"})

                if path == "/v1/webhooks/flutterwave" and method == "POST":
                    if not verify_webhook(raw, dict(self.headers), SECRET_HASH):
                        return self._send(401, {"error": "invalid signature"})
                    return self._send(200, bank.handle_webhook(self._json(raw)))

                if path == "/v1/agents" and method == "POST":
                    self._admin()
                    b = self._json(raw)
                    return self._send(201, bank.create_agent(
                        name=b.get("name", "agent"), currency=b.get("currency", "NGN"),
                        per_txn_max=b.get("per_txn_max"), daily_max=b.get("daily_max"),
                        monthly_max=b.get("monthly_max"),
                        allowlist_only=bool(b.get("allowlist_only", False)),
                        require_approval_above=b.get("require_approval_above")))

                if path == "/v1/fund" and method == "POST":
                    self._admin()
                    b = self._json(raw)
                    entry = bank.fund_agent(b["agent_id"], b["amount"],
                                            b.get("currency", "NGN"),
                                            idempotency_key=b.get("idempotency_key"))
                    return self._send(201, {"entry_id": entry,
                                            "balance": bank.balance(b["agent_id"], b.get("currency", "NGN"))})

                if path == "/v1/me" and method == "GET":
                    agent_id = self._agent()
                    row = bank.conn.execute("SELECT id, name, status FROM agents WHERE id=?",
                                            (agent_id,)).fetchone()
                    return self._send(200, dict(row))

                if path.startswith("/v1/balance") and method == "GET":
                    agent_id = self._agent()
                    cur = "NGN"
                    if "?" in path:
                        from urllib.parse import parse_qs, urlparse
                        cur = parse_qs(urlparse(path).query).get("currency", ["NGN"])[0]
                    return self._send(200, bank.balance(agent_id, cur))

                if path == "/v1/payees" and method == "POST":
                    agent_id = self._agent()
                    b = self._json(raw)
                    pid = bank.add_payee(agent_id, b["label"], b["bank_code"],
                                         b["account_number"], b.get("currency", "NGN"))
                    return self._send(201, {"payee_id": pid})

                if path == "/v1/payouts" and method == "POST":
                    agent_id = self._agent()
                    b = self._json(raw)
                    idem = self.headers.get("Idempotency-Key") or b.get("idempotency_key")
                    out = bank.request_payout(
                        agent_id, b["amount"], b.get("currency", "NGN"),
                        payee_id=b.get("payee_id"), bank_code=b.get("bank_code"),
                        account_number=b.get("account_number"),
                        narration=b.get("narration", ""), fee=b.get("fee", 0),
                        idempotency_key=idem)
                    return self._send(201, out)

                if path.startswith("/v1/payouts/") and method == "GET":
                    self._agent()
                    return self._send(200, bank.get_payout(path.rsplit("/", 1)[-1]))

                return self._send(404, {"error": "not found", "path": path})

            except PermissionError as exc:
                self._send(401, {"error": str(exc)})
            except PolicyDenied as exc:
                self._send(403, {"error": "policy_denied", "reason": str(exc)})
            except InsufficientFunds as exc:
                self._send(402, {"error": "insufficient_funds", "reason": str(exc)})
            except DuplicateIdempotencyKey as exc:
                self._send(409, {"error": "duplicate", "entry_id": exc.existing_entry_id})
            except (MoneyError, LedgerError, BankError, KeyError) as exc:
                self._send(400, {"error": type(exc).__name__, "reason": str(exc)})
            except Exception as exc:  # noqa: BLE001
                traceback.print_exc()
                self._send(500, {"error": "internal", "reason": str(exc)})

    return Handler


def serve(db_path: str = "aibank.db", host: str = "127.0.0.1", port: int = 8000):
    bank = Bank(db_path)
    httpd = ThreadingHTTPServer((host, port), make_handler(bank))
    print(f"aibank listening on http://{host}:{port}  (db={db_path})")
    httpd.serve_forever()


if __name__ == "__main__":
    serve(os.environ.get("AIBANK_DB", "aibank.db"),
          os.environ.get("AIBANK_HOST", "127.0.0.1"),
          int(os.environ.get("AIBANK_PORT", "8000")))
