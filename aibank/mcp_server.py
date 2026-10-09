"""MCP server: exposes an aibank agent wallet as typed tools an LLM can call.

WHY THIS PROCESS TALKS HTTP INSTEAD OF IMPORTING `Bank`
-------------------------------------------------------
This module deliberately does NOT import `aibank.bank`. It holds one agent API
key and speaks to the service over HTTP, exactly like any other third-party
caller. That is not an architectural nicety -- it is the security boundary:

  * An in-process `Bank` would hand the model's host process a live SQLite
    handle, and therefore write access to the `policies` table. Every limit the
    human set on the dashboard would then be one stray tool implementation away
    from being raised by the thing it constrains.
  * Over HTTP the agent credential is rejected by `_user()` on every
    policy/approval route before a handler runs. The ceiling is enforced on the
    far side of a socket, by code this process cannot reach.

So the tool surface below is *incapable* of exposing a policy write, and
`tests/test_mcp.py` asserts that structurally against this file's source.

MCP's spec says there SHOULD be a human in the loop able to deny a tool
invocation. On a bank that cannot be left to the client UI: a client that
chooses not to prompt would silently remove the control. aibank's human gate is
server-side instead -- `require_approval_above` parks the payout in
`pending_approval` and no sequence of tool calls can release it. The client
prompt, where it exists, is a second line of defence, not the first.

Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio).
stdout carries protocol frames ONLY; all logging goes to stderr.

Run:
    AIBANK_URL=http://127.0.0.1:8000 AIBANK_API_KEY=sk_agent_... \
        python3 -m aibank.mcp_server
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "aibank"
SERVER_VERSION = "0.3"

DEFAULT_URL = "http://127.0.0.1:8000"
HTTP_TIMEOUT = float(os.environ.get("AIBANK_MCP_TIMEOUT", "20"))

# Read-only mode drops every money-moving tool from tools/list entirely, rather
# than refusing them at call time. A tool the model cannot see is a tool it
# cannot be talked into trying -- useful for demos and for untrusted prompts.
READONLY = os.environ.get("AIBANK_MCP_READONLY", "").lower() in ("1", "true", "yes")


def log(msg: str) -> None:
    print(f"[mcp] {msg}", file=sys.stderr, flush=True)


class ToolError(Exception):
    """A failure the MODEL should see and reason about, not a protocol fault."""

    def __init__(self, message: str, detail: dict | None = None):
        super().__init__(message)
        self.detail = detail or {}


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
class AibankClient:
    def __init__(self, base_url: str, api_key: str):
        self.base = base_url.rstrip("/")
        self._key = api_key

    def _call(self, method: str, path: str, body: dict | None = None,
              headers: dict | None = None) -> dict:
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._key}")
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw) if raw else {}
            except ValueError:
                payload = {"error": "unreadable_error_body"}
            raise ToolError(_explain(exc.code, payload), {"http_status": exc.code,
                                                          **payload}) from None
        except urllib.error.URLError as exc:
            # Never let a transport failure read as a failed PAYMENT: a timeout
            # can mean the payout was created and the response was lost.
            raise ToolError(
                f"could not reach the aibank service at {self.base}: {exc.reason}. "
                "The request may or may not have been applied -- do NOT retry a "
                "payment with a new idempotency_key; retry with the SAME key, or "
                "call list_payouts to check.",
                {"transport_error": str(exc.reason)}) from None

    def get(self, path: str) -> dict:
        return self._call("GET", path)

    def post(self, path: str, body: dict, headers: dict | None = None) -> dict:
        return self._call("POST", path, body, headers)


def _explain(status: int, payload: dict) -> str:
    """Turn an HTTP status into guidance that stops a model retrying blindly."""
    reason = payload.get("reason") or payload.get("error") or "unknown error"
    if status == 401:
        return ("authentication failed: this agent key is invalid, revoked, or "
                "was presented to a route that requires the human account "
                f"holder's session. Agent keys cannot do that. ({reason})")
    if status == 403:
        return (f"POLICY DENIED -- {reason}. This is a final answer from the "
                "spend policy the account holder set. Do not retry, do not "
                "split the amount across several payments, and do not change "
                "the idempotency key. Report the limit to the human instead.")
    if status == 402:
        return (f"insufficient funds -- {reason}. Spendable balance is the "
                "balance minus funds already held by in-flight payouts. The "
                "account holder must allocate more before this can succeed.")
    if status == 404:
        return f"not found -- {reason}. It may belong to a different agent."
    if status == 409:
        return f"duplicate request -- {reason}. The original was already applied."
    if status == 429:
        return f"rate limited / locked out -- {reason}."
    return f"request failed ({status}) -- {reason}"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
_AMOUNT_HELP = ("Decimal string in MAJOR units, e.g. \"2500.00\" for two "
                "thousand five hundred naira. Must be a STRING: a JSON number "
                "would be parsed as a float and silently lose precision.")


def _amount(args: dict, field: str = "amount") -> str:
    v = args.get(field)
    if v is None:
        raise ToolError(f"missing required argument `{field}`. {_AMOUNT_HELP}")
    if isinstance(v, bool) or not isinstance(v, (str, int)):
        # int is tolerated (lossless); float and bool are not.
        raise ToolError(
            f"`{field}` must be a decimal STRING, got {type(v).__name__}. "
            f"{_AMOUNT_HELP}")
    return str(v)


def _require(args: dict, field: str) -> str:
    v = args.get(field)
    if not isinstance(v, str) or not v.strip():
        raise ToolError(f"missing required argument `{field}` (non-empty string)")
    return v.strip()


def t_whoami(c: AibankClient, args: dict) -> dict:
    me = c.get("/v1/me")
    return {**me, "note": "This credential may spend under the policy the human "
                          "account holder set. It cannot read or change that policy."}


def t_get_balance(c: AibankClient, args: dict) -> dict:
    cur = args.get("currency", "NGN")
    b = c.get(f"/v1/balance?currency={cur}")
    b["note"] = ("`available` is what you may spend now: balance minus funds "
                 "held by payouts already in flight. Fees are charged on top "
                 "of the amount, so check quote_fee before spending near the "
                 "available balance.")
    return b


def t_list_payees(c: AibankClient, args: dict) -> dict:
    return c.get("/v1/payees")


def t_add_payee(c: AibankClient, args: dict) -> dict:
    return c.post("/v1/payees", {
        "label": _require(args, "label"),
        "bank_code": _require(args, "bank_code"),
        "account_number": _require(args, "account_number"),
        "currency": args.get("currency", "NGN"),
    })


def t_quote_fee(c: AibankClient, args: dict) -> dict:
    amt = _amount(args)
    cur = args.get("currency", "NGN")
    q = c.get(f"/v1/quote?amount={urllib.parse.quote(amt)}&currency="
              f"{urllib.parse.quote(cur)}")
    q["note"] = ("The fee is set server-side from the platform's schedule. A "
                 "fee you supply in a payment request is ignored.")
    return q


def t_pay(c: AibankClient, args: dict) -> dict:
    """The one tool that moves money. Everything here is about not moving it twice."""
    amount = _amount(args)
    idem = _require(args, "idempotency_key")
    body: dict = {
        "amount": amount,
        "currency": args.get("currency", "NGN"),
        "narration": args.get("narration", ""),
    }
    payee_id = args.get("payee_id")
    if payee_id:
        body["payee_id"] = payee_id
    else:
        # An LLM inventing a bank destination is the worst failure mode here, so
        # the raw-destination path demands both halves explicitly.
        body["bank_code"] = _require(args, "bank_code")
        body["account_number"] = _require(args, "account_number")

    out = c.post("/v1/payouts", body, headers={"Idempotency-Key": idem})
    status = out.get("status")
    if status == "pending_approval":
        out["note"] = ("MONEY HAS NOT MOVED. This payment exceeded the approval "
                       "threshold the account holder set, so it is parked and a "
                       "human must approve it from the dashboard. You cannot "
                       "approve it yourself. Do not resubmit -- that would queue "
                       "a second payment. Tell the human it is waiting.")
    elif status == "submitted":
        out["note"] = ("Submitted to the payment provider. This is NOT yet "
                       "confirmed delivery: the funds are held and settlement "
                       "lands when the provider's signed webhook arrives. Poll "
                       "get_payout for the final status.")
    return out


def t_get_payout(c: AibankClient, args: dict) -> dict:
    return c.get(f"/v1/payouts/{_require(args, 'payout_id')}")


def t_list_payouts(c: AibankClient, args: dict) -> dict:
    q = []
    if args.get("status"):
        q.append(f"status={args['status']}")
    limit = int(args.get("limit", 20))
    q.append(f"limit={max(1, min(limit, 100))}")
    return c.get("/v1/payouts?" + "&".join(q))


# name -> (handler, write?, schema)
TOOLS: dict[str, tuple] = {
    "whoami": (t_whoami, False, {
        "title": "Who am I",
        "description": "Identify the agent this credential belongs to and what it "
                       "is permitted to do. Call this first if unsure.",
        "inputSchema": {"type": "object", "properties": {}},
    }),
    "get_balance": (t_get_balance, False, {
        "title": "Get wallet balance",
        "description": "Current balance, funds held by in-flight payouts, and the "
                       "spendable (available) amount for this agent's wallet.",
        "inputSchema": {
            "type": "object",
            "properties": {"currency": {"type": "string", "default": "NGN",
                                        "description": "ISO currency code."}},
        },
    }),
    "quote_fee": (t_quote_fee, False, {
        "title": "Quote the fee for a payment",
        "description": "Server-side fee for a given amount, plus the total that "
                       "will be debited. Call before paying near the available "
                       "balance: the fee is charged on top of the amount.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount": {"type": "string", "description": _AMOUNT_HELP},
                "currency": {"type": "string", "default": "NGN"},
            },
            "required": ["amount"],
        },
    }),
    "list_payees": (t_list_payees, False, {
        "title": "List saved payees",
        "description": "Payment destinations already saved for this agent. Prefer "
                       "paying a saved payee_id over typing account numbers.",
        "inputSchema": {"type": "object", "properties": {}},
    }),
    "add_payee": (t_add_payee, True, {
        "title": "Save a payee",
        "description": "Save a bank destination for reuse. Only ever call this "
                       "with account details a human gave you verbatim -- never "
                       "with a guessed, inferred, or remembered account number.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "label": {"type": "string", "description": "Human-readable name."},
                "bank_code": {"type": "string"},
                "account_number": {"type": "string"},
                "currency": {"type": "string", "default": "NGN"},
            },
            "required": ["label", "bank_code", "account_number"],
        },
    }),
    "pay": (t_pay, True, {
        "title": "Send a payment",
        "description": (
            "Move money from this agent's wallet to a payee. Real funds.\n\n"
            "`idempotency_key` is REQUIRED and is the only protection against "
            "paying twice: reuse the SAME key for every retry of the same "
            "logical payment (derive it from the thing being paid for, e.g. "
            "\"invoice-4417\"), and use a NEW key only for a genuinely new "
            "payment. If a call fails with a network error, retry with the same "
            "key -- the service returns the original payout instead of making a "
            "second one.\n\n"
            "A 'policy denied' result is final. Do not retry it, do not split "
            "the amount into smaller payments to get under a limit, and do not "
            "change the key: report the limit to the human, who is the only "
            "party who can change it."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount": {"type": "string", "description": _AMOUNT_HELP},
                "currency": {"type": "string", "default": "NGN"},
                "payee_id": {"type": "string",
                             "description": "A saved payee from list_payees. "
                                            "Preferred over raw bank details."},
                "bank_code": {"type": "string",
                              "description": "Only if no payee_id. Must come from "
                                             "a human, not from memory."},
                "account_number": {"type": "string",
                                   "description": "Only if no payee_id."},
                "narration": {"type": "string",
                              "description": "What this payment is for."},
                "idempotency_key": {
                    "type": "string",
                    "description": "Stable unique id for THIS logical payment. "
                                   "Same key on every retry; new key only for a "
                                   "new payment."},
            },
            "required": ["amount", "idempotency_key"],
        },
    }),
    "get_payout": (t_get_payout, False, {
        "title": "Get one payment",
        "description": "Status and details of a payment this agent made.",
        "inputSchema": {
            "type": "object",
            "properties": {"payout_id": {"type": "string"}},
            "required": ["payout_id"],
        },
    }),
    "list_payouts": (t_list_payouts, False, {
        "title": "List payments",
        "description": "This agent's recent payments, newest first. Use to check "
                       "whether a payment landed before considering a retry.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string",
                           "enum": ["pending_approval", "submitted", "successful",
                                    "failed", "rejected", "refunded"]},
                "limit": {"type": "integer", "default": 20, "maximum": 100},
            },
        },
    }),
}


def visible_tools() -> dict[str, tuple]:
    if READONLY:
        return {n: t for n, t in TOOLS.items() if not t[1]}
    return TOOLS


# ---------------------------------------------------------------------------
# JSON-RPC / MCP plumbing
# ---------------------------------------------------------------------------
class Server:
    def __init__(self, client: AibankClient):
        self.client = client
        self.initialized = False

    # -- framing --
    @staticmethod
    def _write(obj: dict) -> None:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def _result(self, mid, result) -> None:
        self._write({"jsonrpc": "2.0", "id": mid, "result": result})

    def _error(self, mid, code: int, message: str) -> None:
        self._write({"jsonrpc": "2.0", "id": mid,
                     "error": {"code": code, "message": message}})

    # -- methods --
    def handle(self, msg: dict) -> None:
        mid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        if method is None:
            if mid is not None:
                self._error(mid, -32600, "not a request: no method")
            return

        # Notifications carry no id and MUST NOT be answered.
        is_notification = "id" not in msg

        if method == "notifications/initialized" or method == "initialized":
            self.initialized = True
            return
        if method.startswith("notifications/"):
            return

        try:
            if method == "initialize":
                return self._result(mid, {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "instructions": (
                        "This server spends real money from one agent wallet, "
                        "under limits a human set and this server cannot change. "
                        "Always call get_balance before paying, pass a stable "
                        "idempotency_key on every payment, and treat a policy "
                        "denial as final rather than retrying around it."),
                })

            if method == "ping":
                return self._result(mid, {})

            if method == "tools/list":
                tools = []
                for name, (_fn, _w, schema) in visible_tools().items():
                    tools.append({"name": name, **schema})
                return self._result(mid, {"tools": tools})

            if method == "tools/call":
                return self._call_tool(mid, params)

            if is_notification:
                return
            return self._error(mid, -32601, f"method not found: {method}")

        except Exception as exc:  # noqa: BLE001
            log(f"internal error in {method}: {exc!r}")
            if not is_notification:
                self._error(mid, -32603, "internal error")

    def _call_tool(self, mid, params: dict) -> None:
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(name, str) or not name:
            return self._error(mid, -32602, "tools/call requires a `name` string")
        if not isinstance(args, dict):
            return self._error(mid, -32602, "arguments must be an object")

        entry = visible_tools().get(name)
        if entry is None:
            # Unknown tool is a PROTOCOL error (the client sent something not in
            # tools/list); a failing tool is not. Keeping these apart is what
            # lets a model distinguish "I used the wrong name" from "the bank
            # said no".
            if name in TOOLS:
                return self._error(
                    mid, -32602,
                    f"tool `{name}` is disabled: this server is running in "
                    "read-only mode")
            return self._error(mid, -32602, f"unknown tool: {name}")

        fn = entry[0]
        try:
            out = fn(self.client, args)
            return self._result(mid, {
                "content": [{"type": "text",
                             "text": json.dumps(out, indent=2, default=str)}],
                "structuredContent": out,
                "isError": False,
            })
        except ToolError as exc:
            # Tool execution failures are reported INSIDE the result so the model
            # reads the reason and corrects itself, per the MCP spec.
            #
            # Order matters: the service's error body carries its own `error`
            # key ("policy_denied"), so splatting detail AFTER the message
            # silently replaced the guidance with a bare machine code -- the
            # model then saw "policy_denied" with no instruction not to retry
            # around it. The explanation must win; the machine code is kept
            # under `code`.
            detail = dict(exc.detail)
            machine_code = detail.pop("error", None)
            payload = {"error": str(exc), **detail}
            if machine_code:
                payload["code"] = machine_code
            return self._result(mid, {
                "content": [{"type": "text",
                             "text": json.dumps(payload, indent=2, default=str)}],
                "structuredContent": payload,
                "isError": True,
            })
        except Exception as exc:  # noqa: BLE001
            log(f"tool {name} crashed: {exc!r}")
            payload = {"error": "internal error running the tool"}
            return self._result(mid, {
                "content": [{"type": "text", "text": json.dumps(payload)}],
                "structuredContent": payload, "isError": True})

    def serve_stdio(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                self._write({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "parse error"}})
                continue
            if isinstance(msg, list):
                for m in msg:
                    if isinstance(m, dict):
                        self.handle(m)
                continue
            if not isinstance(msg, dict):
                self._write({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32600, "message": "invalid request"}})
                continue
            self.handle(msg)


def build_server() -> Server:
    key = os.environ.get("AIBANK_API_KEY", "").strip()
    if not key:
        raise SystemExit(
            "AIBANK_API_KEY is not set. This server needs an AGENT api key "
            "(sk_agent_...), issued from the dashboard. Do not give it a user "
            "session token or the admin key: those carry authority the model "
            "must not have.")
    if key.startswith("sess_"):
        raise SystemExit(
            "AIBANK_API_KEY looks like a user SESSION token (sess_...). That "
            "credential can change spend limits and approve payouts. Issue an "
            "agent api key instead.")
    url = os.environ.get("AIBANK_URL", DEFAULT_URL)
    log(f"aibank MCP server -> {url}"
        f"{' (read-only)' if READONLY else ''}; "
        f"{len(visible_tools())} tools")
    return Server(AibankClient(url, key))


def main(argv=None) -> int:
    """Console-script entry point (`aibank-mcp`).

    Takes no arguments: an MCP runtime spawns this as a stdio child and
    configures it purely through the environment (AIBANK_URL, AIBANK_API_KEY,
    AIBANK_MCP_READONLY), so accepting flags here would only create a second,
    divergent way to point it at a server.

    `argv` defaults to `sys.argv[1:]` rather than to an empty list: a
    setuptools console script calls `main()` with NO arguments, so defaulting
    to empty made the guard below unreachable from the installed `aibank-mcp`
    binary — the only way it is actually invoked.
    """
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise SystemExit(
            "aibank-mcp takes no arguments; configure it with AIBANK_URL and "
            "AIBANK_API_KEY in the environment.")
    build_server().serve_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
