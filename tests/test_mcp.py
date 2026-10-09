"""Structural tests on the MCP surface. No sockets, no subprocess -- these are
assertions about the SHAPE of the tool surface, which is what stops a later
"helpful" edit widening what the model can reach.

The behavioural proof lives in `scripts/smoke_mcp.py`, which spawns the real
process. This file guards the invariants that a passing behavioural run would
not notice being removed.
"""
from __future__ import annotations

import inspect
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("AIBANK_ALLOW_DEV_SECRETS", "1")
os.environ.setdefault("AIBANK_SCRYPT_N", "1024")

from aibank import mcp_server as M


class TestToolSurface(unittest.TestCase):
    def test_no_tool_can_reach_policy_approval_or_admin(self):
        """THE invariant: the spender's tool surface excludes its own ceiling.

        Checked against the tool TABLE rather than the HTTP routes, because the
        route-level check (api.py) only protects the service; this protects the
        process the model talks to from ever offering the capability.
        """
        banned = ("policy", "approve", "reject", "fund", "deposit", "allocate",
                  "withdraw", "freeze", "fee_set", "admin", "trial", "sweep",
                  "login", "register", "password", "key")
        for name in M.TOOLS:
            for token in banned:
                self.assertNotIn(
                    token, name,
                    f"tool `{name}` names a capability the spender must not have")

    def test_no_tool_implementation_posts_to_a_privileged_route(self):
        """A tool could be named innocently and still POST to /v1/agents/x/policy."""
        privileged = ("/v1/agents", "/v1/fund", "/v1/fees", "/v1/wallet",
                      "/v1/admin", "/v1/auth", "/v1/approvals", "/policy",
                      "/approve", "/reject")
        for name, (fn, _write, _schema) in M.TOOLS.items():
            src = inspect.getsource(fn)
            for route in privileged:
                self.assertNotIn(
                    route, src,
                    f"tool `{name}` references privileged route {route}")

    def test_module_never_imports_the_bank_itself(self):
        """In-process access would hand the model a writable `policies` table."""
        src = inspect.getsource(M)
        for forbidden in ("from .bank import", "from aibank.bank import",
                          "import sqlite3", "from .db import"):
            self.assertNotIn(forbidden, src)

    def test_every_tool_is_documented_and_schema_valid(self):
        for name, (_fn, _w, schema) in M.TOOLS.items():
            self.assertGreater(len(schema.get("description", "")), 20, name)
            self.assertEqual(schema["inputSchema"]["type"], "object", name)
            # Required fields must actually exist in properties, or a client
            # generates a call it cannot populate.
            props = schema["inputSchema"].get("properties", {})
            for req in schema["inputSchema"].get("required", []):
                self.assertIn(req, props, f"{name}.{req}")
            json.dumps(schema)  # must be serialisable as-is

    def test_pay_requires_an_idempotency_key(self):
        """Without it, a retrying agent double-pays. It must not be optional."""
        self.assertIn("idempotency_key",
                      M.TOOLS["pay"][2]["inputSchema"]["required"])

    def test_amount_is_typed_as_string_everywhere(self):
        """A JSON number would arrive as a float and lose minor units."""
        for name, (_fn, _w, schema) in M.TOOLS.items():
            amt = schema["inputSchema"].get("properties", {}).get("amount")
            if amt is not None:
                self.assertEqual(amt["type"], "string", name)

    def test_readonly_mode_drops_exactly_the_write_tools(self):
        writes = {n for n, t in M.TOOLS.items() if t[1]}
        self.assertEqual(writes, {"pay", "add_payee"})
        orig = M.READONLY
        try:
            M.READONLY = True
            self.assertEqual(set(M.visible_tools()), set(M.TOOLS) - writes)
        finally:
            M.READONLY = orig


class TestAmountParsing(unittest.TestCase):
    def test_float_is_refused(self):
        with self.assertRaises(M.ToolError):
            M._amount({"amount": 1000.55})

    def test_bool_is_refused(self):
        # bool is an int subclass; without an explicit check `True` becomes "1".
        with self.assertRaises(M.ToolError):
            M._amount({"amount": True})

    def test_string_and_int_pass_through_losslessly(self):
        self.assertEqual(M._amount({"amount": "2500.00"}), "2500.00")
        self.assertEqual(M._amount({"amount": 2500}), "2500")

    def test_missing_amount_explains_the_format(self):
        with self.assertRaises(M.ToolError) as cm:
            M._amount({})
        self.assertIn("MAJOR units", str(cm.exception))


class TestErrorGuidance(unittest.TestCase):
    """The denial text is a safety control: it is what stops a model looping."""

    def test_policy_denial_forbids_retry_and_splitting(self):
        msg = M._explain(403, {"reason": "per-transaction limit exceeded"})
        self.assertIn("Do not retry", msg)
        self.assertIn("split the amount", msg)
        self.assertIn("per-transaction limit exceeded", msg)

    def test_401_explains_the_trust_boundary(self):
        msg = M._explain(401, {"reason": "invalid session"})
        self.assertIn("human account", msg)

    def test_402_explains_holds(self):
        self.assertIn("held", M._explain(402, {"reason": "short"}))

    def test_unknown_status_still_reports_the_reason(self):
        self.assertIn("teapot", M._explain(418, {"reason": "teapot"}))


class TestCredentialRefusal(unittest.TestCase):
    def test_session_token_is_refused(self):
        os.environ["AIBANK_API_KEY"] = "sess_abc"
        try:
            with self.assertRaises(SystemExit) as cm:
                M.build_server()
            self.assertIn("agent api key", str(cm.exception))
        finally:
            os.environ.pop("AIBANK_API_KEY", None)

    def test_missing_key_is_refused(self):
        os.environ["AIBANK_API_KEY"] = ""
        try:
            with self.assertRaises(SystemExit):
                M.build_server()
        finally:
            os.environ.pop("AIBANK_API_KEY", None)


if __name__ == "__main__":
    unittest.main(verbosity=1)
