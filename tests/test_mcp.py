import json
import os
import tempfile
import unittest

from arachne_guard import (
    AgentCard, ConsentGate, Effect, Gateway, McpGuard, Policy, RateLimiter, Rule, Tool,
    TrustStore, generate_keypair, load_policy, policy_from_dict, sign_card, tool_capability,
)
from arachne_guard.mcp import (
    INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PERMISSION_DENIED, RATE_LIMITED, INTERNAL,
)


def setup(rules, limiter=None, approver=None):
    key = generate_keypair()
    card = sign_card(AgentCard(agent_id="ag", name="ag", version="1",
                               capabilities=frozenset({"mcp.call:*"})), key)
    trust = TrustStore()
    trust.pin(card.agent_id, card.public_key)
    gw = Gateway(trust, Policy(rules), ConsentGate(approver))
    calls = []
    tools = [
        Tool("echo", "echo text", lambda text: calls.append(text) or text, required=["text"]),
        Tool("secret", "dangerous", lambda: "boom"),
        Tool("crash", "raises", lambda: 1 / 0),
        Tool("typeerr", "internal TypeError", lambda: len(5)),
    ]
    return McpGuard(gw, tools, limiter), card, gw, calls


def call(guard, card, name, args=None, rid=1):
    params = {"name": name}
    if args is not None:
        params["arguments"] = args
    return guard.handle({"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": params}, card)


class McpTests(unittest.TestCase):
    def test_list_hides_denied_tools(self):
        g, card, _, _ = setup([Rule(Effect.ALLOW, "mcp.call:*"), Rule(Effect.DENY, "mcp.call:secret")])
        r = g.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, card)
        self.assertEqual({t["name"] for t in r["result"]["tools"]}, {"echo", "crash", "typeerr"})

    def test_call_allowed(self):
        g, card, _, calls = setup([Rule(Effect.ALLOW, "mcp.call:echo")])
        r = call(g, card, "echo", {"text": "hi"})
        self.assertEqual(r["result"], {"content": "hi"})
        self.assertEqual(calls, ["hi"])

    def test_call_denied_never_runs(self):
        g, card, _, calls = setup([Rule(Effect.ALLOW, "mcp.call:secret")])
        r = call(g, card, "echo", {"text": "hi"})
        self.assertEqual(r["error"]["code"], PERMISSION_DENIED)
        self.assertEqual(calls, [])

    def test_ask_requires_consent(self):
        g, card, _, calls = setup([Rule(Effect.ASK, "mcp.call:echo")], approver=lambda a, c: False)
        self.assertEqual(call(g, card, "echo", {"text": "x"})["error"]["code"], PERMISSION_DENIED)
        g2, card2, _, _ = setup([Rule(Effect.ASK, "mcp.call:echo")], approver=lambda a, c: True)
        self.assertIn("result", call(g2, card2, "echo", {"text": "x"}))

    def test_protocol_errors(self):
        g, card, _, _ = setup([Rule(Effect.ALLOW, "*")])
        self.assertEqual(g.handle("nope", card)["error"]["code"], INVALID_REQUEST)
        self.assertEqual(g.handle({"jsonrpc": "1.0", "method": "x"}, card)["error"]["code"], INVALID_REQUEST)
        self.assertEqual(g.handle({"jsonrpc": "2.0", "id": 5, "method": "x"}, card)["error"]["code"], METHOD_NOT_FOUND)
        bad = g.handle({"jsonrpc": "2.0", "id": 6, "method": "tools/list", "params": [1]}, card)
        self.assertEqual(bad["error"]["code"], INVALID_PARAMS)
        self.assertEqual(call(g, card, "missing_tool")["error"]["code"], INVALID_PARAMS)
        self.assertEqual(call(g, card, "echo", {})["error"]["code"], INVALID_PARAMS)
        self.assertEqual(g.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                   "params": {"name": 5}}, card)["error"]["code"], INVALID_PARAMS)

    def test_request_id_echoed(self):
        g, card, _, _ = setup([Rule(Effect.ALLOW, "*")])
        self.assertEqual(call(g, card, "echo", {"text": "a"}, rid="abc")["id"], "abc")

    def test_unexpected_argument_is_invalid_params(self):
        g, card, _, _ = setup([Rule(Effect.ALLOW, "*")])
        r = call(g, card, "echo", {"text": "a", "extra": 1})
        self.assertEqual(r["error"]["code"], INVALID_PARAMS)

    def test_tool_crash_is_generic_internal_error(self):
        g, card, gw, _ = setup([Rule(Effect.ALLOW, "*")])
        r = call(g, card, "crash")
        self.assertEqual(r["error"], {"code": INTERNAL, "message": "tool failed"})
        self.assertEqual(gw.audit.entries[-1]["event"], "invoke_error")

    def test_internal_type_error_is_not_blamed_on_caller(self):
        g, card, _, _ = setup([Rule(Effect.ALLOW, "*")])
        self.assertEqual(call(g, card, "typeerr")["error"]["code"], INTERNAL)

    def test_rate_limit(self):
        t = [0.0]
        g, card, _, _ = setup([Rule(Effect.ALLOW, "*")], limiter=RateLimiter(2, 10, clock=lambda: t[0]))
        self.assertIn("result", call(g, card, "echo", {"text": "1"}))
        self.assertIn("result", call(g, card, "echo", {"text": "2"}))
        self.assertEqual(call(g, card, "echo", {"text": "3"})["error"]["code"], RATE_LIMITED)
        t[0] = 11.0
        self.assertIn("result", call(g, card, "echo", {"text": "4"}))

    def test_audit_records_arg_names_not_values(self):
        g, card, gw, _ = setup([Rule(Effect.ALLOW, "*")])
        call(g, card, "echo", {"text": "TOP-SECRET-VALUE"})
        self.assertNotIn("TOP-SECRET-VALUE", json.dumps(gw.audit.entries))
        self.assertTrue(gw.audit.verify()[0])

    def test_tool_validation(self):
        with self.assertRaises(ValueError):
            Tool("bad name!", "x", lambda: 1)
        with self.assertRaises(ValueError):
            McpGuard(setup([])[2], [Tool("a", "x", lambda: 1), Tool("a", "y", lambda: 2)])
        self.assertEqual(tool_capability("echo"), "mcp.call:echo")

    def test_unsigned_agent_blocked_end_to_end(self):
        g, card, _, calls = setup([Rule(Effect.ALLOW, "*")])
        from dataclasses import replace
        r = call(g, replace(card, signature=None), "echo", {"text": "x"})
        self.assertEqual(r["error"]["code"], PERMISSION_DENIED)
        self.assertEqual(calls, [])


class PolicyLoadTests(unittest.TestCase):
    def test_from_dict_and_file(self):
        data = {"default": "deny", "rules": [
            {"effect": "allow", "capability": "mcp.call:echo", "agent": "ag"},
            {"effect": "ask", "capability": "device.read:*", "reason": "needs consent"}]}
        p = policy_from_dict(data)
        self.assertIs(p.evaluate("ag", "mcp.call:echo")[0], Effect.ALLOW)
        self.assertIs(p.evaluate("x", "device.read:a")[0], Effect.ASK)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with open(path, "w") as fh:
                json.dump(data, fh)
            self.assertEqual(len(load_policy(path).rules), 2)

    def test_bad_rules_rejected(self):
        for bad in ({"rules": [{"effect": "maybe", "capability": "a.b"}]},
                    {"rules": [{"capability": "a.b"}]},
                    {"rules": [{"effect": "allow", "capability": "bad cap!"}]},
                    {"default": "perhaps"}):
            with self.assertRaises(ValueError):
                policy_from_dict(bad)


class RateLimiterTests(unittest.TestCase):
    def test_args_validated_and_keys_independent(self):
        with self.assertRaises(ValueError):
            RateLimiter(0, 1)
        with self.assertRaises(ValueError):
            RateLimiter(1, 0)
        rl = RateLimiter(1, 10, clock=lambda: 0.0)
        self.assertTrue(rl.allow("a"))
        self.assertFalse(rl.allow("a"))
        self.assertTrue(rl.allow("b"))


if __name__ == "__main__":
    unittest.main()
