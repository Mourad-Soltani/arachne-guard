import json
import os
import tempfile
import unittest
from dataclasses import replace

from arachne_guard import (
    AgentCard, AuditLog, ConsentGate, Effect, Gateway, Policy, Rule, TrustStore,
    generate_keypair, matches, sign_card, validate_capability, verify_card,
)
from arachne_guard.gateway import PermissionDenied


def make_card(caps=("device.read:*",), agent_id="agent-a"):
    return AgentCard(agent_id=agent_id, name="A", version="1", capabilities=frozenset(caps))


def make_gateway(rules, approver=None, caps=("device.read:*",), agent_id="agent-a"):
    key = generate_keypair()
    card = sign_card(make_card(caps, agent_id), key)
    trust = TrustStore()
    trust.pin(card.agent_id, card.public_key)
    gw = Gateway(trust, Policy(rules), ConsentGate(approver))
    return gw, card, key


class CapabilityTests(unittest.TestCase):
    def test_valid_and_invalid(self):
        self.assertEqual(validate_capability("device.read:contacts"), "device.read:contacts")
        for bad in ("", "device", "Device.read", "device.read:", "device.*"):
            with self.assertRaises(ValueError):
                validate_capability(bad)

    def test_matching(self):
        self.assertTrue(matches("device.read:*", "device.read:contacts"))
        self.assertTrue(matches("*", "net.fetch:example.com"))
        self.assertFalse(matches("device.read:*", "device.write:contacts"))


class IdentityTests(unittest.TestCase):
    def test_sign_verify_roundtrip(self):
        card = sign_card(make_card(), generate_keypair())
        self.assertTrue(verify_card(card))
        self.assertTrue(verify_card(AgentCard.from_dict(json.loads(json.dumps(card.to_dict())))))

    def test_unsigned_rejected(self):
        self.assertFalse(verify_card(make_card()))

    def test_tamper_detected(self):
        card = sign_card(make_card(), generate_keypair())
        self.assertFalse(verify_card(replace(card, capabilities=frozenset({"device.write:*"}))))
        self.assertFalse(verify_card(replace(card, name="Evil")))

    def test_garbage_signature_rejected(self):
        card = sign_card(make_card(), generate_keypair())
        self.assertFalse(verify_card(replace(card, signature="not-base64!!")))
        self.assertFalse(verify_card(replace(card, signature="AAAA")))

    def test_wrong_key_rejected(self):
        a, b = sign_card(make_card(), generate_keypair()), sign_card(make_card(), generate_keypair())
        self.assertFalse(verify_card(replace(a, public_key=b.public_key)))

    def test_blank_id_rejected(self):
        with self.assertRaises(ValueError):
            AgentCard(agent_id=" ", name="x", version="1")

    def test_trust_pinning(self):
        trust = TrustStore()
        k1, k2 = generate_keypair(), generate_keypair()
        c1, c2 = sign_card(make_card(), k1), sign_card(make_card(), k2)
        trust.pin("agent-a", c1.public_key)
        self.assertTrue(trust.is_pinned(c1))
        self.assertFalse(trust.is_pinned(c2))
        with self.assertRaises(ValueError):
            trust.pin("agent-a", c2.public_key)
        self.assertTrue(trust.revoke("agent-a"))
        self.assertFalse(trust.is_pinned(c1))


class PolicyTests(unittest.TestCase):
    def test_default_deny(self):
        self.assertIs(Policy().evaluate("a", "device.read:x")[0], Effect.DENY)

    def test_deny_beats_ask_beats_allow(self):
        p = Policy([Rule(Effect.ALLOW, "device.*"), Rule(Effect.ASK, "device.read:*"),
                    Rule(Effect.DENY, "device.read:contacts")])
        self.assertIs(p.evaluate("a", "device.read:contacts")[0], Effect.DENY)
        self.assertIs(p.evaluate("a", "device.read:photos")[0], Effect.ASK)
        self.assertIs(p.evaluate("a", "device.write:photos")[0], Effect.ALLOW)

    def test_agent_scoping(self):
        p = Policy([Rule(Effect.ALLOW, "net.*", agent="trusted-*")])
        self.assertIs(p.evaluate("trusted-1", "net.fetch:x")[0], Effect.ALLOW)
        self.assertIs(p.evaluate("other", "net.fetch:x")[0], Effect.DENY)


class ConsentTests(unittest.TestCase):
    def test_no_approver_denies(self):
        self.assertFalse(ConsentGate().request("a", "device.read:x")[0])

    def test_approver_error_fails_closed(self):
        def boom(a, c):
            raise RuntimeError("ui crashed")
        self.assertFalse(ConsentGate(boom).request("a", "device.read:x")[0])

    def test_approve_and_deny(self):
        self.assertTrue(ConsentGate(lambda a, c: True).request("a", "c.d")[0])
        self.assertFalse(ConsentGate(lambda a, c: False).request("a", "c.d")[0])


class AuditTests(unittest.TestCase):
    def test_chain_verifies(self):
        log = AuditLog(clock=lambda: 1.0)
        for i in range(5):
            log.append("e", {"i": i})
        self.assertEqual(log.verify(), (True, None))

    def test_tamper_detected(self):
        log = AuditLog(clock=lambda: 1.0)
        for i in range(4):
            log.append("e", {"i": i})
        log._entries[2]["data"]["i"] = 99
        self.assertEqual(log.verify(), (False, 2))

    def test_prev_hash_field_tamper_detected(self):
        log = AuditLog(clock=lambda: 1.0)
        for i in range(3):
            log.append("e", {"i": i})
        log._entries[1]["prev_hash"] = "f" * 64
        self.assertEqual(log.verify(), (False, 1))

    def test_deletion_detected(self):
        log = AuditLog(clock=lambda: 1.0)
        for i in range(4):
            log.append("e", {"i": i})
        del log._entries[1]
        self.assertFalse(log.verify()[0])

    def test_persistence_and_reload(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            log = AuditLog(path)
            log.append("a", {"x": 1})
            log.append("b", {"x": 2})
            self.assertEqual(len(AuditLog(path).entries), 2)
            with open(path) as fh:
                lines = fh.read().splitlines()
            tampered = json.loads(lines[0])
            tampered["data"]["x"] = 7
            lines[0] = json.dumps(tampered, sort_keys=True)
            with open(path, "w") as fh:
                fh.write("\n".join(lines) + "\n")
            with self.assertRaises(ValueError):
                AuditLog(path)


class GatewayTests(unittest.TestCase):
    def test_allowed(self):
        gw, card, _ = make_gateway([Rule(Effect.ALLOW, "device.read:*")])
        self.assertTrue(gw.authorize(card, "device.read:contacts").allowed)

    def test_default_deny_without_rules(self):
        gw, card, _ = make_gateway([])
        self.assertFalse(gw.authorize(card, "device.read:contacts").allowed)

    def test_undeclared_capability_denied(self):
        gw, card, _ = make_gateway([Rule(Effect.ALLOW, "*")])
        d = gw.authorize(card, "device.write:contacts")
        self.assertFalse(d.allowed)
        self.assertIn("not declared", d.reason)

    def test_unsigned_and_unpinned_denied(self):
        gw, card, _ = make_gateway([Rule(Effect.ALLOW, "*")])
        self.assertFalse(gw.authorize(replace(card, signature=None), "device.read:x").allowed)
        forged = sign_card(make_card(), generate_keypair())  # valid sig, wrong key
        d = gw.authorize(forged, "device.read:x")
        self.assertFalse(d.allowed)
        self.assertIn("not pinned", d.reason)

    def test_tampered_card_denied(self):
        gw, card, _ = make_gateway([Rule(Effect.ALLOW, "*")])
        evil = replace(card, capabilities=frozenset({"*"}))
        self.assertFalse(gw.authorize(evil, "device.write:x").allowed)

    def test_invalid_capability_denied(self):
        gw, card, _ = make_gateway([Rule(Effect.ALLOW, "*")], caps=("*",))
        self.assertFalse(gw.authorize(card, "nonsense").allowed)

    def test_ask_flow(self):
        gw, card, _ = make_gateway([Rule(Effect.ASK, "device.read:*")], approver=lambda a, c: True)
        self.assertTrue(gw.authorize(card, "device.read:photos").allowed)
        gw2, card2, _ = make_gateway([Rule(Effect.ASK, "device.read:*")], approver=lambda a, c: False)
        self.assertFalse(gw2.authorize(card2, "device.read:photos").allowed)
        gw3, card3, _ = make_gateway([Rule(Effect.ASK, "device.read:*")])
        self.assertFalse(gw3.authorize(card3, "device.read:photos").allowed)

    def test_invoke_runs_only_when_allowed(self):
        gw, card, _ = make_gateway([Rule(Effect.ALLOW, "device.read:*")])
        self.assertEqual(gw.invoke(card, "device.read:contacts", lambda x: x * 2, 21), 42)
        calls = []
        with self.assertRaises(PermissionDenied):
            gw.invoke(card, "device.write:contacts", lambda: calls.append(1))
        self.assertEqual(calls, [])

    def test_invoke_error_audited_and_reraised(self):
        gw, card, _ = make_gateway([Rule(Effect.ALLOW, "device.read:*")])
        def boom():
            raise RuntimeError("x")
        with self.assertRaises(RuntimeError):
            gw.invoke(card, "device.read:a", boom)
        self.assertEqual(gw.audit.entries[-1]["event"], "invoke_error")

    def test_every_decision_audited_and_chain_intact(self):
        gw, card, _ = make_gateway([Rule(Effect.ALLOW, "device.read:*")])
        gw.authorize(card, "device.read:a")
        gw.authorize(card, "device.write:a")
        events = [e["data"]["allowed"] for e in gw.audit.entries]
        self.assertEqual(events, [True, False])
        self.assertTrue(gw.audit.verify()[0])


if __name__ == "__main__":
    unittest.main()
