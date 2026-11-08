import json
import os
import stat
import tempfile
import unittest
from dataclasses import replace

from arachne_guard import (
    AgentCard, ConsentGate, Effect, Gateway, Policy, Rule, TrustStore,
    generate_keypair, public_key_b64, sign_card, sign_rotation,
)


def card_for(key, agent_id="ag"):
    return sign_card(AgentCard(agent_id=agent_id, name="n", version="1",
                               capabilities=frozenset({"device.read:*"})), key)


class TrustPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "trust.json")
        self.addCleanup(self.dir.cleanup)

    def test_pins_survive_restart(self):
        key = generate_keypair()
        c = card_for(key)
        TrustStore(self.path).pin("ag", c.public_key)
        self.assertTrue(TrustStore(self.path).is_pinned(c))

    def test_file_is_private(self):
        TrustStore(self.path).pin("ag", public_key_b64(generate_keypair()))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_no_temp_files_left_behind(self):
        ts = TrustStore(self.path)
        ts.pin("ag", public_key_b64(generate_keypair()))
        self.assertEqual(os.listdir(self.dir.name), ["trust.json"])

    def test_corrupt_file_fails_loudly(self):
        for bad in ("not json", "{}", '{"pins": [], "counters": {}, "revoked": []}',
                    '{"pins": {"a": "AAAA"}, "counters": {}, "revoked": []}'):
            with open(self.path, "w") as fh:
                fh.write(bad)
            with self.assertRaises(ValueError):
                TrustStore(self.path)

    def test_revocation_is_permanent_and_persisted(self):
        key = generate_keypair()
        c = card_for(key)
        ts = TrustStore(self.path)
        ts.pin("ag", c.public_key)
        self.assertTrue(ts.revoke("ag"))
        again = TrustStore(self.path)
        self.assertTrue(again.is_revoked("ag"))
        self.assertFalse(again.is_pinned(c))
        with self.assertRaises(ValueError):
            again.pin("ag", c.public_key)

    def test_revoking_unknown_agent_blocks_future_pin(self):
        ts = TrustStore()
        self.assertFalse(ts.revoke("ghost"))
        with self.assertRaises(ValueError):
            ts.pin("ghost", public_key_b64(generate_keypair()))


class RotationTests(unittest.TestCase):
    def setup_pinned(self, path=None):
        old = generate_keypair()
        ts = TrustStore(path)
        ts.pin("ag", public_key_b64(old))
        return ts, old

    def test_valid_rotation(self):
        ts, old = self.setup_pinned()
        new = generate_keypair()
        sig = sign_rotation(old, "ag", public_key_b64(new), 1)
        ts.rotate("ag", public_key_b64(new), 1, sig)
        self.assertTrue(ts.is_pinned(card_for(new)))
        self.assertFalse(ts.is_pinned(card_for(old)))

    def test_rotation_signed_by_wrong_key_rejected(self):
        ts, old = self.setup_pinned()
        new, attacker = generate_keypair(), generate_keypair()
        sig = sign_rotation(attacker, "ag", public_key_b64(new), 1)
        with self.assertRaises(ValueError):
            ts.rotate("ag", public_key_b64(new), 1, sig)
        self.assertTrue(ts.is_pinned(card_for(old)))

    def test_signature_bound_to_new_key_agent_and_counter(self):
        ts, old = self.setup_pinned()
        new, other = generate_keypair(), generate_keypair()
        sig = sign_rotation(old, "ag", public_key_b64(new), 1)
        with self.assertRaises(ValueError):
            ts.rotate("ag", public_key_b64(other), 1, sig)      # swapped new key
        with self.assertRaises(ValueError):
            ts.rotate("ag", public_key_b64(new), 2, sig)        # altered counter
        TrustStore().pin("other", public_key_b64(old))
        ts2 = TrustStore()
        ts2.pin("other", public_key_b64(old))
        with self.assertRaises(ValueError):
            ts2.rotate("other", public_key_b64(new), 1, sig)    # statement for a different agent

    def test_replay_and_rollback_rejected(self):
        ts, k0 = self.setup_pinned()
        k1, k2 = generate_keypair(), generate_keypair()
        s1 = sign_rotation(k0, "ag", public_key_b64(k1), 1)
        ts.rotate("ag", public_key_b64(k1), 1, s1)
        s2 = sign_rotation(k1, "ag", public_key_b64(k2), 2)
        ts.rotate("ag", public_key_b64(k2), 2, s2)
        with self.assertRaises(ValueError):
            ts.rotate("ag", public_key_b64(k1), 1, s1)  # replay of old statement
        self.assertTrue(ts.is_pinned(card_for(k2)))

    def test_replay_after_rotating_back_to_original_key(self):
        # A -> B -> A: the first statement is validly signed by A and A is pinned
        # again, so only the stored counter stops an attacker replaying it.
        ts, a = self.setup_pinned()
        b = generate_keypair()
        s1 = sign_rotation(a, "ag", public_key_b64(b), 1)
        ts.rotate("ag", public_key_b64(b), 1, s1)
        ts.rotate("ag", public_key_b64(a), 2, sign_rotation(b, "ag", public_key_b64(a), 2))
        self.assertTrue(ts.is_pinned(card_for(a)))
        with self.assertRaises(ValueError):
            ts.rotate("ag", public_key_b64(b), 1, s1)
        self.assertTrue(ts.is_pinned(card_for(a)))

    def test_counter_must_exceed_even_if_signature_valid(self):
        ts, k0 = self.setup_pinned()
        k1 = generate_keypair()
        sig = sign_rotation(k0, "ag", public_key_b64(k1), 0)
        with self.assertRaises(ValueError):
            ts.rotate("ag", public_key_b64(k1), 0, sig)

    def test_rotate_unpinned_or_revoked_rejected(self):
        ts = TrustStore()
        k = generate_keypair()
        with self.assertRaises(ValueError):
            ts.rotate("nobody", public_key_b64(k), 1, "AAAA")
        ts.pin("ag", public_key_b64(k))
        ts.revoke("ag")
        with self.assertRaises(ValueError):
            ts.rotate("ag", public_key_b64(k), 1, sign_rotation(k, "ag", public_key_b64(k), 1))

    def test_garbage_new_key_rejected(self):
        ts, old = self.setup_pinned()
        with self.assertRaises(ValueError):
            ts.rotate("ag", "AAAA", 1, sign_rotation(old, "ag", "AAAA", 1))

    def test_rotation_persists_with_counter(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.json")
            ts, old = self.setup_pinned(path)
            new = generate_keypair()
            sig = sign_rotation(old, "ag", public_key_b64(new), 1)
            ts.rotate("ag", public_key_b64(new), 1, sig)
            reloaded = TrustStore(path)
            self.assertTrue(reloaded.is_pinned(card_for(new)))
            with self.assertRaises(ValueError):
                reloaded.rotate("ag", public_key_b64(new), 1, sig)  # counter survived restart

    def test_gateway_rejects_old_key_after_rotation(self):
        ts, old = self.setup_pinned()
        new = generate_keypair()
        ts.rotate("ag", public_key_b64(new), 1, sign_rotation(old, "ag", public_key_b64(new), 1))
        gw = Gateway(ts, Policy([Rule(Effect.ALLOW, "*")]), ConsentGate())
        self.assertFalse(gw.authorize(card_for(old), "device.read:x").allowed)
        self.assertTrue(gw.authorize(card_for(new), "device.read:x").allowed)

    def test_gateway_rejects_revoked_agent(self):
        ts, old = self.setup_pinned()
        ts.revoke("ag")
        gw = Gateway(ts, Policy([Rule(Effect.ALLOW, "*")]), ConsentGate())
        self.assertFalse(gw.authorize(card_for(old), "device.read:x").allowed)


if __name__ == "__main__":
    unittest.main()
