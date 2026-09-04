"""Tests for e2e/keys.py — X25519 key pair generation, fingerprinting, and shared-secret derivation.

These tests complement tests/test_crypto.py by focusing on the key-management layer:
key pair determinism, public-key fingerprint stability, and HKDF-based shared secret
derivation between two parties.
"""

import os
import sys
import unittest

# Make the repo importable when running ``python -m unittest`` from the project root.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from e2e import keys  # noqa: E402


class TestKeyPairGeneration(unittest.TestCase):
    def test_generate_returns_keypair(self):
        kp = keys.generate_keypair()
        self.assertTrue(hasattr(kp, "private_bytes"))
        self.assertTrue(hasattr(kp, "public_bytes"))
        self.assertEqual(len(kp.private_bytes), 32)
        self.assertEqual(len(kp.public_bytes), 32)

    def test_generate_produces_unique_pairs(self):
        a = keys.generate_keypair()
        b = keys.generate_keypair()
        self.assertNotEqual(a.private_bytes, b.private_bytes)
        self.assertNotEqual(a.public_bytes, b.public_bytes)


class TestPublicKeyFingerprint(unittest.TestCase):
    def test_fingerprint_is_32_bytes(self):
        kp = keys.generate_keypair()
        fp = keys.fingerprint(kp.public_bytes)
        self.assertIsInstance(fp, bytes)
        self.assertEqual(len(fp), 32)

    def test_fingerprint_is_stable(self):
        kp = keys.generate_keypair()
        fp1 = keys.fingerprint(kp.public_bytes)
        fp2 = keys.fingerprint(kp.public_bytes)
        self.assertEqual(fp1, fp2)

    def test_fingerprint_differs_for_different_keys(self):
        a = keys.generate_keypair()
        b = keys.generate_keypair()
        self.assertNotEqual(keys.fingerprint(a.public_bytes), keys.fingerprint(b.public_bytes))


class TestSharedSecretDerivation(unittest.TestCase):
    def test_shared_secret_is_symmetric(self):
        alice = keys.generate_keypair()
        bob = keys.generate_keypair()
        s_ab = keys.derive_shared_secret(alice.private_bytes, bob.public_bytes)
        s_ba = keys.derive_shared_secret(bob.private_bytes, alice.public_bytes)
        self.assertEqual(s_ab, s_ba)
        self.assertEqual(len(s_ab), 32)

    def test_shared_secret_differs_per_pair(self):
        alice = keys.generate_keypair()
        bob = keys.generate_keypair()
        carol = keys.generate_keypair()
        s_ab = keys.derive_shared_secret(alice.private_bytes, bob.public_bytes)
        s_ac = keys.derive_shared_secret(alice.private_bytes, carol.public_bytes)
        self.assertNotEqual(s_ab, s_ac)

    def test_derive_with_context(self):
        """Deriving with an explicit HKDF context (salt/info) must change the output."""
        alice = keys.generate_keypair()
        bob = keys.generate_keypair()
        s_default = keys.derive_shared_secret(
            alice.private_bytes, bob.public_bytes, context="default"
        )
        s_chat = keys.derive_shared_secret(
            alice.private_bytes, bob.public_bytes, context="chat-v1"
        )
        s_default_sym = keys.derive_shared_secret(
            bob.private_bytes, alice.public_bytes, context="default"
        )
        self.assertNotEqual(s_default, s_chat)
        self.assertEqual(s_default, s_default_sym)


class TestKeyPairSerialization(unittest.TestCase):
    def test_private_and_public_bytes_are_distinct(self):
        kp = keys.generate_keypair()
        self.assertNotEqual(kp.private_bytes, kp.public_bytes)


if __name__ == "__main__":
    unittest.main()

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
