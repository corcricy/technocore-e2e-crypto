"""Tests for technocore-e2e-crypto.

Run with: python -m pytest tests/ -v
or: python tests/test_crypto.py

These tests verify the X25519 + HKDF-SHA256 + AES-256-GCM construction
documented in patterns.md, including round-trip encrypt/decrypt, tamper
detection, key uniqueness, and the full session handshake simulation.
"""

import os
import sys
import unittest

# Allow running this file directly from the repo root.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from e2e.crypto import (
    generate_keypair,
    public_key_bytes,
    derive_shared_key,
    encrypt_message,
    decrypt_message,
    build_envelope,
    open_envelope,
    CryptoError,
    AuthError,
)


class TestKeyAgreement(unittest.TestCase):
    def test_keypairs_are_unique(self):
        keys = {generate_keypair().private for _ in range(20)}
        self.assertEqual(len(keys), 20)

    def test_public_key_bytes_length(self):
        kp = generate_keypair()
        self.assertEqual(len(public_key_bytes(kp.public)), 32)

    def test_shared_keys_match(self):
        a = generate_keypair()
        b = generate_keypair()
        s_ab = derive_shared_key(a.private, b.public)
        s_ba = derive_shared_key(b.private, a.public)
        self.assertEqual(s_ab, s_ba)
        self.assertEqual(len(s_ab), 32)  # 256-bit session key


class TestRoundTrip(unittest.TestCase):
    def setUp(self):
        self.alice = generate_keypair()
        self.bob = generate_keypair()
        self.session_key = derive_shared_key(self.alice.private, self.bob.public)

    def test_encrypt_decrypt_low_level(self):
        plaintext = b"hello bob"
        nonce, ct = encrypt_message(self.session_key, plaintext)
        self.assertEqual(len(nonce), 12)
        self.assertNotIn(plaintext, ct)
        pt = decrypt_message(self.session_key, nonce, ct)
        self.assertEqual(pt, plaintext)

    def test_encrypt_decrypt_envelope(self):
        plaintext = b"hello bob, this is a longer message with unicode \xe2\x9c\x93"
        envelope = build_envelope(self.session_key, plaintext)
        # Envelope should be opaque bytes, larger than plaintext.
        self.assertIsInstance(envelope, (bytes, bytearray))
        self.assertGreater(len(envelope), len(plaintext))
        pt = open_envelope(self.session_key, bytes(envelope))
        self.assertEqual(pt, plaintext)

    def test_nonce_is_random(self):
        plaintext = b"same plaintext twice"
        n1, c1 = encrypt_message(self.session_key, plaintext)
        n2, c2 = encrypt_message(self.session_key, plaintext)
        self.assertNotEqual(n1, n2)
        self.assertNotEqual(c1, c2)

    def test_aad_is_bound(self):
        # If AAD differs at decrypt time, auth must fail.
        plaintext = b"signed payload"
        aad = b"context:v1"
        nonce, ct = encrypt_message(self.session_key, plaintext, aad=aad)
        with self.assertRaises((AuthError, CryptoError, ValueError)):
            decrypt_message(self.session_key, nonce, ct, aad=b"context:v2")


class TestTamperDetection(unittest.TestCase):
    def setUp(self):
        self.session_key = derive_shared_key(
            generate_keypair().private, generate_keypair().public
        )

    def test_tampered_ciphertext_rejected(self):
        nonce, ct = encrypt_message(self.session_key, b"important data")
        tampered = bytearray(ct)
        tampered[0] ^= 0x01
        with self.assertRaises((AuthError, CryptoError, ValueError)):
            decrypt_message(self.session_key, nonce, bytes(tampered))

    def test_tampered_nonce_rejected(self):
        nonce, ct = encrypt_message(self.session_key, b"important data")
        bad_nonce = bytearray(nonce)
        bad_nonce[0] ^= 0x01
        with self.assertRaises((AuthError, CryptoError, ValueError)):
            decrypt_message(self.session_key, bytes(bad_nonce), ct)

    def test_wrong_key_rejected(self):
        nonce, ct = encrypt_message(self.session_key, b"secret")
        wrong_key = derive_shared_key(
            generate_keypair().private, generate_keypair().public
        )
        with self.assertRaises((AuthError, CryptoError, ValueError)):
            decrypt_message(wrong_key, nonce, ct)


class TestSessionSimulation(unittest.TestCase):
    """End-to-end Alice <-> Bob session as described in patterns.md."""

    def test_full_handshake_and_exchange(self):
        alice = generate_keypair()
        bob = generate_keypair()

        # Each side derives the same shared secret from the other's pubkey.
        alice_key = derive_shared_key(alice.private, bob.public)
        bob_key = derive_shared_key(bob.private, alice.public)
        self.assertEqual(alice_key, bob_key)

        # Alice sends several messages to Bob.
        messages = [
            b"hi bob",
            b"are you there?",
            b"\xe2\x9c\x93 ready",
            b"\x00\x01\x02\x03 binary safe",
            b"" ,  # empty message
        ]
        envelopes = [build_envelope(alice_key, m) for m in messages]

        # Bob decrypts them in order.
        for env, original in zip(envelopes, messages):
            self.assertEqual(open_envelope(bob_key, env), original)

        # Replaying an old envelope should still decrypt (sessions are stateful
        # w.r.t. replay in this minimal API; that is the caller's job per
        # patterns.md). We just assert the decryption is consistent.
        self.assertEqual(open_envelope(bob_key, envelopes[0]), messages[0])

    def test_role_symmetry(self):
        """Either party can encrypt to the other with the same derived key."""
        alice = generate_keypair()
        bob = generate_keypair()
        key = derive_shared_key(alice.private, bob.public)

        a_to_b = build_envelope(key, b"ping")
        b_to_a = build_envelope(key, b"pong")

        self.assertEqual(open_envelope(key, a_to_b), b"ping")
        self.assertEqual(open_envelope(key, b_to_a), b"pong")


if __name__ == "__main__":
    unittest.main(verbosity=2)

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
