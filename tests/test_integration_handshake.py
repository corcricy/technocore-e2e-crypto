"""
Integration test exercising a full end-to-end encrypted handshake and message
exchange between two parties (Alice and Bob). Validates the X25519+HKDF+AESGCM
pipeline defined in docs/protocol-spec.md against the patterns in patterns.md.

The test uses both Session and KeyFingerprint modules together. It does NOT
mock the cryptographic primitives — everything is real Cryptography library
calls — so a regression in key derivation, nonce construction, or AEAD
auth-tag verification surfaces immediately.

Run with: pytest tests/test_integration_handshake.py -v
"""

from __future__ import annotations

import os
import sys
import unittest

# Allow running this test file directly from the repo root.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from e2e.session import (  # noqa: E402
    Session,
    SessionError,
    HandshakeError,
    decrypt_message,
)
from e2e.key_fingerprint import (  # noqa: E402
    fingerprint_from_public_key,
    fingerprint_matches,
)


def _make_session(name: str) -> Session:
    """Factory that constructs a fresh Session for a party."""
    return Session.generate(local_label=name)


class FullHandshakeIntegration(unittest.TestCase):
    """End-to-end exercise: key exchange, fingerprint verification, transport."""

    def setUp(self) -> None:
        self.alice = _make_session("alice@example.com")
        self.bob = _make_session("bob@example.com")

    # ---- Handshake -------------------------------------------------------

    def test_mutual_handshake_produces_matching_symmetric_keys(self) -> None:
        """Both sides must derive the same 32-byte traffic key."""
        alice_pub = self.alice.public_bytes()
        bob_pub = self.bob.public_bytes()

        self.alice.complete_handshake(peer_public_bytes=bob_pub)
        self.bob.complete_handshake(peer_public_bytes=alice_pub)

        self.assertTrue(self.alice.is_ready())
        self.assertTrue(self.bob.is_ready())

        self.assertEqual(
            self.alice.export_traffic_key(),
            self.bob.export_traffic_key(),
            "Derived traffic keys must match between peers",
        )

    def test_fingerprints_match_before_exchanging_data(self) -> None:
        """Out-of-band fingerprint comparison is the authentication step."""
        alice_fp = fingerprint_from_public_key(self.alice.public_bytes())
        bob_fp = fingerprint_from_public_key(self.bob.public_bytes())

        # In a real deployment Alice and Bob read these aloud / scan a QR.
        # Here we assert the helper agrees with a direct comparison.
        self.assertTrue(fingerprint_matches(alice_fp, alice_fp))
        self.assertTrue(fingerprint_matches(bob_fp, bob_fp))
        self.assertFalse(
            fingerprint_matches(alice_fp, bob_fp),
            "Distinct identities must produce distinct fingerprints",
        )

    # ---- Transport -------------------------------------------------------

    def test_bidirectional_encrypted_message_exchange(self) -> None:
        """Alice -> Bob and Bob -> Alice messages round-trip cleanly."""
        self.alice.complete_handshake(peer_public_bytes=self.bob.public_bytes())
        self.bob.complete_handshake(peer_public_bytes=self.alice.public_bytes())

        plaintext_a_to_b = b"hello bob, this is alice \u2728"
        plaintext_b_to_a = b"ack alice, message received \u2713"

        ct1 = self.alice.encrypt(plaintext_a_to_b)
        ct2 = self.bob.encrypt(plaintext_b_to_a)

        self.assertNotIn(plaintext_a_to_b, ct1)
        self.assertNotIn(plaintext_b_to_a, ct2)

        recovered_b = self.bob.decrypt(ct1)
        recovered_a = self.alice.decrypt(ct2)

        self.assertEqual(recovered_b, plaintext_a_to_b)
        self.assertEqual(recovered_a, plaintext_b_to_a)

    def test_tampered_ciphertext_is_rejected(self) -> None:
        """Flipping a single byte in the ciphertext must fail AEAD verification."""
        self.alice.complete_handshake(peer_public_bytes=self.bob.public_bytes())
        self.bob.complete_handshake(peer_public_bytes=self.alice.public_bytes())

        ciphertext = self.alice.encrypt(b"integrity matters")
        tampered = bytearray(ciphertext)
        tampered[len(tampered) // 2] ^= 0x01  # flip one bit
        tampered = bytes(tampered)

        with self.assertRaises(SessionError):
            self.bob.decrypt(tampered)

    def test_standalone_decrypt_helper_matches_session_decrypt(self) -> None:
        """The convenience decrypt_message() helper must interoperate."""
        self.alice.complete_handshake(peer_public_bytes=self.bob.public_bytes())
        self.bob.complete_handshake(peer_public_bytes=self.alice.public_bytes())

        ciphertext = self.alice.encrypt(b"helper parity check")

        via_helper = decrypt_message(
            session=self.bob,
            ciphertext=ciphertext,
        )
        via_method = self.bob.decrypt(ciphertext)

        self.assertEqual(via_helper, via_method)
        self.assertEqual(via_helper, b"helper parity check")

    # ---- Negative paths ---------------------------------------------------

    def test_calling_encrypt_before_handshake_raises(self) -> None:
        """Pre-handshake encrypt attempts must fail loudly, not silently."""
        with self.assertRaises(HandshakeError):
            self.alice.encrypt(b"too early")

    def test_invalid_peer_public_key_is_rejected(self) -> None:
        """Malformed peer key bytes must raise HandshakeError, not crash."""
        with self.assertRaises(HandshakeError):
            self.alice.complete_handshake(peer_public_bytes=b"\x00" * 5)


if __name__ == "__main__":
    unittest.main()

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
