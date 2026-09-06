"""Tests for HKDF-based key derivation in the X25519+HKDF+AESGCM E2E crypto layer.

These tests exercise the helper that turns the raw 32-byte X25519 shared secret
into a pair of direction-specific 32-byte AES-GCM keys using HKDF-SHA-256
with an application-specific info string and optional salt.

The reference for the derivation is patterns.md::"Key Schedule".
"""

from __future__ import annotations

import hashlib
import hmac
import os
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from seal_scribe.keys import (
    HKDF_INFO,
    derive_session_keys,
    fingerprint_pubkey,
    normalize_info,
)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Tiny RFC 5869 HKDF-SHA-256 implementation used as an oracle."""
    if salt == b"":
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


class NormalizeInfoTests(unittest.TestCase):
    def test_bytes_passthrough(self) -> None:
        self.assertEqual(normalize_info(b"technocore/v1"), b"technocore/v1")

    def test_str_encoded(self) -> None:
        self.assertEqual(normalize_info("technocore/v1"), b"technocore/v1")

    def test_rejects_non_ascii_str(self) -> None:
        with self.assertRaises(ValueError):
            normalize_info("\u00e9")

    def test_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            normalize_info(b"")


class DeriveSessionKeysTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alice_priv = X25519PrivateKey.generate()
        self.bob_priv = X25519PrivateKey.generate()
        self.alice_pub = self.alice_priv.public_key().public_bytes_raw()
        self.bob_pub = self.bob_priv.public_key().public_bytes_raw()

        # ECDH shared secret is identical from either side.
        self.shared = self.alice_priv.exchange(X25519PublicKey.from_public_bytes(self.bob_pub))
        self.assertEqual(
            self.shared,
            self.bob_priv.exchange(X25519PublicKey.from_public_bytes(self.alice_pub)),
        )

    def test_keys_are_32_bytes_each(self) -> None:
        k_send, k_recv = derive_session_keys(self.shared, self.alice_pub, self.bob_pub, role="initiator")
        self.assertEqual(len(k_send), 32)
        self.assertEqual(len(k_recv), 32)

    def test_initiator_and_responder_keys_mirror(self) -> None:
        a_send, a_recv = derive_session_keys(self.shared, self.alice_pub, self.bob_pub, role="initiator")
        b_send, b_recv = derive_session_keys(self.shared, self.alice_pub, self.bob_pub, role="responder")
        # What Alice sends, Bob receives.
        self.assertEqual(a_send, b_recv)
        # What Bob sends, Alice receives.
        self.assertEqual(b_send, a_recv)
        # And the two directions are distinct.
        self.assertNotEqual(a_send, a_recv)

    def test_matches_rfc5869_oracle(self) -> None:
        salt = os.urandom(32)
        k_send, k_recv = derive_session_keys(
            self.shared, self.alice_pub, self.bob_pub, role="initiator", salt=salt
        )
        # Reconstruct what the helper should be doing internally.
        info_send = HKDF_INFO + b"\x00" + self.alice_pub + b"\x00" + self.bob_pub + b"\x01send"
        info_recv = HKDF_INFO + b"x00" + self.alice_pub + b"x00" + self.bob_pub + b"x01recv"
        expected_send = hkdf_sha256(self.shared, salt, info_send, 32)
        expected_recv = hkdf_sha256(self.shared, salt, info_recv, 32)
        self.assertEqual(k_send, expected_send)
        self.assertEqual(k_recv, expected_recv)

    def test_salt_changes_output(self) -> None:
        k1, _ = derive_session_keys(self.shared, self.alice_pub, self.bob_pub, role="initiator")
        k2, _ = derive_session_keys(
            self.shared, self.alice_pub, self.bob_pub, role="initiator", salt=b"domain-xyz"
        )
        self.assertNotEqual(k1, k2)

    def test_role_must_be_known(self) -> None:
        with self.assertRaises(ValueError):
            derive_session_keys(self.shared, self.alice_pub, self.bob_pub, role="middleman")

    def test_short_shared_secret_rejected(self) -> None:
        with self.assertRaises(ValueError):
            derive_session_keys(b"short", self.alice_pub, self.bob_pub, role="initiator")

    def test_keys_bound_to_pubkey_order(self) -> None:
        # Swapping the pubkey order must change the derived keys (context binding).
        a_send, _ = derive_session_keys(self.shared, self.alice_pub, self.bob_pub, role="initiator")
        b_send, _ = derive_session_keys(self.shared, self.bob_pub, self.alice_pub, role="initiator")
        self.assertNotEqual(a_send, b_send)


class FingerprintPubkeyTests(unittest.TestCase):
    def test_fingerprint_is_32_hex_chars(self) -> None:
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        fp = fingerprint_pubkey(pub)
        self.assertEqual(len(fp), 32)
        int(fp, 16)  # parses as hex

    def test_fingerprint_is_stable(self) -> None:
        priv = X25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw()
        self.assertEqual(fingerprint_pubkey(pub), fingerprint_pubkey(pub))

    def test_fingerprint_differs_per_key(self) -> None:
        a = X25519PrivateKey.generate().public_key().public_bytes_raw()
        b = X25519PrivateKey.generate().public_key().public_bytes_raw()
        self.assertNotEqual(fingerprint_pubkey(a), fingerprint_pubkey(b))


if __name__ == "__main__":
    unittest.main()

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
