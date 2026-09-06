"""Tests for X25519 public key fingerprints used in identity pinning.

Fingerprints are short, stable hashes of raw public keys. They let two
agents confirm "I'm talking to the same identity as before" without
showing the full 32-byte key in chat. This module tests:

  * deterministic output for the same key
  * different output for different keys
  * format: lowercase hex, 64 chars (SHA-256 over the 32-byte raw key)
  * round-trip via the high-level helper in keys.py
"""

import os
import sys
import unittest

# Allow `python tests/test_key_fingerprint.py` from repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from e2e.keys import (
    generate_keypair,
    fingerprint,
    fingerprint_from_hex,
    PUB_KEY_SIZE,
)


class TestFingerprintFormat(unittest.TestCase):
    def test_fingerprint_is_64_lowercase_hex(self):
        priv, pub = generate_keypair()
        fp = fingerprint(pub)
        self.assertEqual(len(fp), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp))

    def test_fingerprint_matches_raw_bytes(self):
        priv, pub = generate_keypair()
        self.assertEqual(fingerprint(pub), fingerprint(pub.encode("ascii")))

    def test_fingerprint_rejects_wrong_size(self):
        with self.assertRaises(ValueError):
            fingerprint(b"short")
        with self.assertRaises(ValueError):
            fingerprint(b"x" * (PUB_KEY_SIZE - 1))
        with self.assertRaises(ValueError):
            fingerprint(b"x" * (PUB_KEY_SIZE + 1))

    def test_fingerprint_from_hex_matches_bytes(self):
        priv, pub = generate_keypair()
        self.assertEqual(fingerprint(pub), fingerprint_from_hex(pub.hex()))

    def test_fingerprint_from_hex_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            fingerprint_from_hex("not-hex!")
        with self.assertRaises(ValueError):
            fingerprint_from_hex("ab" * 16)  # 32 hex chars but only 16 bytes


class TestFingerprintStability(unittest.TestCase):
    def test_same_key_same_fingerprint(self):
        priv, pub = generate_keypair()
        self.assertEqual(fingerprint(pub), fingerprint(pub))

    def test_different_keys_different_fingerprints(self):
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        self.assertNotEqual(fingerprint(pub1), fingerprint(pub2))

    def test_collisions_unlikely_for_n_small(self):
        # Sanity: 1000 random keys should produce 1000 distinct fingerprints.
        fps = {fingerprint(generate_keypair()[1]) for _ in range(1000)}
        self.assertEqual(len(fps), 1000)


class TestFingerprintVisual(unittest.TestCase):
    def test_common_formatting_helpers(self):
        priv, pub = generate_keypair()
        fp = fingerprint(pub)
        # Grouped form: "xxxx:xxxx:...:xxxx" in 8-char chunks.
        grouped = ":".join(fp[i : i + 8] for i in range(0, 64, 8))
        self.assertEqual(grouped.count(":"), 7)
        # Compact form has no separators.
        self.assertNotIn(":", fp)


if __name__ == "__main__":
    unittest.main(verbosity=2)

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
