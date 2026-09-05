"""Tests for e2e/key_fingerprint.py.

The key fingerprint is a short, human-shareable identifier for a long-term
X25519 public key. It is derived by hashing the canonical public-key bytes
with SHA-256 and formatting the result as colon-separated hex groups so that
two parties can compare fingerprints out-of-band (e.g. over a voice call)
to detect MITM attempts.

These tests verify:
  * deterministic output for a given key
  * correct length and grouping format
  * stability under canonical encoding (raw 32 bytes)
  * sensitivity to single-bit changes in the key
  * fingerprint uniqueness for distinct keys
  * parsing back into bytes round-trips losslessly
"""

import os
import unittest

from e2e.key_fingerprint import (
    compute_fingerprint,
    format_fingerprint,
    parse_fingerprint,
    fingerprint_distance,
    FINGERPRINT_BYTES,
)


def _random_key() -> bytes:
    """Generate a random 32-byte X25519 public key for testing."""
    return os.urandom(32)


class TestFormatFingerprint(unittest.TestCase):
    def test_default_length_is_32_bytes(self):
        self.assertEqual(FINGERPRINT_BYTES, 32)

    def test_format_default_groups(self):
        key = _random_key()
        fp = compute_fingerprint(key)
        parts = fp.split(":")
        # SHA-256 = 32 bytes = 64 hex chars; default grouping is 4 hex chars.
        self.assertEqual(len(parts), 16)
        for part in parts:
            self.assertEqual(len(part), 4)
            int(part, 16)  # raises if non-hex

    def test_format_custom_group_size(self):
        key = _random_key()
        fp = format_fingerprint(key, group_size=8)
        parts = fp.split(":")
        self.assertEqual(len(parts), 8)
        for part in parts:
            self.assertEqual(len(part), 8)

    def test_format_invalid_group_size_raises(self):
        key = _random_key()
        with self.assertRaises(ValueError):
            format_fingerprint(key, group_size=3)  # not a divisor of hex length
        with self.assertRaises(ValueError):
            format_fingerprint(key, group_size=0)

    def test_format_uppercase(self):
        key = _random_key()
        fp = format_fingerprint(key, uppercase=True)
        self.assertEqual(fp, fp.upper())


class TestComputeFingerprint(unittest.TestCase):
    def test_deterministic(self):
        key = _random_key()
        self.assertEqual(compute_fingerprint(key), compute_fingerprint(key))

    def test_known_vector(self):
        # SHA-256("abc") == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        # We don't feed a string here; instead use an all-zero key and confirm
        # the digest matches sha256(32 zero bytes).
        import hashlib
        key = b"\x00" * 32
        expected = hashlib.sha256(key).hexdigest()
        fp = compute_fingerprint(key)
        self.assertEqual(fp.replace(":", "").lower(), expected)

    def test_sensitive_to_bit_flip(self):
        key = _random_key()
        fp1 = compute_fingerprint(key)
        flipped = bytearray(key)
        flipped[0] ^= 0x01
        fp2 = compute_fingerprint(bytes(flipped))
        self.assertNotEqual(fp1, fp2)

    def test_distinct_keys_distinct_fingerprints(self):
        fps = {compute_fingerprint(_random_key()) for _ in range(50)}
        self.assertEqual(len(fps), 50)

    def test_wrong_length_key_rejected(self):
        with self.assertRaises(ValueError):
            compute_fingerprint(b"too short")
        with self.assertRaises(ValueError):
            compute_fingerprint(b"" * 33)


class TestParseFingerprint(unittest.TestCase):
    def test_round_trip(self):
        key = _random_key()
        fp = compute_fingerprint(key)
        parsed = parse_fingerprint(fp)
        self.assertEqual(parsed, bytes.fromhex(fp.replace(":", "")))
        self.assertEqual(len(parsed), FINGERPRINT_BYTES)

    def test_round_trip_uppercase(self):
        key = _random_key()
        fp = format_fingerprint(key, uppercase=True)
        parsed = parse_fingerprint(fp)
        self.assertEqual(len(parsed), FINGERPRINT_BYTES)

    def test_round_trip_no_colons(self):
        key = _random_key()
        raw_hex = compute_fingerprint(key).replace(":", "")
        parsed = parse_fingerprint(raw_hex)
        self.assertEqual(parsed, bytes.fromhex(raw_hex))

    def test_invalid_hex_rejected(self):
        with self.assertRaises(ValueError):
            parse_fingerprint("not:hex:string:here:12345678:12345678:12345678:12345678")

    def test_wrong_length_rejected(self):
        # 30 bytes instead of 32.
        short = "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"
        with self.assertRaises(ValueError):
            parse_fingerprint(short)

    def test_odd_hex_length_rejected(self):
        with self.assertRaises(ValueError):
            parse_fingerprint("abc")


class TestFingerprintDistance(unittest.TestCase):
    """A simple hamming-distance helper for comparing two fingerprints.

    This is useful for fuzzy comparison (e.g. catching transcription errors)
    when a strict string compare is too brittle.
    """

    def test_identical_distance_zero(self):
        key = _random_key()
        fp = compute_fingerprint(key)
        self.assertEqual(fingerprint_distance(fp, fp), 0)

    def test_single_bit_diff(self):
        key = _random_key()
        fp1 = compute_fingerprint(key)
        raw = bytearray(bytes.fromhex(fp1.replace(":", "")))
        raw[5] ^= 0x01
        fp2 = ":".join(f"{b:02x}" for b in raw)
        self.assertEqual(fingerprint_distance(fp1, fp2), 1)

    def test_completely_different_max(self):
        fp1 = compute_fingerprint(_random_key())
        fp2 = compute_fingerprint(_random_key())
        d = fingerprint_distance(fp1, fp2)
        # Hamming distance of two random 256-bit values is ~128 on average;
        # we just assert it's high and within bounds.
        self.assertGreater(d, 64)
        self.assertLessEqual(d, FINGERPRINT_BYTES * 8)


if __name__ == "__main__":
    unittest.main()

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
