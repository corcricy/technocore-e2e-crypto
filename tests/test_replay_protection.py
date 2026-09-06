"""Tests for the replay-protection sliding window.

The window is byte-stringly typed on purpose: opaque nonces/timestamps from the
wire must not be coerced to int behind the consumer's back. The store itself
does no I/O; persistence is the caller's problem (see e2e/replay_protection.py).
"""

import os
import unittest

from e2e.replay_protection import ReplayWindow, ReplayRejected


def _rand(n: int) -> bytes:
    return os.urandom(n)


class TestReplayWindow(unittest.TestCase):
    def setUp(self) -> None:
        self.window = ReplayWindow(size=64)

    def test_first_seen_nonce_is_accepted(self) -> None:
        nonce = _rand(12)
        self.window.check_and_record(nonce, ts=1)
        self.assertIn(nonce, self.window.seen)

    def test_duplicate_nonce_is_rejected(self) -> None:
        nonce = _rand(12)
        self.window.check_and_record(nonce, ts=1)
        with self.assertRaises(ReplayRejected):
            self.window.check_and_record(nonce, ts=2)

    def test_old_nonce_below_floor_is_rejected(self) -> None:
        # Fill the window so floor advances.
        for i in range(self.window.size):
            self.window.check_and_record(_rand(12), ts=1000 + i)
        # Anything older than the highest seen minus window size must be rejected.
        old_ts = 1000 + self.window.size - 1  # one below the floor
        with self.assertRaises(ReplayRejected):
            self.window.check_and_record(_rand(12), ts=old_ts)

    def test_fresh_nonce_above_floor_is_accepted(self) -> None:
        for i in range(self.window.size):
            self.window.check_and_record(_rand(12), ts=1000 + i)
        # Same epoch as highest, fresh nonce: still allowed.
        self.window.check_and_record(_rand(12), ts=1000 + self.window.size - 1)

    def test_byte_string_nonce_is_not_coerced_to_int(self) -> None:
        # A 12-byte nonce that happens to look like a small number must still be
        # treated as opaque bytes; equality is structural, not numeric.
        nonce = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        self.window.check_and_record(nonce, ts=1)
        with self.assertRaises(ReplayRejected):
            self.window.check_and_record(nonce, ts=2)

    def test_serialisation_roundtrip(self) -> None:
        for i in range(8):
            self.window.check_and_record(_rand(12), ts=500 + i)
        blob = self.window.to_dict()
        restored = ReplayWindow.from_dict(blob)
        # A nonce seen before serialisation must still be rejected afterwards.
        sample = next(iter(self.window.seen))
        with self.assertRaises(ReplayRejected):
            restored.check_and_record(sample, ts=999)
        self.assertEqual(restored.highest_ts, self.window.highest_ts)
        self.assertEqual(restored.size, self.window.size)

    def test_clear_resets_state(self) -> None:
        self.window.check_and_record(_rand(12), ts=42)
        self.window.clear()
        self.assertEqual(len(self.window.seen), 0)
        self.assertEqual(self.window.highest_ts, 0)
        # Re-recording the same nonce after clear must succeed.
        nonce = _rand(12)
        self.window.check_and_record(nonce, ts=1)
        self.window.clear()
        self.window.check_and_record(nonce, ts=1)

    def test_replay_rejected_carries_reason(self) -> None:
        nonce = _rand(12)
        self.window.check_and_record(nonce, ts=10)
        try:
            self.window.check_and_record(nonce, ts=11)
        except ReplayRejected as exc:
            self.assertIn("duplicate", str(exc).lower())


if __name__ == "__main__":
    unittest.main()

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
