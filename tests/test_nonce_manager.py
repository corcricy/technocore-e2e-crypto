"""Tests for e2e/nonce_manager.py.

These tests exercise the NonceManager: deterministic counter increment,
monotonic uniqueness within a session, overflow protection, and
serialization round-trip.

The tests are deliberately independent of network/crypto primitives -
NonceManager is purely an integer counter abstraction.
"""

from __future__ import annotations

import pytest

from e2e.nonce_manager import NonceManager, NonceOverflowError


def test_initial_counter_is_zero():
    nm = NonceManager()
    assert nm.peek() == 0
    assert not nm.is_exhausted()


def test_next_increments_monotonically():
    nm = NonceManager()
    seen = []
    for _ in range(100):
        seen.append(nm.next())
    assert seen == list(range(100))


def test_next_is_strictly_increasing():
    nm = NonceManager()
    prev = -1
    for _ in range(50):
        cur = nm.next()
        assert cur > prev
        prev = cur


def test_peek_does_not_consume():
    nm = NonceManager()
    nm.peek()
    nm.peek()
    assert nm.next() == 0


def test_overflow_protection():
    # Use a small cap so the test is fast.
    nm = NonceManager(max_value=3)
    assert nm.next() == 0
    assert nm.next() == 1
    assert nm.next() == 2
    assert nm.is_exhausted()
    with pytest.raises(NonceOverflowError):
        nm.next()


def test_overflow_at_2_64_default():
    # The default cap is 2^64 - 1; ensure a fresh manager reports
    # not-exhausted and can hand out at least a few values.
    nm = NonceManager()
    for _ in range(10):
        nm.next()
    assert not nm.is_exhausted()


def test_serialize_roundtrip():
    nm = NonceManager()
    for _ in range(7):
        nm.next()
    blob = nm.serialize()
    restored = NonceManager.deserialize(blob)
    assert restored.peek() == 7
    assert restored.next() == 7


def test_serialize_is_canonical_bytes():
    nm1 = NonceManager()
    nm2 = NonceManager()
    nm1.next()
    nm1.next()
    nm2.next()
    nm2.next()
    # Both managers at counter=2 should serialize identically.
    assert nm1.serialize() == nm2.serialize()


def test_deserialize_rejects_oversized_blob():
    # 17 bytes would overflow a u128; NonceManager uses u64 internally
    # in the canonical schema, so anything longer than 8 bytes is invalid.
    with pytest.raises(ValueError):
        NonceManager.deserialize(b"\x00" * 17)


def test_deserialize_rejects_truncated_blob():
    with pytest.raises(ValueError):
        NonceManager.deserialize(b"\x00\x01\x02")


def test_thread_safety_under_contention():
    # Smoke test: concurrent next() calls must all be unique.
    import threading

    nm = NonceManager()
    out: list[int] = []
    lock = threading.Lock()

    def worker():
        for _ in range(500):
            v = nm.next()
            with lock:
                out.append(v)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(out) == 2000
    assert len(set(out)) == 2000  # all unique
    assert min(out) == 0
    assert max(out) == 1999


def test_counter_persists_across_instances_for_same_session():
    # Pattern: resume a session by deserializing and continuing.
    a = NonceManager()
    for _ in range(42):
        a.next()
    blob = a.serialize()
    b = NonceManager.deserialize(blob)
    assert b.next() == 42
    assert b.next() == 43

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
