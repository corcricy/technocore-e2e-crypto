"""Tests for e2e/session.py — end-to-end encrypted session lifecycle.

Covers:
  * Session establishment (initiator ↔ responder) yields matching symmetric keys.
  * Encrypt/decrypt round-trip across many frames preserves plaintext and AAD.
  * Reordered frames decrypt successfully (reorder tolerance).
  * Forged ciphertext (bit-flip) fails authentication.
  * Forged AAD fails authentication.
  * Replay of an old frame within window is rejected.
  * Session teardown prevents further encrypt/decrypt operations.

These tests are intentionally self-contained: they build their own keypairs,
negotiate a shared secret manually via X25519, and exercise the Session
class without any network I/O.
"""

from __future__ import annotations

import os
import time
from typing import Tuple

import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from e2e.session import Session, SessionError, SessionRole


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


def _establish_pair() -> Tuple[Session, Session]:
    """Create two Sessions that share the same X25519 secret."""
    a_priv, a_pub = _keypair()
    b_priv, b_pub = _keypair()
    shared_a = a_priv.exchange(b_pub)
    shared_b = b_priv.exchange(a_pub)
    assert shared_a == shared_b, "X25519 ECDH sanity check failed"

    info = b"technocore-e2e/test-session/v1"
    initiator = Session(
        role=SessionRole.INITIATOR,
        local_private=a_priv,
        remote_public=b_pub,
        info=info,
    )
    responder = Session(
        role=SessionRole.RESPONDER,
        local_private=b_priv,
        remote_public=a_pub,
        info=info,
    )
    return initiator, responder


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_session_keys_match_after_establish() -> None:
    a, b = _establish_pair()
    assert a.tx_key == b.rx_key, "initiator TX must match responder RX"
    assert a.rx_key == b.tx_key, "initiator RX must match responder TX"
    assert a.tx_key != a.rx_key, "directions must derive distinct keys"


def test_roundtrip_many_frames() -> None:
    a, b = _establish_pair()
    for i in range(50):
        plaintext = f"frame-{i}".encode().ljust(64, b"\x00")
        aad = {"seq": i, "src": "alice", "dst": "bob"}
        frame = a.encrypt(plaintext, aad=aad)
        assert frame.seq == i
        recovered, recovered_aad = b.decrypt(frame, expected_aad=aad)
        assert recovered == plaintext
        assert recovered_aad == aad


def test_reorder_tolerance() -> None:
    a, b = _establish_pair()
    frames = []
    for i in range(10):
        frames.append(a.encrypt(b"msg-%d" % i, aad={"seq": i}))
    # Deliver out of order
    for f in reversed(frames):
        pt, _ = b.decrypt(f, expected_aad={"seq": f.seq})
        assert pt == b"msg-%d" % f.seq


def test_forged_ciphertext_rejected() -> None:
    a, b = _establish_pair()
    frame = a.encrypt(b"hello", aad={"x": 1})
    tampered = bytearray(frame.ciphertext)
    tampered[0] ^= 0x01
    from e2e.session import Frame
    bad = Frame(
        seq=frame.seq,
        nonce=frame.nonce,
        ciphertext=bytes(tampered),
        tag=frame.tag,
    )
    with pytest.raises(SessionError):
        b.decrypt(bad, expected_aad={"x": 1})


def test_forged_aad_rejected() -> None:
    a, b = _establish_pair()
    frame = a.encrypt(b"hello", aad={"role": "alice"})
    with pytest.raises(SessionError):
        b.decrypt(frame, expected_aad={"role": "eve"})


def test_replay_within_window_rejected() -> None:
    a, b = _establish_pair()
    frame = a.encrypt(b"once", aad={"seq": 0})
    # First delivery succeeds
    b.decrypt(frame, expected_aad={"seq": 0})
    # Replay must fail
    with pytest.raises(SessionError):
        b.decrypt(frame, expected_aad={"seq": 0})


def test_teardown_blocks_use() -> None:
    a, _ = _establish_pair()
    a.close()
    with pytest.raises(SessionError):
        a.encrypt(b"nope", aad={})


def test_monotonic_seq_no_reuse() -> None:
    a, b = _establish_pair()
    seqs = []
    for i in range(20):
        f = a.encrypt(b"x", aad={"i": i})
        seqs.append(f.seq)
    assert seqs == list(range(20))
    assert len(set(seqs)) == 20


def test_key_derivation_is_deterministic() -> None:
    """Same inputs → same Session keys (HKDF determinism)."""
    a_priv = X25519PrivateKey.generate()
    b_priv = X25519PrivateKey.generate()
    shared = a_priv.exchange(b_priv.public_key())
    info = b"test-info"

    s1 = Session(SessionRole.INITIATOR, a_priv, b_priv.public_key(), info)
    # Re-derive from raw shared secret to confirm match
    from e2e.session import _derive_session_keys  # type: ignore[attr-defined]
    k_tx, k_rx = _derive_session_keys(shared, info)
    assert s1.tx_key == k_tx
    assert s1.rx_key == k_rx


def test_session_clock_skew_check() -> None:
    """Decrypting with a wildly wrong expected timestamp in AAD fails."""
    a, b = _establish_pair()
    now = int(time.time())
    frame = a.encrypt(b"ping", aad={"ts": now})
    # Correct AAD works
    b.decrypt(frame, expected_aad={"ts": now})
    # Wrong timestamp is treated as AAD mismatch
    with pytest.raises(SessionError):
        b.decrypt(frame, expected_aad={"ts": now + 9999})

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
