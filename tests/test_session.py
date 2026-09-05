"""Tests for e2e/session.py — handshake state machine and message encrypt/decrypt."""
import os
import sys
import pytest

# Make repo root importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from e2e.session import (
    SessionState,
    HandshakeError,
    encrypt_message,
    decrypt_message,
    derive_session_keys,
    compute_handshake_hash,
    serialize_public_key,
    load_public_key,
)
from e2e.key_fingerprint import generate_keypair, fingerprint_public_key


def _initiator():
    return generate_keypair()


def _responder():
    return generate_keypair()


def test_serialize_and_load_public_key_roundtrip():
    sk, pk = generate_keypair()
    raw = serialize_public_key(pk)
    assert isinstance(raw, bytes) and len(raw) == 32
    pk2 = load_public_key(raw)
    assert pk2.public_bytes_raw() == pk.public_bytes_raw()


def test_handshake_hash_is_deterministic_and_distinct():
    sk_a, pk_a = generate_keypair()
    sk_b, pk_b = generate_keypair()
    h1 = compute_handshake_hash(pk_a, pk_b)
    h2 = compute_handshake_hash(pk_a, pk_b)
    h3 = compute_handshake_hash(pk_b, pk_a)
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 32


def test_derive_session_keys_symmetric_for_both_sides():
    sk_i, pk_i = generate_keypair()
    sk_r, pk_r = generate_keypair()
    k_i = derive_session_keys(sk_i, pk_r, pk_i)
    k_r = derive_session_keys(sk_r, pk_i, pk_r)
    # Both sides must agree on tx/rx keys (mirrored)
    assert k_i.tx_key == k_r.rx_key
    assert k_i.rx_key == k_r.tx_key
    assert k_i.handshake_hash == k_r.handshake_hash
    assert k_i.tx_nonce != k_r.tx_nonce  # directions must not collide


def test_encrypt_decrypt_roundtrip():
    sk_i, pk_i = generate_keypair()
    sk_r, pk_r = generate_keypair()
    keys_i = derive_session_keys(sk_i, pk_r, pk_i)
    keys_r = derive_session_keys(sk_r, pk_i, pk_r)

    plaintext = b"hello, technocore"
    aad = b"msg-id:1"

    nonce, ct = encrypt_message(keys_i, plaintext, aad=aad)
    pt = decrypt_message(keys_r, nonce, ct, aad=aad)
    assert pt == plaintext


def test_decrypt_fails_on_tampered_ciphertext():
    sk_i, pk_i = generate_keypair()
    sk_r, pk_r = generate_keypair()
    keys_i = derive_session_keys(sk_i, pk_r, pk_i)
    keys_r = derive_session_keys(sk_r, pk_i, pk_r)

    nonce, ct = encrypt_message(keys_i, b"secret", aad=None)
    tampered = bytearray(ct)
    tampered[-1] ^= 0x01
    tampered = bytes(tampered)
    with pytest.raises(HandshakeError):
        decrypt_message(keys_r, nonce, tampered, aad=None)


def test_decrypt_fails_on_wrong_aad():
    sk_i, pk_i = generate_keypair()
    sk_r, pk_r = generate_keypair()
    keys_i = derive_session_keys(sk_i, pk_r, pk_i)
    keys_r = derive_session_keys(sk_r, pk_i, pk_r)

    nonce, ct = encrypt_message(keys_i, b"secret", aad=b"msg:1")
    with pytest.raises(HandshakeError):
        decrypt_message(keys_r, nonce, ct, aad=b"msg:2")


def test_session_state_machine_transitions():
    sk_i, pk_i = generate_keypair()
    sk_r, pk_r = generate_keypair()
    s_i = SessionState(initiator=True)
    s_r = SessionState(initiator=False)

    # Fresh sessions are INIT
    assert s_i.phase == "INIT"
    assert s_r.phase == "INIT"

    # Cannot encrypt before handshake completes
    with pytest.raises(HandshakeError):
        s_i.encrypt(b"nope")

    s_i.set_remote_public_key(pk_r)
    s_r.set_remote_public_key(pk_i)
    s_i.complete_handshake()
    s_r.complete_handshake()
    assert s_i.phase == "ESTABLISHED"
    assert s_r.phase == "ESTABLISHED"

    # Now bidirectional encrypt/decrypt works through the state object
    nonce, ct = s_i.encrypt(b"ping", aad=b"m:1")
    assert s_r.decrypt(nonce, ct, aad=b"m:1") == b"ping"
    nonce, ct = s_r.encrypt(b"pong", aad=b"m:2")
    assert s_i.decrypt(nonce, ct, aad=b"m:2") == b"pong"

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
