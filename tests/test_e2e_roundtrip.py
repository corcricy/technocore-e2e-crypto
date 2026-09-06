"""End-to-end roundtrip tests for the X25519+HKDF+AESGCM protocol.

These tests verify the full envelope lifecycle: ephemeral key generation,
shared-secret derivation, encrypt/decrypt, and field-by-field envelope
validation. They exercise both the happy path and the negative paths that
real deployments must catch (tampered ciphertext, wrong key, replay).

Run with: pytest tests/test_e2e_roundtrip.py -v
"""

import json
import os

import pytest

from e2e.session import Session, SessionError
from e2e.envelope import Envelope, decrypt_envelope, encrypt_envelope
from e2e.replay_protection import ReplayCache


RECEIVER_DID = "did:key:z6MkReceiverExampleAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SENDER_DID = "did:key:z6MkSenderExampleAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


@pytest.fixture
def alice_bob():
    """Fresh Session pair representing Alice (sender) and Bob (receiver)."""
    alice = Session(self_did=SENDER_DID, peer_did=RECEIVER_DID)
    bob = Session(self_did=RECEIVER_DID, peer_did=SENDER_DID)
    # Bind each side to the other's static public key.
    alice.set_peer_public_key(bob.public_key_bytes())
    bob.set_peer_public_key(alice.public_key_bytes())
    return alice, bob


def _make_cache():
    return ReplayCache(max_size=128, ttl_seconds=300)


def test_basic_roundtrip(alice_bob):
    alice, bob = alice_bob
    cache = _make_cache()

    plaintext = b"hello bob, this is alice"
    env = alice.encrypt(plaintext)

    assert isinstance(env, Envelope)
    assert env.ephemeral_pub, "envelope must carry ephemeral public key"
    assert env.nonce, "envelope must contain a nonce"
    assert env.ciphertext, "ciphertext must be non-empty"
    assert env.tag, "AES-GCM authentication tag must be present"

    recovered = bob.decrypt(env, replay_cache=cache)
    assert recovered == plaintext


def test_roundtrip_preserves_payload_integrity_for_binary_data(alice_bob):
    alice, bob = alice_bob
    cache = _make_cache()

    payload = os.urandom(4096)  # 4 KiB of random binary
    env = alice.encrypt(payload)
    assert bob.decrypt(env, replay_cache=cache) == payload


def test_envelope_serializes_to_canonical_json(alice_bob):
    alice, _ = alice_bob
    env = alice.encrypt(b"x")
    blob = env.to_json()
    # Round-trip parse.
    parsed = Envelope.from_json(blob)
    assert parsed.ephemeral_pub == env.ephemeral_pub
    assert parsed.nonce == env.nonce
    assert parsed.ciphertext == env.ciphertext
    assert parsed.tag == env.tag
    # Canonical: keys must be sorted, no extra whitespace.
    as_dict = json.loads(blob)
    assert list(as_dict.keys()) == sorted(as_dict.keys())


def test_tampered_ciphertext_is_rejected(alice_bob):
    alice, bob = alice_bob
    cache = _make_cache()

    env = alice.encrypt(b"transfer 100 to alice")
    bad = Envelope(
        ephemeral_pub=env.ephemeral_pub,
        nonce=env.nonce,
        ciphertext=bytes(b ^ 0x01 for b in env.ciphertext),
        tag=env.tag,
    )
    with pytest.raises(SessionError):
        bob.decrypt(bad, replay_cache=cache)


def test_tampered_tag_is_rejected(alice_bob):
    alice, bob = alice_bob
    cache = _make_cache()

    env = alice.encrypt(b"signed instruction")
    bad = Envelope(
        ephemeral_pub=env.ephemeral_pub,
        nonce=env.nonce,
        ciphertext=env.ciphertext,
        tag=bytes(b ^ 0xFF for b in env.tag),
    )
    with pytest.raises(SessionError):
        bob.decrypt(bad, replay_cache=cache)


def test_wrong_peer_key_fails_to_decrypt():
    alice = Session(self_did=SENDER_DID, peer_did=RECEIVER_DID)
    bob = Session(self_did=RECEIVER_DID, peer_did=SENDER_DID)
    mallory = Session(self_did="did:key:z6MkMallory", peer_did=SENDER_DID)

    alice.set_peer_public_key(bob.public_key_bytes())
    bob.set_peer_public_key(alice.public_key_bytes())
    mallory.set_peer_public_key(alice.public_key_bytes())

    env = alice.encrypt(b"secret")
    with pytest.raises(SessionError):
        mallory.decrypt(env, replay_cache=_make_cache())


def test_replay_is_rejected_within_ttl(alice_bob):
    alice, bob = alice_bob
    cache = _make_cache()

    env = alice.encrypt(b"once")
    assert bob.decrypt(env, replay_cache=cache) == b"once"
    with pytest.raises(SessionError):
        bob.decrypt(env, replay_cache=cache)


def test_session_uses_unique_ephemeral_keys_per_message(alice_bob):
    alice, _ = alice_bob
    seen = set()
    for _ in range(16):
        env = alice.encrypt(b"ping")
        assert env.ephemeral_pub not in seen, "ephemeral key reused"
        seen.add(env.ephemeral_pub)


def test_module_level_helpers_match_session_api(alice_bob):
    alice, bob = alice_bob
    sk_a = alice.export_private_key_bytes()
    pk_b = bob.public_key_bytes()

    env = encrypt_envelope(receiver_pub=pk_b, plaintext=b"hi")
    out = decrypt_envelope(
        our_private_key=sk_a,
        peer_pub=bob.public_key_bytes(),
        envelope=env,
    )
    assert out == b"hi"

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
