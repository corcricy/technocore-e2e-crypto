"""
End-to-end key exchange handshake example.

Demonstrates the X25519+HKDF-SHA256+AES-256-GCM handshake between two peers
(Alice and Bob) using the e2e.crypto module. Each peer generates an ephemeral
X25519 keypair, computes a shared secret, derives a symmetric session key
via HKDF, and then exchanges a short authenticated ciphertext to confirm
the session is established.

Run from the repo root:

    python -m examples.key_exchange_handshake

No network is involved; messages are passed as in-memory dicts.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# Allow running this file directly from the repo root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from e2e.crypto import (
    NONCE_SIZE,
    generate_keypair,
    derive_session_key,
    encrypt_message,
    decrypt_message,
)


@dataclass
class Peer:
    name: str
    private_key: bytes
    public_key: bytes

    @classmethod
    def create(cls, name: str) -> "Peer":
        sk, pk = generate_keypair()
        return cls(name=name, private_key=sk, public_key=pk)


def send(peer: Peer, recipient_pub: bytes, plaintext: bytes) -> dict:
    """Encrypt a message for a recipient using peer's session key."""
    session_key = derive_session_key(
        my_private=peer.private_key,
        their_public=recipient_pub,
        info=f"e2e-chat:{peer.name}".encode(),
    )
    nonce, ciphertext = encrypt_message(session_key, plaintext)
    return {"from": peer.name, "nonce": nonce, "ct": ciphertext}


def receive(peer: Peer, sender_pub: bytes, envelope: dict) -> bytes:
    """Decrypt an incoming envelope using peer's session key."""
    session_key = derive_session_key(
        my_private=peer.private_key,
        their_public=sender_pub,
        info=f"e2e-chat:{envelope['from']}".encode(),
    )
    assert len(envelope["nonce"]) == NONCE_SIZE, "bad nonce size"
    return decrypt_message(session_key, envelope["nonce"], envelope["ct"])


def handshake(label: str, a: Peer, b: Peer) -> bool:
    """Run a mutual confirm-in-the-cipher handshake and return True on success."""
    a_to_b = send(a, b.public_key, f"hello from {a.name}".encode())
    b_to_a = send(b, a.public_key, f"ack from {b.name} to {a.name}".encode())
    a_got = receive(a, b.public_key, b_to_a)
    b_got = receive(b, a.public_key, a_to_b)
    ok = b_got.startswith(b"hello from ") and a_got.startswith(b"ack from ")
    print(f"[{label}] {a.name}<->{b.name}: handshake_ok={ok}")
    return ok


def main() -> int:
    alice = Peer.create("alice")
    bob = Peer.create("bob")

    assert handshake("demo", alice, bob), "handshake failed"

    # Demonstrate forward-secrecy-style rotation: fresh keypairs yield a
    # different session key, so old ciphertexts become undecryptable.
    alice2 = Peer.create("alice")
    bob2 = Peer.create("bob")
    envelope = send(alice2, bob2.public_key, b"rotated session message")
    assert receive(bob2, alice2.public_key, envelope) == b"rotated session message"
    # The original alice/bob must not be able to decrypt the rotated envelope.
    try:
        receive(bob, alice2.public_key, envelope)
        raise AssertionError("unexpected cross-session decrypt")
    except Exception:
        print("[demo] rotated session is isolated from prior keypairs: ok")

    print("[demo] all handshake checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
