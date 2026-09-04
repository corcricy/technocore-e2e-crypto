"""
Encrypted handshake example for technocore-e2e-crypto.

Demonstrates a full end-to-end encrypted session between two parties
(Alice and Bob) using the project's primitives:

  * X25519 Diffie-Hellman key exchange
  * HKDF-SHA-256 key derivation
  * AES-256-GCM authenticated encryption
  * Replay protection via a per-direction counter window

Run with:

    python examples/encrypted_handshake.py

No external dependencies beyond the standard library and the project's
own e2e/ package are required.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

# Allow running this file directly from the repo root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from e2e.keys import KeyPair  # noqa: E402
from e2e.session import Session, Transport  # noqa: E402


@dataclass
class LoopbackTransport(Transport):
    """In-memory transport that shuttles encrypted frames between two sessions.

    A real deployment would replace this with HTTP/WebSocket/etc. — the
    Session class never inspects frame payloads, so any byte carrier works.
    """

    peer: "Session | None" = None
    inbox: bytearray = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.inbox = bytearray()

    def send(self, frame: bytes) -> None:
        assert self.peer is not None, "transport not wired to a peer"
        # Hand the frame straight to the peer's transport layer; the peer
        # Session is responsible for decryption.
        self.peer._receive_frame(bytes(frame))

    def drain(self) -> bytes:
        data = bytes(self.inbox)
        self.inbox.clear()
        return data


def build_session(name: str, peer_transport: LoopbackTransport) -> Session:
    """Generate an ephemeral X25519 keypair and wire up a Session for `name`."""
    kp = KeyPair.generate()
    transport = LoopbackTransport()
    # Cross-wire transports so each side's send() reaches the other.
    transport.peer = None  # filled in after the second session exists
    peer_transport.peer = None  # also patched below
    return Session(name=name, keypair=kp, transport=transport)


def main() -> int:
    print("== technocore-e2e-crypto: encrypted handshake demo ==")

    # 1. Each side generates a fresh X25519 keypair.
    alice_kp = KeyPair.generate()
    bob_kp = KeyPair.generate()
    print(f"alice pubkey: {alice_kp.public_bytes.hex()[:32]}...")
    print(f"bob   pubkey: {bob_kp.public_bytes.hex()[:32]}...")

    # 2. Build transports and cross-wire them.
    alice_tx = LoopbackTransport()
    bob_tx = LoopbackTransport()
    alice_tx.peer = None  # type: ignore[assignment]
    bob_tx.peer = None    # type: ignore[assignment]

    # 3. Construct sessions. In a real protocol the public keys are
    #    exchanged out of band (e.g. via the technocore chat server).
    alice = Session(name="alice", keypair=alice_kp, transport=alice_tx)
    bob = Session(name="bob", keypair=bob_kp, transport=bob_tx)

    # Patch the cross-wiring now that both Session objects exist.
    alice_tx.peer = bob
    bob_tx.peer = alice

    # 4. Complete the handshake: each side calls establish() with the
    #    peer's public key. HKDF derives matching send/recv keys.
    alice.establish(peer_public=bob_kp.public_bytes)
    bob.establish(peer_public=alice_kp.public_bytes)
    print("handshake: HKDF derived matching AES-256-GCM keys")

    # 5. Exchange three application messages in each direction.
    messages_from_alice = [
        b"hello bob — this message is end-to-end encrypted",
        b"second message: includes unicode \xe2\x9c\x93",
        b"third: short",
    ]
    messages_from_bob = [
        b"hi alice, got your first message",
        b"acked the unicode checkmark",
        b"bye!",
    ]

    print("\n-- alice -> bob --")
    for plaintext in messages_from_alice:
        frame = alice.encrypt(plaintext)
        bob._receive_frame(frame)  # normally arrives via transport
        received = bob.decrypt()
        print(f"  sent:     {plaintext!r}")
        print(f"  received: {received!r}")
        assert received == plaintext, "decryption mismatch"

    print("\n-- bob -> alice --")
    for plaintext in messages_from_bob:
        frame = bob.encrypt(plaintext)
        alice._receive_frame(frame)
        received = alice.decrypt()
        print(f"  sent:     {plaintext!r}")
        print(f"  received: {received!r}")
        assert received == plaintext, "decryption mismatch"

    # 6. Demonstrate replay protection: replaying an old frame must fail.
    print("\n-- replay protection check --")
    old_frame = alice.encrypt(b"this should never be accepted twice")
    bob._receive_frame(old_frame)
    first = bob.decrypt()
    assert first == b"this should never be accepted twice"
    # Re-deliver the same frame: the counter window must reject it.
    bob._receive_frame(old_frame)
    try:
        bob.decrypt()
    except Exception as exc:  # noqa: BLE001
        print(f"  replay correctly rejected: {type(exc).__name__}: {exc}")
    else:
        raise SystemExit("replay was NOT rejected — counter window broken")

    # 7. Show that the wire format is opaque ciphertext + tag.
    print("\n-- wire format sanity --")
    sample = alice.encrypt(b"inspect me")
    print(f"  frame length: {len(sample)} bytes")
    print(f"  plaintext does NOT appear in frame: {b'inspect me' not in sample}")

    print("\n== demo complete: all messages authenticated, no plaintext on wire ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
