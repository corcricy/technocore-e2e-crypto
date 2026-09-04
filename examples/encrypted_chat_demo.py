"""End-to-end encrypted chat demo using technocore-e2e-crypto.

This script shows the full lifecycle of a technocore session between two parties
(Alice and Bob). It is intentionally self-contained and runnable from the repo
root with no external network or fixtures:

    python examples/encrypted_chat_demo.py

What it demonstrates
--------------------
1. Long-term identity keypair generation (X25519) for each party.
2. Key fingerprint computation so users can verify out-of-band.
3. Transport-layer key exchange: each side sends its ephemeral X25519 public key.
4. Session establishment: HKDF-SHA256 derives a shared 32-byte AES key from the
   ephemeral ECDH secret, binding both party identities into the transcript.
5. AES-256-GCM encrypt/decrypt of a small chat transcript, including a tampered
   ciphertext case to show authentication failure.
6. Clean shutdown (wipe session keys, drop transports).

The code mirrors the patterns in docs/protocol-spec.md. It is meant to be read,
not just run: every step prints what is happening so newcomers can map spec
sections to working code.

Security notes
--------------
- This demo is illustrative. In production you would:
  * verify the peer's fingerprint via a second channel (QR, voice, etc.)
  * use a proper double-ratchet / continuous KDF for forward secrecy
  * never log session keys (we print fingerprints, which are hashes, instead)
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import List, Tuple

# Make the package importable when running this file directly.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from e2e.keys import X25519KeyPair  # noqa: E402
from e2e.key_fingerprint import fingerprint  # noqa: E402
from e2e.session import Session, SessionError  # noqa: E402
from e2e.transport import InMemoryTransport, Transport  # noqa: E402


# ---------------------------------------------------------------------------
# A minimal "chat transcript" we will encrypt.
# ---------------------------------------------------------------------------
SCRIPT: List[Tuple[str, str]] = [
    ("alice", "hi bob, ready for the handoff?"),
    ("bob", "ready. fingerprint looks good on my end."),
    ("alice", "sending the design doc under the new session key."),
    ("bob", "got it. closing the loop after this message."),
]


@dataclass
class Party:
    name: str
    identity: X25519KeyPair
    transport: Transport
    session: Session

    def send(self, plaintext: bytes) -> bytes:
        return self.session.encrypt(plaintext)

    def recv(self, ciphertext: bytes) -> bytes:
        return self.session.decrypt(ciphertext)


def banner(text: str) -> None:
    line = "=" * len(text)
    print(f"\n{line}\n{text}\n{line}")


def build_party(name: str, peer_transport: Transport, wire: InMemoryTransport) -> Party:
    identity = X25519KeyPair.generate()
    fp = fingerprint(identity.public_bytes())
    print(f"[{name}] identity public key fingerprint: {fp}")
    session = Session(local_identity=identity, peer_transport=peer_transport, wire=wire)
    return Party(name=name, identity=identity, transport=peer_transport, session=session)


def run() -> int:
    banner("technocore-e2e-crypto: encrypted chat demo")

    # Two transports wired together so each side sees the other's outbound frames.
    alice_to_bob = InMemoryTransport()
    bob_to_alice = InMemoryTransport()

    alice = build_party("alice", alice_to_bob, wire_for_bob=bob_to_alice)
    bob = build_party("bob", bob_to_alice, wire_for_alice=alice_to_bob)

    # Out-of-band fingerprint verification step.
    fp_alice = fingerprint(alice.identity.public_bytes())
    fp_bob = fingerprint(bob.identity.public_bytes())
    print(f"\n[verify] alice -> bob fingerprint: {fp_alice}")
    print(f"[verify] bob   <- alice fingerprint: {fp_bob}")
    assert fp_alice != fp_bob, "fingerprint collision (impossible in practice)"

    # Run the chat.
    banner("chat transcript (encrypted on the wire)")
    for sender_name, message in SCRIPT:
        sender = alice if sender_name == "alice" else bob
        receiver = bob if sender_name == "alice" else alice

        plaintext = f"{sender_name}: {message}".encode("utf-8")
        ciphertext = sender.send(plaintext)
        print(f"[{sender_name} -> {receiver.name}] {len(ciphertext)}B ciphertext: {ciphertext.hex()[:64]}...")

        try:
            recovered = receiver.recv(ciphertext)
        except SessionError as exc:
            print(f"  !! decryption failed: {exc}")
            return 1
        assert recovered == plaintext, "round-trip mismatch"
        print(f"[{receiver.name} decrypted] {recovered.decode('utf-8')}")

    # Tamper test: flip a bit in the ciphertext and confirm AES-GCM rejects it.
    banner("tamper test")
    ciphertext = alice.send(b"secret payload")
    tampered = bytearray(ciphertext)
    tampered[5] ^= 0x01  # flip a single bit somewhere in the body
    try:
        bob.recv(bytes(tampered))
    except SessionError as exc:
        print(f"expected authentication failure on tampered frame: {exc}")
    else:
        print("!! tampered frame was accepted (this would be a bug)")
        return 2

    # Clean shutdown.
    banner("shutdown")
    alice.session.close()
    bob.session.close()
    alice_to_bob.close()
    bob_to_alice.close()
    print("session keys wiped, transports closed. done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
