"""
basic_e2e_chat.py
================

A self-contained, runnable example demonstrating the end-to-end encrypted
message protocol described in patterns.md, implemented in e2e/crypto.py.

Two parties ("Alice" and "Bob") exchange a small number of messages over a
naive in-process transport (a plain dict acting as a mailbox). Every message
is encrypted with X25519 (per-message ephemeral ECDH) + HKDF-SHA256 key
derivation + AES-256-GCM authenticated encryption, exactly as a real client
would on the wire. An eavesdropper ("Mallory") is shown the raw bytes on the
"wire" but cannot decrypt them; a tamper attempt is detected and rejected.

Run it:

    python examples/basic_e2e_chat.py

Expected output: both parties decrypt each other's messages successfully,
the wire shows only base64url ciphertext+tag blobs, and Mallory's tampered
packet raises DecryptError from AES-GCM authentication.

This file intentionally depends only on the standard library and the
in-repo e2e.crypto module. No external services, no network sockets.
"""

from __future__ import annotations

import sys
import os
import traceback

# Make the package importable when running this file directly.
HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, os.pardot))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from e2e.crypto import (
    generate_keypair,
    encrypt_to_peer,
    decrypt_from_peer,
    CryptoError,
    MAX_PLAINTEXT,
)


class Mailbox:
    """A deliberately trivial transport. Holds (sender, ciphertext) tuples."""

    def __init__(self) -> None:
        self.wire: list[tuple[str, str]] = []

    def post(self, sender: str, recipient_pub: str, ciphertext: str) -> None:
        # We store the ciphertext publicly so an eavesdropper can see it.
        self.wire.append((sender, ciphertext))
        # In a real system we'd hand it to the recipient out-of-band; here
        # the recipient will simply drain the queue.
        del recipient_pub  # unused in this toy transport

    def drain_for(self, recipient_name: str) -> list[tuple[str, str]]:
        out = [item for item in self.wire if item[0] != recipient_name]
        # Don't clear: we want Mallory to inspect later.
        return out


def banner(title: str) -> None:
    print("\n=== " + title + " ===")


def main() -> int:
    banner("Key generation")
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()
    print("Alice pubkey (first 16 chars):", alice_pub[:16], "...")
    print("Bob   pubkey (first 16 chars):", bob_pub[:16], "...")

    mailbox = Mailbox()

    banner("Outbound messages")
    # Alice -> Bob
    a_to_b_1 = encrypt_to_peer(bob_pub, "Hello Bob, this is Alice.")
    a_to_b_2 = encrypt_to_peer(bob_pub, "Want to grab coffee at 3pm?")
    # Bob -> Alice
    b_to_a_1 = encrypt_to_peer(alice_pub, "Hi Alice! Sounds good.")
    b_to_a_2 = encrypt_to_peer(alice_pub, "See you at the usual place.")

    # Post them onto the wire (publicly visible).
    mailbox.post("alice", bob_pub, a_to_b_1)
    mailbox.post("alice", bob_pub, a_to_b_2)
    mailbox.post("bob", alice_pub, b_to_a_1)
    mailbox.post("bob", alice_pub, b_to_a_2)

    print("Posted", len(mailbox.wire), "messages onto the wire.")
    print("Wire blob sample (Alice msg #1):", a_to_b_1[:48], "...")

    banner("Bob decrypts Alice's messages")
    for sender, blob in mailbox.drain_for("bob"):
        # Filter to only Alice->Bob packets for this demo. In a real system
        # we'd key by sender identity; here we just match on sender label.
        if sender != "alice":
            continue
        plaintext = decrypt_from_peer(bob_priv, blob)
        print(f"[{sender} -> bob] {plaintext!r}")

    banner("Alice decrypts Bob's messages")
    for sender, blob in mailbox.drain_for("alice"):
        if sender != "bob":
            continue
        plaintext = decrypt_from_peer(alice_priv, blob)
        print(f"[{sender} -> alice] {plaintext!r}")

    banner("Mallory tries to tamper with a ciphertext")
    # Flip one character of the base64url ciphertext portion. This should
    # cause AES-GCM authentication to fail.
    evil = list(a_to_b_1)
    # Pick a character somewhere in the body, not the prefix byte.
    target = len(evil) // 2
    evil[target] = "A" if evil[target] != "A" else "B"
    tampered = "".join(evil)
    print("Tampered blob differs at index", target)
    try:
        decrypt_from_peer(bob_priv, tampered)
    except CryptoError as exc:
        print("Tamper detected (expected):", type(exc).__name__, "-", exc)
    else:
        print("ERROR: tampered message decrypted; this should not happen!")
        return 1

    banner("Oversize plaintext is rejected")
    try:
        encrypt_to_peer(bob_pub, "x" * (MAX_PLAINTEXT + 1))
    except CryptoError as exc:
        print("Oversize rejected (expected):", type(exc).__name__, "-", exc)
    else:
        print("ERROR: oversize plaintext was accepted!")
        return 1

    banner("Done")
    print("All cryptographic operations behaved as specified.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        raise SystemExit(2)

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
