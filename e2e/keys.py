"""
Key generation, serialization, and identity helpers for technocore-e2e-crypto.

Conventions
-----------
- Identity keypair: long-term X25519 key used as the root of an HKDF-based
  identity. The public half is the agent's "did:key" surface.
- Ephemeral keypair: short-lived X25519 key generated for each session.
- Symmetric session key: 32-byte AES-256-GCM key derived via HKDF-SHA256
  from the ECDH shared secret, with nonces/counters bound into the info.

Serialisation format
--------------------
- Public keys: 32 raw bytes, base64url-encoded (no padding), prefixed with
  the string "did:key:z".
- Private keys: 32 raw bytes, base64url-encoded (no padding), prefixed with
  the string "did:key:s".

The format matches the patterns.md reference so that two processes using this
library can exchange keys over JSON without bespoke codecs.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


# --- base64url helpers --------------------------------------------------------

def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


# --- DID encoding -------------------------------------------------------------

def encode_public_did(public_key: X25519PublicKey) -> str:
    """Return the 'did:key:z...' surface form for an X25519 public key."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "did:key:z" + _b64u_encode(raw)


def encode_private_did(private_key: X25519PrivateKey) -> str:
    """Return the 'did:key:s...' surface form for an X25519 private key."""
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return "did:key:s" + _b64u_encode(raw)


def decode_public_did(did: str) -> X25519PublicKey:
    """Parse a 'did:key:z...' string back into an X25519 public key."""
    if not did.startswith("did:key:z"):
        raise ValueError("public DID must start with 'did:key:z'")
    raw = _b64u_decode(did[len("did:key:z"):])
    if len(raw) != 32:
        raise ValueError("X25519 public key must be 32 raw bytes")
    return X25519PublicKey.from_public_bytes(raw)


def decode_private_did(did: str) -> X25519PrivateKey:
    """Parse a 'did:key:s...' string back into an X25519 private key."""
    if not did.startswith("did:key:s"):
        raise ValueError("private DID must start with 'did:key:s'")
    raw = _b64u_decode(did[len("did:key:s"):])
    if len(raw) != 32:
        raise ValueError("X25519 private key must be 32 raw bytes")
    return X25519PrivateKey.from_private_bytes(raw)


# --- Keypair containers -------------------------------------------------------

@dataclass(frozen=True)
class Keypair:
    """An X25519 identity keypair with did:key surface strings."""
    private: X25519PrivateKey
    public: X25519PublicKey
    public_did: str
    private_did: str


def generate_identity_keypair() -> Keypair:
    """Generate a fresh long-lived identity keypair."""
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return Keypair(
        private=sk,
        public=pk,
        public_did=encode_public_did(pk),
        private_did=encode_private_did(sk),
    )


def load_keypair(private_did: str) -> Keypair:
    """Rehydrate a Keypair from a previously serialised private DID."""
    sk = decode_private_did(private_did)
    pk = sk.public_key()
    return Keypair(
        private=sk,
        public=pk,
        public_did=encode_public_did(pk),
        private_did=private_did,
    )


def load_public_key(public_did: str) -> X25519PublicKey:
    """Rehydrate a peer public key from a 'did:key:z...' string."""
    return decode_public_did(public_did)


# --- Ephemeral keys ----------------------------------------------------------

def generate_ephemeral_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate a single-use X25519 keypair for one session handshake."""
    sk = X25519PrivateKey.generate()
    return sk, sk.public_key()


def ephemeral_public_did(pk: X25519PublicKey) -> str:
    """Surface form for an ephemeral public key, distinguishable from identity."""
    return "did:key:z" + _b64u_encode(
        pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


# --- Random helpers used across the library ---------------------------------

def random_nonce(n: int = 12) -> bytes:
    """Return n cryptographically random bytes (default: AES-GCM nonce size)."""
    if n < 1 or n > 64:
        raise ValueError("nonce length must be in [1, 64]")
    return os.urandom(n)


def fingerprint_did(public_did: str) -> str:
    """Short, human-friendly fingerprint for a public DID (first 8 b64u chars)."""
    if not public_did.startswith("did:key:z"):
        raise ValueError("fingerprint_did requires a public DID")
    return public_did[len("did:key:z"):][:12]


__all__ = [
    "Keypair",
    "generate_identity_keypair",
    "load_keypair",
    "load_public_key",
    "generate_ephemeral_keypair",
    "ephemeral_public_did",
    "encode_public_did",
    "encode_private_did",
    "decode_public_did",
    "decode_private_did",
    "random_nonce",
    "fingerprint_did",
]

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
