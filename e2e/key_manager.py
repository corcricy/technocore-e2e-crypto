"""
e2e/key_manager.py
==================

X25519 keypair management with HKDF-based derivation of symmetric session keys.

This module is the companion to ``nonce_manager.py`` and the patterns described
in ``docs/protocol-spec.md``. It owns the long-term identity keypair and the
shared-secret derivation used to produce per-session AES-256-GCM keys.

Design notes
------------
* The long-term identity keypair is a static X25519 key (Curve25519 ECDH).
  The private scalar is held in memory only; never written to disk in this
  reference implementation. Production deployments should wrap the scalar in a
  KMS / HSM / OS keystore.
* Per-peer shared secrets are derived via ``crypto_kx``-style HKDF over the raw
  X25519 output (libsodium's ``crypto_kx`` uses Info strings ``"ss_sm``
  (client->server) and ``"ss_sm"`` rotated directionally). We follow the same
  pattern using RFC 5869 HKDF-SHA256 so the code is portable to any
  ``cryptography``-based environment.
* Session keys are 256-bit (AES-256-GCM) and re-derived for every session_id.
  Rekeying on session change prevents key reuse across logically separate
  conversations.

Example
-------
>>> from e2e.key_manager import KeyManager
>>> alice = KeyManager()
>>> bob = KeyManager()
>>> a2b = alice.session_keys(bob.public_key_bytes(), session_id=b"chat-1")
>>> b2a = bob.session_keys(alice.public_key_bytes(), session_id=b"chat-1")
>>> a2b.tx_key == b2a.rx_key  # Alice's tx == Bob's rx
True
>>> a2b.rx_key == b2a.tx_key
True
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


# HKDF info strings separate the two directional keys, mirroring libsodium's
# crypto_kx layout. Different info == different derived bytes even with the
# same IKM, which is the whole point of the directional split.
_INFO_TX = b"e2e/v1/kx/tx"
_INFO_RX = b"e2e/v1/kx/rx"
_SALT_CONTEXT = b"e2e/v1/session"


@dataclass(frozen=True)
class SessionKeys:
    """Directional symmetric keys for one session with one peer."""

    tx_key: bytes  # key used to encrypt data YOU send
    rx_key: bytes  # key used to decrypt data YOU receive
    session_id: bytes

    def __len__(self) -> int:  # convenience for assertions / logging
        return 32


class KeyManager:
    """Holds an X25519 identity and derives session keys with peers."""

    __slots__ = ("_priv", "_pub", "_pub_bytes")

    def __init__(self, private_key: Optional[X25519PrivateKey] = None) -> None:
        if private_key is None:
            private_key = X25519PrivateKey.generate()
        self._priv = private_key
        self._pub = private_key.public_key()
        # Cache the raw public bytes once; they're sent over the wire.
        self._pub_bytes = self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # ---- identity ---------------------------------------------------------

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "KeyManager":
        """Reconstruct a KeyManager from 32 raw private-key bytes."""
        if len(raw) != 32:
            raise ValueError("X25519 private key must be 32 bytes")
        return cls(X25519PrivateKey.from_private_bytes(raw))

    def public_key_bytes(self) -> bytes:
        """Return the 32-byte raw public key (safe to share / serialize)."""
        return self._pub_bytes

    def private_bytes(self) -> bytes:
        """Return the 32-byte raw private scalar. Treat as a secret."""
        return self._priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    # ---- session key derivation -------------------------------------------

    def session_keys(self, peer_public_bytes: bytes, *, session_id: bytes) -> SessionKeys:
        """Derive directional AES-256 keys for one session with one peer.

        Parameters
        ----------
        peer_public_bytes:
            The peer's raw 32-byte X25519 public key.
        session_id:
            Application-defined identifier for this conversation. Must be
            non-empty and unique per logical session; mixing session_ids
            guarantees no key reuse across conversations even with the
            same peer.
        """
        if not isinstance(peer_public_bytes, (bytes, bytearray)) or len(peer_public_bytes) != 32:
            raise ValueError("peer public key must be 32 bytes")
        if not session_id:
            raise ValueError("session_id must be non-empty")

        peer_pub = X25519PublicKey.from_public_bytes(bytes(peer_public_bytes))
        shared = self._priv.exchange(peer_pub)  # 32-byte raw X25519 output

        # Salt binds the derivation to the session_id so two sessions with
        # the same peer produce disjoint keys.
        salt = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=_SALT_CONTEXT,
            info=session_id,
        ).derive(shared)

        tx_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=_INFO_TX,
        ).derive(shared)

        rx_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=_INFO_RX,
        ).derive(shared)

        return SessionKeys(tx_key=tx_key, rx_key=rx_key, session_id=bytes(session_id))


# ---- helpers --------------------------------------------------------------

def random_session_id(nbytes: int = 16) -> bytes:
    """Return a fresh random session_id suitable for ``KeyManager.session_keys``."""
    if nbytes < 8:
        raise ValueError("session_id should be at least 8 bytes")
    return secrets.token_bytes(nbytes)


# Re-export the underlying primitive type for callers that need to wrap
# a pre-existing private key (e.g. loaded from a hardware-backed store).
__all__ = ["KeyManager", "SessionKeys", "X25519PrivateKey", "random_session_id"]

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
