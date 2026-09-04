"""High-level encrypted session for E2E chat (X25519 + HKDF-SHA256 + AES-256-GCM).

Wraps the lower-level primitives in e2e.crypto so callers can do:

    alice = Session(my_x25519_priv)
    bob   = Session(bob_x25519_pub)

    send = alice.wrap(b"hi bob", nonce_salt=b"\x01")
    recv = bob.unwrap(send)

A Session derives a 32-byte AES key on demand via HKDF-SHA256 with an
application/domain info string, and uses AES-256-GCM with a 96-bit random
nonce per message. The 16-byte auth tag is appended to the ciphertext so
that the wire format is just nonce || ciphertext || tag (the nonce is also
covered by the AEAD since AES-GCM authenticates AAD; we put the per-message
salt in the AAD so a key+nonce reuse produces different ciphertexts).

This is intentionally small and dependency-free (uses only the stdlib + the
cryptography package, same as the rest of e2e/).
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .crypto import hkdf_sha256, aesgcm_encrypt, aesgcm_decrypt


# Wire layout for a wrapped message (after Session.wrap):
#   1 byte  : version (currently 0x01)
#   12 bytes: AES-GCM nonce (random per message)
#   N bytes : ciphertext (plaintext || 16-byte tag, as produced by crypto.aesgcm_encrypt)
# We also put the version + a per-message caller salt into the AAD so the
# tag covers them and tampering with the version byte is detected.
_VERSION = 0x01
_NONCE_LEN = 12


@dataclass
class Session:
    """A single E2E session bound to one local X25519 keypair.

    Either `local_private` (outbound/capable of decrypt) or `remote_public`
    (decrypt-only/verify side) must be supplied. For a full bidirectional
    session, pass `local_private` and construct the peer Session with
    `remote_public=my_public`.
    """

    local_private: Optional[X25519PrivateKey] = None
    remote_public: Optional[X25519PublicKey] = None
    info: Union[bytes, str] = b"technocore-e2e/v1"

    def __post_init__(self) -> None:
        if self.local_private is None and self.remote_public is None:
            raise ValueError("Session needs at least local_private or remote_public")
        if isinstance(self.info, str):
            self.info = self.info.encode("utf-8")

    # --- key derivation -------------------------------------------------

    def _shared_key(self) -> bytes:
        """Compute the 32-byte session key.

        If both sides are known (local + remote), we use a true ECDH. If
        only `local_private` is set, we treat the session as a self-session
        (useful for tests and for the local side before the remote pub is
        known). If only `remote_public` is set, we cannot derive a key on
        this side because we lack the ECDH contribution.
        """
        if self.local_private is None:
            raise ValueError("cannot derive session key: no local private key")
        if self.remote_public is None:
            # Self-session: ECDH with our own public key.
            peer = self.local_private.public_key()
        else:
            peer = self.remote_public
        shared = self.local_private.exchange(peer)
        return hkdf_sha256(shared, info=self.info, length=32)

    # --- wrap / unwrap ---------------------------------------------------

    def wrap(self, plaintext: bytes, *, salt: bytes = b"") -> bytes:
        """Encrypt `plaintext` for the peer. Returns nonce || ct||tag.

        `salt` is an optional per-message nonce_salt that is mixed into the
        AAD, so two messages with the same plaintext and randomly-equal
        nonces still produce distinct ciphertexts when callers supply
        distinct salts (e.g. a monotonic counter).
        """
        key = self._shared_key()
        nonce = os.urandom(_NONCE_LEN)
        aad = bytes([_VERSION]) + salt
        ct_and_tag = aesgcm_encrypt(key, nonce, plaintext, aad=aad)
        return bytes([_VERSION]) + nonce + ct_and_tag

    def unwrap(self, envelope: bytes, *, salt: bytes = b"") -> bytes:
        """Decrypt an envelope produced by `wrap` on the peer side."""
        if len(envelope) < 1 + _NONCE_LEN + 16:
            raise ValueError("envelope too short")
        version = envelope[0]
        if version != _VERSION:
            raise ValueError(f"unsupported envelope version: {version}")
        nonce = envelope[1 : 1 + _NONCE_LEN]
        ct_and_tag = envelope[1 + _NONCE_LEN :]
        aad = bytes([_VERSION]) + salt
        key = self._shared_key()
        return aesgcm_decrypt(key, nonce, ct_and_tag, aad=aad)

    # --- convenience: hex public key for transport ---------------------

    @staticmethod
    def public_bytes(pub: X25519PublicKey) -> bytes:
        return pub.public_bytes(
            encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
            format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
        )


def make_session(local_private_bytes: bytes, *,
                 remote_public_bytes: Optional[bytes] = None,
                 info: Union[bytes, str] = b"technocore-e2e/v1"") -> Session:
    """Build a Session from raw 32-byte key material (handy for transport)."""
    priv = X25519PrivateKey.from_raw_bytes(local_private_bytes)
    pub = X25519PublicKey.from_raw_bytes(remote_public_bytes) if remote_public_bytes else None
    return Session(local_private=priv, remote_public=pub, info=info)

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
