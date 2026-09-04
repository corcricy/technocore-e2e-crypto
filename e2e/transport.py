"""
Encrypted transport layer for technocore-e2e-crypto.

Provides a thin abstraction over the E2E primitives (X25519 + HKDF-SHA256 +
AES-256-GCM) that frames messages for transmission over an unreliable byte
stream such as technocore.chat's HTTP-based room protocol.

Wire format (one frame, big-endian):

    +--------+--------+----------+----------+----------+----------+
    | magic  | ver    | eph_len  | eph_key  | nonce    | ciphertext|
    | 2 B    | 1 B    | 1 B      | N bytes  | 12 bytes | ...       |
    +--------+--------+----------+----------+----------+----------+
        magic   = b"TC"      (0x54 0x43) - identifies a technocore E2E frame
        ver     = 0x01       - protocol version
        eph_len = len(ephemeral_public_key) (currently always 32 for X25519)
        eph_key = X25519 ephemeral public key (32 B)
        nonce   = AES-GCM nonce (12 B)
        ciphertext = AES-256-GCM(ciphertext || tag)
                  = aad(eph_key || nonce) is bound into the GCM AAD so the
                    receiver cannot be tricked into decrypting under a
                    different ephemeral key/nonce pair.

The session_id parameter (any caller-chosen bytes, e.g. room+thread id) is
mixed into the HKDF info so two rooms with the same key pair still derive
distinct send/recv keys.

This module deliberately contains no I/O. Callers feed in bytes, get bytes
back, and are responsible for framing, length-prefixing, and reconnection.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag

from .crypto import (
    CryptoError,
    KeyPair,
    aesgcm_decrypt,
    aesgcm_encrypt,
    derive_session_keys,
    ephemeral_keypair,
    x25519_shared_secret,
)

MAGIC = b"TC"
VERSION = 0x01
HEADER_FMT = ">2sBB"
# 2 (magic) + 1 (ver) + 1 (eph_len) = 4 bytes before the ephemeral key
HEADER_PREFIX_LEN = struct.calcsize(HEADER_FMT)
EPH_PUB_LEN = 32  # X25519 public key size
NONCE_LEN = 12    # AES-GCM standard nonce size


class TransportError(CryptoError):
    """Raised for malformed frames, version mismatches, or decryption failures."""


@dataclass(frozen=True)
class Decrypted:
    """Result of opening a frame."""

    plaintext: bytes
    ephemeral_public: bytes  # the sender's per-message ephemeral X25519 public key
    nonce: bytes


def _build_aad(eph_pub: bytes, nonce: bytes) -> bytes:
    """AAD binds the ephemeral key and nonce into the AEAD tag."""
    if len(eph_pub) != EPH_PUB_LEN:
        raise TransportError(f"ephemeral public key must be {EPH_PUB_LEN} bytes")
    if len(nonce) != NONCE_LEN:
        raise TransportError(f"nonce must be {NONCE_LEN} bytes")
    return eph_pub + nonce


def seal(
    plaintext: bytes,
    recipient_public: bytes,
    *,
    session_id: bytes = b"",
    associated_data: bytes = b"",
) -> bytes:
    """Encrypt ``plaintext`` for ``recipient_public`` and return a wire frame.

    Each call generates a fresh ephemeral X25519 keypair and a random
    12-byte nonce, so the output is non-deterministic even for identical
    inputs.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if len(recipient_public) != EPH_PUB_LEN:
        raise TransportError(f"recipient public key must be {EPH_PUB_LEN} bytes")

    eph = ephemeral_keypair()
    shared = x25519_shared_secret(eph.secret, recipient_public)
    send_key, _ = derive_session_keys(shared, session_id=session_id)
    nonce = os.urandom(NONCE_LEN)
    aad = _build_aad(eph.public, nonce) + associated_data
    ciphertext = aesgcm_encrypt(send_key, nonce, bytes(plaintext), aad=aad)

    header = struct.pack(HEADER_FMT, MAGIC, VERSION, len(eph.public))
    return header + eph.public + nonce + ciphertext


def open(
    frame: bytes,
    recipient_keypair: KeyPair,
    *,
    session_id: bytes = b"",
    associated_data: bytes = b"",
) -> Decrypted:
    """Decrypt a wire frame produced by :func:`seal`."""
    if not isinstance(frame, (bytes, bytearray)):
        raise TypeError("frame must be bytes")

    if len(frame) < HEADER_PREFIX_LEN:
        raise TransportError("frame too short for header")

    magic, version, eph_len = struct.unpack(HEADER_FMT, frame[:HEADER_PREFIX_LEN])
    if magic != MAGIC:
        raise TransportError("bad magic: not a technocore E2E frame")
    if version != VERSION:
        raise TransportError(f"unsupported frame version: {version}")
    if eph_len != EPH_PUB_LEN:
        raise TransportError(f"unexpected ephemeral key length: {eph_len}")

    cursor = HEADER_PREFIX_LEN
    if len(frame) < cursor + eph_len + NONCE_LEN + 16:
        # 16 = minimum GCM tag size
        raise TransportError("frame truncated")

    eph_pub = bytes(frame[cursor : cursor + eph_len])
    cursor += eph_len
    nonce = bytes(frame[cursor : cursor + NONCE_LEN])
    cursor += NONCE_LEN
    ciphertext = bytes(frame[cursor:])

    shared = x25519_shared_secret(recipient_keypair.secret, eph_pub)
    _, recv_key = derive_session_keys(shared, session_id=session_id)
    aad = _build_aad(eph_pub, nonce) + associated_data

    try:
        plaintext = aesgcm_decrypt(recv_key, nonce, ciphertext, aad=aad)
    except InvalidTag as exc:
        raise TransportError("authentication failed: bad key, nonce, or AAD") from exc

    return Decrypted(plaintext=plaintext, ephemeral_public=eph_pub, nonce=nonce)


def make_keypair() -> KeyPair:
    """Convenience wrapper: generate a fresh X25519 keypair."""
    return ephemeral_keypair()


__all__ = [
    "MAGIC",
    "VERSION",
    "EPH_PUB_LEN",
    "NONCE_LEN",
    "Decrypted",
    "TransportError",
    "seal",
    "open",
    "make_keypair",
]

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
