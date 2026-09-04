"""High-level encrypted session manager.

Wraps the lower-level pieces (keys, transport, AEAD primitives from
``e2e.crypto``) into a single object that callers can use to send and
receive framed messages over an arbitrary byte stream (e.g. a socket,
stdin/stdout pipe, or an in-memory queue used in tests).

Wire format per direction:

    +---------+--------------+---------+----------+------------------+
    | ver (1) | eph_pub (32) | n (12)  | ct_len   | ciphertext+tag  |
    +---------+--------------+---------+----------+------------------+

    ver      = 0x01  (protocol version)
    eph_pub  = 32-byte X25519 ephemeral public key (sender side)
    n        = 12-byte AES-GCM nonce
    ct_len   = 4-byte big-endian length of the ciphertext+tag payload

The receiver combines its long-term X25519 secret key with the sender's
ephemeral public key (and vice versa) to derive a 32-byte shared secret
via X25519, then runs HKDF-SHA-256 with a context label to produce the
32-byte AES-256-GCM key.  A new ephemeral key + nonce is generated for
every send, providing forward secrecy at the cost of one extra
public key per message.

This module deliberately exposes a small, easy-to-audit surface and
forwards the heavy lifting to the primitive modules.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keys import KeyPair
from .crypto import hkdf_derive

PROTOCOL_VERSION = 0x01
HEADER_FMT = ">B32s12sI"  # ver, eph_pub, nonce, ct_len
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 1 + 32 + 12 + 4 = 49
HKDF_INFO = b"technocore-e2e/v1/session-key"


class ProtocolError(Exception):
    """Raised when an incoming frame violates the session wire format."""


@dataclass
class Session:
    """An encrypted session bound to a local long-term ``KeyPair``.

    The remote peer's long-term *public* key must be supplied up front
    so that each message can derive a fresh shared secret with a new
    ephemeral key.
    """

    local: KeyPair
    remote_pub: X25519PublicKey
    _send_counter: int = 0
    _recv_counter: int = 0

    # ---------- key derivation ---------------------------------------

    @staticmethod
    def _derive_aead_key(my_priv: X25519PrivateKey, their_pub: X25519PublicKey) -> bytes:
        """X25519 + HKDF-SHA256 -> 32-byte AES-256 key."""
        shared = my_priv.exchange(their_pub)
        return hkdf_derive(shared, info=HKDF_INFO, length=32)

    # ---------- send side --------------------------------------------

    def _frame(self, plaintext: bytes) -> bytes:
        """Encrypt and frame one message under a fresh ephemeral key."""
        if len(plaintext) > 0xFFFFFFFF:
            raise ValueError("plaintext exceeds 4 GiB frame limit")
        eph_priv = X25519PrivateKey.generate()
        key = self._derive_aead_key(eph_priv, self.remote_pub)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
        header = struct.pack(HEADER_FMT, PROTOCOL_VERSION, eph_priv.public_key().public_bytes_raw(), nonce, len(ct))
        self._send_counter += 1
        return header + ct

    def send(self, stream: BinaryIO, plaintext: bytes) -> None:
        stream.write(self._frame(plaintext))

    # ---------- receive side -----------------------------------------

    def _unframe(self, framed: bytes) -> bytes:
        if len(framed) < HEADER_LEN:
            raise ProtocolError("frame shorter than header")
        ver, eph_pub_bytes, nonce, ct_len = struct.unpack(HEADER_FMT, framed[:HEADER_LEN])
        if ver != PROTOCOL_VERSION:
            raise ProtocolError(f"unsupported protocol version {ver}")
        if len(framed) < HEADER_LEN + ct_len:
            raise ProtocolError("frame truncated payload")
        ct = framed[HEADER_LEN:HEADER_LEN + ct_len]
        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
        key = self._derive_aead_key(self.local.private_key(), eph_pub)
        try:
            pt = AESGCM(key).decrypt(nonce, ct, associated_data=None)
        except Exception as exc:  # InvalidTag is the only error in practice
            raise ProtocolError(f"decryption failed: {exc}") from exc
        self._recv_counter += 1
        return pt

    def recv_exact(self, stream: BinaryIO) -> bytes:
        """Read one full framed message from ``stream`` and decrypt it."""
        header = stream.read(HEADER_LEN)
        if len(header) < HEADER_LEN:
            raise ProtocolError("unexpected EOF while reading header")
        _, _, _, ct_len = struct.unpack(HEADER_FMT, header)
        ct = stream.read(ct_len)
        if len(ct) < ct_len:
            raise ProtocolError("unexpected EOF while reading payload")
        return self._unframe(header + ct)

    def recv(self, stream: BinaryIO) -> bytes:
        """Alias for :meth:`recv_exact` retained for readability at call sites."""
        return self.recv_exact(stream)


# ---------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------

def open_session(local: KeyPair, remote_pub: X25519PublicKey) -> Session:
    """Construct a :class:`Session`. Equivalent to ``Session(local, remote_pub)``."""
    return Session(local=local, remote_pub=remote_pub)


def pair(local_a: KeyPair, local_b: KeyPair) -> tuple[Session, Session]:
    """Build a matched pair of sessions, one for each direction.

    Useful for tests and examples that need to demonstrate round-trip
    traffic without any real network.
    """
    return (
        Session(local=local_a, remote_pub=local_b.public_key()),
        Session(local=local_b, remote_pub=local_a.public_key()),
    )

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
