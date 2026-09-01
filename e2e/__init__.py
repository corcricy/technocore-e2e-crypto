"""e2e: reference X25519 + HKDF-SHA256 + AES-256-GCM end-to-end encryption.

This package implements the patterns documented in ``patterns.md``:

  * X25519 ephemeral-static key agreement (per-message ephemeral key)
  * HKDF-SHA256 with explicit salt/info for domain separation
  * AES-256-GCM authenticated encryption with 96-bit random nonce and
    128-bit auth tag
  * Versioned, length-prefixed framing so ciphertexts are self-describing

The single source of truth for the wire format is ``e2e.framing``; the
single source of truth for the cryptographic primitives is ``e2e.crypto``.
Importing this package re-exports the most common entry points so callers
can do ``from e2e import encrypt, decrypt``.
"""

from .crypto import (
    generate_keypair,
    public_key_from_bytes,
    private_key_from_bytes,
    encrypt,
    decrypt,
    CryptoError,
    AuthenticationError,
    VersionMismatchError,
)
from .framing import (
    MAGIC,
    CURRENT_VERSION,
    FRAME_HEADER_LEN,
    NONCE_LEN,
    TAG_LEN,
    MAX_PAYLOAD,
    frame,
    unframe,
    FrameError,
    FrameTooLargeError,
    FrameTruncatedError,
    BadMagicError,
    BadVersionError,
)

__all__ = [
    # crypto
    "generate_keypair",
    "public_key_from_bytes",
    "private_key_from_bytes",
    "encrypt",
    "decrypt",
    "CryptoError",
    "AuthenticationError",
    "VersionMismatchError",
    # framing
    "MAGIC",
    "CURRENT_VERSION",
    "FRAME_HEADER_LEN",
    "NONCE_LEN",
    "TAG_LEN",
    "MAX_PAYLOAD",
    "frame",
    "unframe",
    "FrameError",
    "FrameTooLargeError",
    "FrameTruncatedError",
    "BadMagicError",
    "BadVersionError",
]

__version__ = "1.0.0"

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
