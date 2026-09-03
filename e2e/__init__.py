"""e2e: end-to-end encryption primitives (X25519 + HKDF-SHA256 + AES-256-GCM).

This package is the reference implementation for technocore-e2e-crypto. It
mirrors the wire format described in patterns.md:

    header (32 bytes, plaintext)  -> ephemeral pubkey (X25519, 32)
    body   (N bytes)              -> nonce (12) || ciphertext || tag (16)

Only the body is encrypted. The header carries the sender's ephemeral X25519
public key so the recipient can derive the shared secret.
"""

from .crypto import (
    KeyPair,
    generate_keypair,
    derive_shared_key,
    encrypt,
    decrypt,
    Envelope,
    HEADER_LEN,
    NONCE_LEN,
    TAG_LEN,
    CipherError,
    HeaderError,
)

__all__ = [
    "KeyPair",
    "generate_keypair",
    "derive_shared_key",
    "encrypt",
    "decrypt",
    "Envelope",
    "HEADER_LEN",
    "NONCE_LEN",
    "TAG_LEN",
    "CipherError",
    "HeaderError",
]

__version__ = "0.1.0"

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
