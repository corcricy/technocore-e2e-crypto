"""
X25519 + HKDF + AES-256-GCM End-to-End Encryption

A reference implementation of the full authenticated-encryption flow:
  1. Ephemeral-static or static-static X25519 ECDH key agreement
  2. HKDF-SHA256 key derivation (extract + expand)
  3. AES-256-GCM authenticated encryption/decryption

All primitives are provided by the `cryptography` library.
Requires: cryptography >= 41.0.0
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, hkdf
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ── low-level primitives ────────────────────────────────────────────


def generate_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generate a fresh X25519 key pair. Returns (private_key, public_key)."""
    private = x25519.X25519PrivateKey.generate()
    return private, private.public_key()


def raw_public_bytes(public_key: x25519.X25519PublicKey) -> bytes:
    """Serialize an X25519 public key to its 32-byte raw form (RFC 7748)."""
    return public_key.public_bytes_raw()


def public_key_from_bytes(data: bytes) -> x25519.X25519PublicKey:
    """Deserialize a 32-byte raw public key. Raises ValueError on invalid input."""
    return x25519.X25519PublicKey.from_public_bytes(data)


def compute_shared_secret(
    private_key: x25519.X25519PrivateKey,
    peer_public: x25519.X25519PublicKey,
) -> bytes:
    """Perform X25519 ECDH: returns the 32-byte shared secret."""
    return private_key.exchange(peer_public)


def derive_key(
    shared_secret: bytes,
    *,
    salt: Optional[bytes] = None,
    info: bytes = b"technocore-e2e-v1",
    length: int = 32,
) -> bytes:
    """Derive a symmetric key from the shared secret via HKDF-SHA256.

    Uses the extract-then-expand pattern.
    - `salt`:   optional random salt (32 bytes recommended).
    - `info`:   domain-separation / context string.
    - `length`: output key length in bytes (default 32 for AES-256).
    """
    hkdf_instance = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf_instance.derive(shared_secret)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt plaintext with AES-256-GCM.

    Returns the concatenation (nonce || ciphertext || tag).
    Nonce is 12 random bytes (NIST SP 800-38D, §8.2.2).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    # ciphertext already includes the 16-byte authentication tag appended
    return nonce + ciphertext


def decrypt(key: bytes, packet: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt a packet produced by `encrypt`.

    Expects the format (12-byte nonce || ciphertext-with-tag).
    Raises `cryptography.exceptions.InvalidTag` on authentication failure.
    """
    if len(packet) < 28:  # 12 nonce + 16 tag minimum
        raise ValueError("Packet too short")
    nonce = packet[:12]
    ciphertext = packet[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


# ── high-level envelope ─────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Envelope:
    """The result of `seal`: everything the recipient needs to decrypt.

    Fields:
        sender_public:   32-byte raw sender X25519 public key.
        salt:            32-byte random salt for HKDF.
        ciphertext:      AES-256-GCM ciphertext (12-byte nonce prefix + tag suffix).
    """

    sender_public: bytes
    salt: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        """Pack the envelope into a single byte string for storage/wire.

        Format: sender_public (32) || salt (32) || ciphertext (var).
        """
        return self.sender_public + self.salt + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "Envelope":
        """Unpack a byte string produced by `to_bytes`."""
        if len(data) < 64:
            raise ValueError("Envelope too short (need at least 64 bytes)")
        return cls(
            sender_public=data[:32],
            salt=data[32:64],
            ciphertext=data[64:],
        )


def seal(
    plaintext: bytes,
    recipient_public: x25519.X25519PublicKey,
    *,
    associated_data: bytes = b"",
    info: bytes = b"technocore-e2e-v1",
) -> Envelope:
    """Encrypt `plaintext` for a known recipient (static-static mode).

    Uses the caller's already-held keypair.
    """
    sender_priv, sender_pub = generate_keypair()
    shared = compute_shared_secret(sender_priv, recipient_public)
    salt = os.urandom(32)
    key = derive_key(shared, salt=salt, info=info)
    ciphertext = encrypt(key, plaintext, associated_data)
    return Envelope(
        sender_public=raw_public_bytes(sender_pub),
        salt=salt,
        ciphertext=ciphertext,
    )


def open_envelope(
    envelope: Envelope,
    recipient_private: x25519.X25519PrivateKey,
    *,
    associated_data: bytes = b"",
    info: bytes = b"technocore-e2e-v1",
) -> bytes:
    """Decrypt a sealed `Envelope` using the recipient's private key.

    Returns the original plaintext.
    Raises `cryptography.exceptions.InvalidTag` if authentication fails.
    """
    sender_pub = public_key_from_bytes(envelope.sender_public)
    shared = compute_shared_secret(recipient_private, sender_pub)
    key = derive_key(shared, salt=envelope.salt, info=info)
    return decrypt(key, envelope.ciphertext, associated_data)


# ── convenience: ephemeral key-generation helpers ───────────────────


def generate_sender_keypair() -> Tuple[bytes, bytes]:
    """Generate a sender keypair, returning (raw_private, raw_public).

    Raw private is 32 bytes (clamped scalar).  Store securely.
    Raw public is 32 bytes (X-coordinate).
    """
    priv, pub = generate_keypair()
    return (
        priv.private_bytes_raw(),
        raw_public_bytes(pub),
    )

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
