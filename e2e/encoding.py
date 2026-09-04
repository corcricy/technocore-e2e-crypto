"""
e2e/encoding.py
================

Binary <-> text encoding helpers used by the technocore-e2e-crypto reference
implementation.

We standardize on:
  * URL-safe Base64 (RFC 4648 §5) WITHOUT padding stripping surprises.
    We use the standard `base64.urlsafe_b64encode` / `urlsafe_b64decode`
    routines but always emit *unpadded* strings on the wire, because URLs,
    JSON, and most chat transports dislike the '=' character. Decoding
    tolerates both padded and unpadded input.
  * Hex encoding for short, human-debuggable fingerprints (X25519 public
    keys, session ids, nonces).

Why a dedicated module?
----------------------
Mixing ad-hoc `b64encode(...).decode().rstrip('=')` calls throughout the
codebase is a classic source of subtle interoperability bugs (a stray
`.decode('utf-8')` here, a missing padding there, a base32 vs base64
confusion). Centralizing the encoding rules makes the protocol-spec
self-documenting and gives us a single place to add stricter validation.

This module is intentionally dependency-free (stdlib only) so that it can
be reused on constrained environments that ship the core crypto module.

Public API
----------
- b64e(data: bytes) -> str
- b64d(text: str)   -> bytes
- hexe(data: bytes) -> str
- hexd(text: str)   -> bytes
- is_b64(text: str) -> bool
- constant_time_eq(a: bytes, b: bytes) -> bool
"""

from __future__ import annotations

import base64
import binascii
import hmac

__all__ = [
    "b64e",
    "b64d",
    "hexe",
    "hexd",
    "is_b64",
    "constant_time_eq",
]


# ---------------------------------------------------------------------------
# Base64 (URL-safe, unpadded on the wire)
# ---------------------------------------------------------------------------

def b64e(data: bytes) -> str:
    """Encode *data* to URL-safe Base64, unpadded.

    >>> b64e(b'\x00\x01\x02')
    'AAEC'
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("b64e() requires a bytes-like object")
    encoded = base64.urlsafe_b64encode(bytes(data)).decode("ascii")
    return encoded.rstrip("=")


def b64d(text: str) -> bytes:
    """Decode a Base64 string. Accepts padded or unpadded input.

    Raises ValueError on invalid Base64.
    """
    if not isinstance(text, str):
        raise TypeError("b64d() requires a str")
    # Normalize: strip ASCII whitespace that some transports add.
    cleaned = "".join(text.split())
    # Re-pad to a multiple of 4. urlsafe_b64decode is strict about padding.
    pad = (-len(cleaned)) % 4
    padded = cleaned + ("=" * pad)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64 input: {exc}") from exc


def is_b64(text: str) -> bool:
    """Cheap syntactic check: does *text* look like (URL-safe) Base64?

    This is purely a *format* check used for input validation in transport
    layers; it does not validate that the decoded bytes are meaningful.
    """
    if not isinstance(text, str) or not text:
        return False
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "-_"
        "="
    )
    return all(ch in allowed for ch in text)


# ---------------------------------------------------------------------------
# Hex (lowercase, for fingerprints and short identifiers)
# ---------------------------------------------------------------------------

def hexe(data: bytes) -> str:
    """Lowercase hex encoding."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("hexe() requires a bytes-like object")
    return bytes(data).hex()


def hexd(text: str) -> bytes:
    """Decode lowercase (or uppercase) hex. Tolerates ASCII whitespace."""
    if not isinstance(text, str):
        raise TypeError("hexd() requires a str")
    cleaned = "".join(text.split())
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hex input: {exc}") from exc


# ---------------------------------------------------------------------------
# Constant-time comparison helper
# ---------------------------------------------------------------------------

def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Length-leaky but value-constant-time bytes comparison.

    Use this for MAC/auth-tag checks where you want to avoid early-exit
    timing oracles. Length itself is generally not secret for our use
    cases (X25519 keys are fixed-length, AES-GCM tags are 16 bytes), so
    the standard `hmac.compare_digest` is appropriate.
    """
    if not isinstance(a, (bytes, bytearray, memoryview)):
        raise TypeError("constant_time_eq() requires bytes-like args")
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise TypeError("constant_time_eq() requires bytes-like args")
    return hmac.compare_digest(bytes(a), bytes(b))


# ---------------------------------------------------------------------------
# Self-test when run as a script
## ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover - manual sanity check
    import doctest
    doctest.testmod(verbose=True)

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
