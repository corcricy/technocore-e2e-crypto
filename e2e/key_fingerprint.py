"""
Key fingerprinting helpers for the technocore-e2e-crypto protocol.

A fingerprint is a short, stable, human-comparable encoding of a peer's
long-term X25519 identity key. It is *not* secret. Peers verify each
other out-of-band (e.g. by reading the fingerprint aloud) to defeat
active MITM attacks where an adversary swaps public keys at session
establishment time.

Design choices (matching patterns.md):

* Hash the raw 32-byte X25519 public key with BLAKE2b-256, then encode
  the first 16 bytes (128 bits) as 32 lowercase hex characters.
* 128 bits is well beyond any practical collision search and matches
  the SSH `ssh-keygen -lf` default word count (md5 fingerprint).
* Hex (not base32/base64) because it is easy to read aloud and to
  compare visually, and it requires no special padding rules.
* We expose a grouped form (4-char groups separated by spaces) for UI
  display, plus a canonical compact form for storage and equality
  comparisons.

This module is dependency-free except for the standard library.
"""

from __future__ import annotations

import hashlib
import re
from typing import Final

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

# 16 bytes = 32 hex chars = 128 bits of entropy.
_FP_BYTES: Final = 16
_FP_HEX_LEN: Final = _FP_BYTES * 2

# A 32-character lowercase hex string, optionally split into 4-char
# groups by single spaces.
_GROUPED_RE = re.compile(
    r"^([0-9a-f]{4}( [0-9a-f]{4}){7})$"
)
_COMPACT_RE = re.compile(r"^[0-9a-f]{32}$")


def fingerprint_of_public_key(pub: X25519PublicKey) -> str:
    """Compute the canonical compact hex fingerprint of a public key.

    Args:
        pub: An X25519 public key.

    Returns:
        A 32-character lowercase hex string (128 bits).
    """
    if not isinstance(pub, X25519PublicKey):
        raise TypeError(
            f"expected X25519PublicKey, got {type(pub).__name__}"
        )
    raw = pub.public_bytes_raw()  # 32 bytes
    digest = hashlib.blake2b(raw, digest_size=_FP_BYTES).hexdigest()
    return digest


def fingerprint_of_bytes(public_key_bytes: bytes) -> str:
    """Compute the fingerprint from raw 32-byte public key material.

    Convenience wrapper that avoids forcing callers to construct an
    X25519PublicKey object when they only have the raw bytes.

    Args:
        public_key_bytes: Exactly 32 bytes of X25519 public key material.

    Returns:
        A 32-character lowercase hex string.

    Raises:
        ValueError: if input is not exactly 32 bytes.
    """
    if len(public_key_bytes) != 32:
        raise ValueError(
            f"X25519 public key must be 32 bytes, got {len(public_key_bytes)}"
        )
    return hashlib.blake2b(public_key_bytes, digest_size=_FP_BYTES).hexdigest()


def format_grouped(fingerprint: str) -> str:
    """Group a compact fingerprint into 4-char chunks for display.

    Example:
        >>> format_grouped('a1b2c3d4' * 4)
        'a1b2 c3d4 a1b2 c3d4 a1b2 c3d4 a1b2 c3d4'
    """
    _validate_compact(fingerprint)
    return " ".join(
        fingerprint[i : i + 4] for i in range(0, _FP_HEX_LEN, 4)
    )


def parse_grouped(grouped: str) -> str:
    """Parse a grouped fingerprint back to its compact form.

    Accepts any whitespace-separated hex groups as long as they
    concatenate to exactly 32 hex characters. Whitespace inside groups
    is not allowed (each group must be exactly 4 hex chars to make
    word-count mistakes obvious when read aloud).
    """
    if not isinstance(grouped, str):
        raise TypeError(
            f"expected str, got {type(grouped).__name__}"
        )
    if _GROUPED_RE.match(grouped) is None:
        # Try to be lenient: collapse internal whitespace and re-check.
        compact = "".join(grouped.split())
        if _COMPACT_RE.match(compact) is None:
            raise ValueError(
                f"not a valid grouped fingerprint: {grouped!r}"
            )
        return compact
    return grouped.replace(" ", "")


def fingerprints_equal(a: str, b: str) -> bool:
    """Constant-time equality check between two compact fingerprints.

    Both inputs must already be in compact (non-grouped) form; call
    :func:`parse_grouped` first if needed.
    """
    _validate_compact(a)
    _validate_compact(b)
    if len(a) != len(b):
        return False
    # Constant-time compare over equal-length hex strings.
    diff = 0
    for ca, cb in zip(a, b):
        diff |= ord(ca) ^ ord(cb)
    return diff == 0


def _validate_compact(fp: str) -> None:
    if not isinstance(fp, str) or _COMPACT_RE.match(fp) is None:
        raise ValueError(
            f"fingerprint must be 32 lowercase hex chars, got {fp!r}"
        )


__all__ = [
    "fingerprint_of_public_key",
    "fingerprint_of_bytes",
    "format_grouped",
    "parse_grouped",
    "fingerprints_equal",
]

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
