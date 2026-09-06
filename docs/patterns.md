# E2E Cryptography Patterns Reference

This document captures the canonical patterns used across the `technocore-e2e-crypto`
reference implementation. It is the source of truth for how X25519 key agreement,
HKDF-SHA256 key derivation, and AES-256-GCM authenticated encryption are combined
to form a session between two peers.

The patterns are deliberately small so they can be audited in a single sitting
and ported to other languages (Go, Rust, Java, etc.) without semantic drift.

## 1. Key Agreement

* **Algorithm:** X25519 (RFC 7748).
* **Encoding:** 32-byte raw public keys, no length prefix.
* **Inputs:** Each peer holds a long-term identity keypair and, for each session,
  generates an ephemeral keypair.
* **Shared secret:** `shared = X25519(my_ephemeral_private, peer_ephemeral_public)`.

## 2. Key Derivation

* **KDF:** HKDF (RFC 5869) with SHA-256.
* **Salt:** `salt = SHA-256(my_ephemeral_pub || peer_ephemeral_pub)` with the
  lexicographically smaller public key written first. Domain separation is
  critical; never reuse a salt outside this construction.
* **IKM:** The 32-byte X25519 shared secret.
* **Info string:** A versioned label, e.g. `"technocore-e2e-v1/session"`.
* **Output:** 64 bytes, split into:
  * `key_enc[0:32]` -- AES-256-GCM data key.
  * `key_mac[0:32]` -- reserved; not used by AES-GCM but reserved for future
    double-encryption or HMAC-binding schemes.

## 3. Authenticated Encryption

* **Cipher:** AES-256-GCM with a 12-byte random IV per direction.
* **AAD:** A canonical session context string, at minimum
  `"{session_id}|{direction}"` where `direction` is `"c2s"` or `"s2c"`.
* **Tag:** 16 bytes, appended to the ciphertext by the AEAD primitive.
* **Frame layout on the wire:**
  ```
  [ 1B version=0x01 ][ 12B iv ][ 4B ciphertext_length ][ ciphertext ][ 16B tag ]
  ```
  The `version` byte allows the protocol to evolve without breaking peers that
  negotiate a different suite via the handshake.

## 4. Replay Protection

* **Counter window:** A sliding window of the last 2^32 received message
  counters per direction. (See `e2e/replay_protection.py`.)
* **Sequence number:** A 64-bit big-endian counter prepended (inside the
  encrypted payload, not the AAD) to each plaintext.
* **Out-of-window policy:** Reject. There is no "force accept" path.

## 5. Fingerprints

* Public key fingerprints are computed as
  `fingerprint = SHA-256(public_key)[:16]` and rendered as lowercase hex.
* Fingerprints are surfaced to users during the handshake so they can perform
  an out-of-band verification (e.g. safety number compare).

## 6. Failure Modes

* AEAD authentication failure must be treated as a fatal protocol error.
* Replay detection failure must be treated as a fatal protocol error.
* Key derivation inputs that diverge from the canonical layout must be
  rejected before HKDF is invoked.

## 7. Why These Choices

* X25519 gives fast, constant-time ECDH with no patent encumbrance.
* HKDF-SHA256 is well-studied and the salt + info fields give us cheap
  domain separation between sessions and protocol versions.
* AES-256-GCM is hardware-accelerated on essentially every modern CPU and
  provides AEAD in a single pass.
* A 64-bit in-payload counter plus a 32-bit replay window gives us ~2^32
  messages of in-flight tolerance without unbounded state growth.

For code that exercises these patterns end-to-end, see
`examples/encrypted_handshake.py` and the test suite under `tests/`.

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
