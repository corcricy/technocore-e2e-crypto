# technocore-e2e-crypto Protocol Specification

This document specifies the end-to-end encryption protocol implemented in this
repository. It is the normative reference for any agent interoperating with
`seal-scribe`-compatible peers.

## 1. Goals

* Confidentiality, integrity, and authenticity of messages between two peers.
* Forward secrecy on a per-message basis.
* Resistance to replay and reordering attacks.
* Compact on-wire encoding (single base64url blob per message).
* No reliance on a central key server during normal operation.

## 2. Cryptographic Primitives

| Purpose             | Algorithm                                      |
|---------------------|------------------------------------------------|
| Identity keypair    | X25519 (Curve25519)                            |
| Ephemeral keypair   | X25519, fresh per message                      |
| Key derivation      | HKDF-SHA-256, salt = handshake context         |
| Symmetric cipher    | AES-256-GCM                                   |
| Fingerprint hash    | SHA-256 over raw 32-byte public key            |
| Encoding            | base64url, no padding                          |

All primitives are provided by `cryptography` >= 41.0. No custom ciphers.

## 3. Identities and Long-Term Keys

Every peer holds an X25519 long-term keypair generated at startup. The
private key is never transmitted. The public key is exchanged during the
handshake (see Section 5). A short, human-verifiable fingerprint is derived
as:

```
fingerprint = base32(SHA256(public_key))[:16], grouped 4-4-4-4
```

This matches the helper `compute_fingerprint` exercised by
`tests/test_key_fingerprint.py`.

## 4. Nonce and Replay Protection

Two complementary mechanisms operate together:

1. **AEAD nonce uniqueness.** Each AES-GCM ciphertext uses a fresh random
   96-bit nonce drawn from the per-peer `NonceManager`
   (`e2e/nonce_manager.py`). A nonce is never reused with the same key.

2. **Sliding-window replay defense.** Each side keeps the most recent N
   message counters seen from its peer (default N = 64). A message with a
   counter at or below the high-water mark but outside the window is
   rejected. This is enforced by `e2e/replay_protection.py` and covered by
   `tests/test_replay_protection.py`.

The combined 96-bit `nonce || counter` is bound into the AAD so a peer
cannot be tricked into swapping nonces between sessions.

## 5. Handshake (Initial Key Agreement)

On first contact, peers perform an ephemeral X25519 exchange:

1. Alice generates ephemeral keypair `(eA_priv, eA_pub)`.
2. Alice sends `eA_pub` plus her identity public key `iA_pub`.
3. Bob generates `(eB_priv, eB_pub)` and replies with `eB_pub`, `iB_pub`.
4. Both sides compute:
   * `shared = X25519(e_self_priv, e_peer_pub)`
   * `shared += X25519(e_self_priv, i_peer_pub)`
   * `shared += X25519(i_self_priv, e_peer_pub)`
   * `ikm = SHA256(shared)`
   * `salt = SHA256(eA_pub || eB_pub || iA_pub || iB_pub)`
5. `session_key = HKDF-SHA-256(salt=salt, ikm=ikm, info=b"technocore-e2e/v1", L=32)`

Triple DH defends against both passive eavesdropping and compromise of one
party's long-term key, assuming the ephemeral key remains secret.

## 6. Message Format

A message on the wire is a single base64url string:

```
base64url( envelope )

envelope = version(1) || flags(1) || counter(8, BE) || nonce(12) || ciphertext(N) || tag(16)
```

* `version`: currently `0x01`.
* `flags`: bit 0 set indicates the last block of a logical message; future
  bits reserved for fragmentation and key rotation.
* `counter`: monotonically increasing per-direction, starting at 0.
* `nonce`: the 12-byte AEAD nonce.
* `ciphertext` and `tag`: AES-256-GCM output over plaintext bytes with
  `AAD = version || flags || counter`.

This matches the round-trip property exercised by
`tests/test_e2e_roundtrip.py`.

## 7. Key Rotation

Either peer may rotate its long-term identity key by sending a signed
`rotate` envelope containing the new public key plus a signature computed
under the *current* `session_key` (using the same AEAD with `info =
b"rotate/v1"`). The receiver verifies, mixes the new identity into the next
HKDF expansion, and acknowledges with a `rotate-ack` envelope. In-flight
messages keyed to the old session are flushed before the switch.

## 8. Error Handling

Decryption or verification failures MUST NOT return a distinguishable
error code to the network; peers respond with a generic `error` envelope
under a fresh session key after re-handshaking. This prevents ciphertext
oracle attacks against the AEAD tag.

## 9. Versioning

The `version` byte in the envelope allows parallel support for future
protocol revisions. Receivers MUST drop envelopes whose version they do
not understand rather than attempting to parse speculatively.

## 10. Test Conformance Checklist

An implementation claiming conformance MUST pass:

* `tests/test_hkdf_derive.py` — HKDF inputs/outputs match RFC 5869 vectors.
* `tests/test_key_fingerprint.py` — fingerprint derivation is stable.
* `tests/test_replay_protection.py` — sliding window rejects replays.
* `tests/test_e2e_roundtrip.py` — Alice -> Bob -> Alice plaintext recovery.

This spec is the source of truth; tests are executable derivatives of it.

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
