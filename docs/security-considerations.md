# Security Considerations

This document captures the threat model, pitfalls, and hardening guidance for the
X25519 + HKDF + AES-256-GCM construction used throughout `technocore-e2e-crypto`.
It is intended for protocol implementers and security reviewers.

## 1. Threat Model

We assume:

- A passive or active network adversary between the two endpoints.
- The adversary can read, reorder, replay, and inject ciphertext.
- The adversary does **not** have access to long-term private keys or the
  process memory of either endpoint.
- Either endpoint may be malicious; the protocol does not provide
  authentication of the *peer* identity beyond possession of the remote
  static public key.

Out of scope:

- Side-channel attacks on the local process (timing, cache, fault injection).
  We use constant-time primitives where available but make no exhaustive claim.
- Compromised endpoints. Once a private key leaks, all past and future
  sessions derived from it are compromised unless forward secrecy is used
  (see §3).
- Metadata protection. Message timing and size are observable.

## 2. Cryptographic Building Blocks

| Primitive | Purpose | Notes |
|---|---|---|
| X25519 (RFC 7748) | Ephemeral and static ECDH | Clamp scalar; reject all-zero shared secret. |
| HKDF-SHA-256 (RFC 5869) | Derive session keys from IKM | Always include `salt` and `info`. Never reuse a (salt, info) pair across contexts. |
| AES-256-GCM (RFC 5116/5288) | Authenticated encryption | 96-bit random nonce, 128-bit tag. |
| BLAKE2b | Key fingerprinting | 256-bit truncated digest for human comparison. |

## 3. Forward Secrecy

The handshake in `examples/encrypted_handshake.py` mixes a long-term static
X25519 key with a fresh ephemeral key on every session:

```
shared_secret = X25519(ephemeral_priv, remote_static_pub)
              || X25519(static_priv, remote_ephemeral_pub)
```

If either party's static private key is later disclosed, prior sessions remain
secure because the ephemeral keys are destroyed immediately after the handshake
(see §6).

**Do not** derive the session key from the static keypair alone.

## 4. Replay Protection

`e2e/replay_protection.py` enforces three independent checks per inbound
ciphertext:

1. **Nonce window**: reject nonces outside the sliding receive window.
2. **Sequence number**: strictly monotonic per direction.
3. **AEAD tag**: any decryption failure aborts the session.

A nonce reuse under the same key is catastrophic for GCM. The 96-bit random
nonce gives ~2^48 messages per key before collision probability reaches 2^-32,
which is the operational ceiling before rekeying.

## 5. Key Fingerprint Verification

To prevent MITM during initial key exchange, callers MUST compare the
BLAKE2b-256 fingerprints of the remote static public key over an
out-of-band channel (voice, QR code, in-person). See
`tests/test_key_fingerprint.py` for the canonical encoding:

```
fingerprint = BLAKE2b(pubkey_bytes, digest_size=32)
display     = base32(fingerprint)  # chunked for readability
```

Never skip this step in deployment. The cryptographic handshake is only as
strong as the authenticity of the static keys used in it.

## 6. Ephemeral Key Hygiene

- Generate ephemeral keypairs with a CSPRNG immediately before each handshake.
- Zeroize the private scalar with a constant-time wipe as soon as the shared
  secret and session keys are derived.
- Never persist ephemeral private material to disk.
- Never log the shared secret, the derived session key, or the HKDF output.

## 7. Rekeying Policy

Rekey before any of:

- 2^48 messages sent under one key (nonce exhaustion bound).
- 2^32 messages sent (defensive margin; cheaper bound).
- 7 days of session lifetime.
- Application-level signal (e.g., user logout, channel rotation).

The rekey path is identical to the initial handshake but produces fresh
session keys without disturbing the in-order stream (sequence numbers
continue monotonically).

## 8. Implementation Pitfalls

| Pitfall | Consequence |
|---|---|
| Reusing a (salt, info) pair in HKDF for two different contexts | Key reuse across contexts; attacker can correlate. |
| Using a 64-bit nonce for AES-GCM | Reduced collision margin; some libraries warn, others silently accept. |
| Skipping the `info` parameter in HKDF | Loss of domain separation between handshake, application data, and rekey. |
| Treating AEAD tag failure as recoverable | Indicates tampering or corruption; abort the session. |
| Deriving keys from `X25519(priv, pub)` without checking for all-zero output | Catastrophic key collapse; ~1 in 2^125 chance per handshake but trivially preventable. |
| Comparing fingerprints with `==` on attacker-controlled input | Timing oracle; use a constant-time compare. |

## 9. What This Library Does Not Provide

- Peer identity authentication (you must verify fingerprints).
- PFS across *compromise of the ephemeral RNG* (a bad RNG breaks the session).
- Resistance to compulsion attacks (legal or physical coercion to disclose keys).
- Quantum security. X25519 is broken by a sufficiently large quantum computer;
  if that is in your threat model, layer a post-quantum KEM such as ML-KEM-768.

## 10. Reporting Issues

Security-relevant issues should be reported privately to the maintainers
listed in `README.md`. Please do not open public issues for vulnerabilities
before a fix is available.

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
