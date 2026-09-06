# Key Management Guide

This document describes how callers of the `technocore-e2e-crypto` library
should generate, store, rotate, and retire the X25519 key pairs that drive
end-to-end encrypted sessions.

## 1. Key Lifecycle Overview

An X25519 identity key follows four phases:

1. **Generation** — A fresh 32-byte secret scalar is drawn from a
   cryptographically secure RNG. Never reuse a scalar across identities.
2. **Binding** — The corresponding 32-byte public key is derived and
   registered as the agent's identity (e.g. published in a DID document
   or directory record).
3. **Use** — The secret participates in ECDH with peers' ephemeral or
   static keys; HKDF-SHA-256 expands the shared secret into session keys.
4. **Rotation / Retirement** — The old secret is destroyed once all
   sessions using it are closed, or immediately upon suspected compromise.

## 2. Generation

Use `cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate()`.
The library never accepts user-supplied scalars — only this generator or
values loaded from a sealed storage backend.

```python
from cryptography.hazitat.primitives.asymmetric import x25519
sk = x25519.X25519PrivateKey.generate()
pub = sk.public_key().public_bytes_raw()  # 32 bytes
```

## 3. Storage

The private scalar must never appear in plaintext on disk or in logs.
Acceptable backends:

- OS keyring (macOS Keychain, Windows DPAPI, Linux `secretstorage`).
- TPM 2.0 sealed object (`tpm2_createloaded` + policy).
- A hardware token (YubiKey PIV slot 9d, Nitrokey, etc.).
- An HSM reachable over PKCS#11.

If you must store the key in a file, encrypt it with a passphrase using
the same AES-GCM primitive the library exposes (`AEAD.encrypt`), with a
random 32-byte key derived via Argon2id from the passphrase. Rotate the
wrapping key on the same cadence as the identity key.

## 4. Fingerprints

Publish the SHA-256 fingerprint of the raw 32-byte public key (see
`e2e/key_fingerprint.py`):

```python
from e2e.key_fingerprint import fingerprint_public_key
print(fingerprint_public_key(pub))  # 'fp:9b1f...:4a7c'
```

Fingerprints — not raw keys — are what humans should compare out of band.
The `fp:` prefix and the colon-grouped hex aid visual verification.

## 5. Rotation Policy

Recommended defaults for a long-lived agent identity:

| Event | Action |
|-------|--------|
| Scheduled (90 days) | Generate new keypair, publish new public key alongside old. |
| Peer compromise | Immediately retire the affected keypair; notify peers via signed rotation message. |
| Loss of device | Revoke the keypair; rely on a secondary pre-shared recovery key. |
| Software upgrade touching crypto path | Rotate as a precaution. |

During a rotation window both old and new public keys are accepted. After
the window only the new key is honored; inbound traffic to the old key is
rejected and the sender is asked to re-handshake.

## 6. Compromise Response

If a private scalar is exposed:

1. Mark the fingerprint as revoked in your directory.
2. Tear down every session whose `session_key` was derived via HKDF
   involving that scalar — `e2e/session.py` exposes `Session.invalidate()`.
3. Force a fresh handshake with every known peer, using the new identity.
4. Audit the `replay_log` (see `e2e/replay_protection.py`) for messages
   accepted under the compromised key; replay those at the application
   layer where appropriate.

## 7. Multi-Device Use

The protocol assumes one identity key per device. To sync across devices:

- Each device generates its own X25519 keypair.
- All device public keys are listed under a single agent DID.
- Peers pick the device key by routing hint or last-seen timestamp.
- A device that loses its secret does not compromise the agent's other
  devices; only that device's sessions are invalidated.

## 8. Do Not

- Reuse a scalar as both an X25519 key and an Ed25519 signing key — they
  live in different code paths and conflating them invites cross-protocol
  attacks.
- Derive session keys without a fresh HKDF salt per session.
- Log raw public keys together with session IDs in persistent storage.
- Skip the `replay_protection` check on inbound frames — it is the only
  line of defense against an attacker who captures a ciphertext.

Following this guide keeps the cryptographic identity of an agent
auditable, recoverable, and bounded in blast radius when incidents occur.

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
