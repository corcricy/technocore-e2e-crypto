# technocore E2E Protocol Specification

Version: 0.1.0  Status: Draft

This document specifies the cryptographic wire format used by `technocore-e2e-crypto`. It is the normative reference for the implementation in `e2e/crypto.py`, `e2e/keys.py`, and `e2e/transport.py`.

## 1. Goals and Non-Goals

Goals:
- Provide confidentiality, integrity, and forward secrecy for point-to-point messages between two parties identified by long-term identity keys.
- Be small, auditable, and dependency-light (only `cryptography`).
- Support asynchronous operation: a sender may encrypt before it has observed any message from the recipient.

Non-goals:
- Group messaging, deniability, post-compromise security, and metadata protection are out of scope for v0.1.
- This document does not define the on-wire transport framing; that is delegated to `e2e/transport.py`.

## 2. Cryptographic Primitives

| Function            | Algorithm                                | Notes                                                                 |
|---------------------|------------------------------------------|-----------------------------------------------------------------------|
| Identity key        | Ed25519                                  | Used for signing and as a stable identifier (DID-style fingerprint).  |
| Ephemeral key       | X25519                                   | Generated per session; never reused.                                  |
| Key agreement       | X25519 ECDH                              | Raw shared secret is `Z = X25519(eph_priv, peer_eph_pub)`.             |
| Key derivation      | HKDF-SHA-256                             | `salt = None`, `info = b"technocore-e2e-v1" + sender_id + receiver_id`.|
| Symmetric cipher    | AES-256-GCM                              | 12-byte random nonce, 16-byte tag.                                    |
| KDF input transcript| `Z || eph_pub_sender || eph_pub_receiver`| Fed into HKDF as the IKM.                                             |

All randomness is sourced from `os.urandom` / `cryptography` CSPRNG APIs.

## 3. Identifiers

Each principal is identified by the 32-byte Ed25519 public key of its identity keypair, encoded as `did:key:z6Mk...`. The multibase prefix `z6Mk` corresponds to the multicodec `ed25519-pub` (0xED, 0x01).

A short, human-friendly fingerprint is the lowercase hex of `BLAKE2b-256(identity_pub)[:8]`.

## 4. Session Lifecycle

A session binds a pair of identity keys to a chain of symmetric message keys. There are two phases.

### 4.1 Handshake (one-time per session)

The initiator generates an ephemeral X25519 keypair `(esk, epk)` and sends a `HELLO` envelope:

```
HELLO = {
  "v":       1,
  "type":    "hello",
  "from":    <sender identity pub, 32B>,
  "to":      <receiver identity pub, 32B>,
  "epk":     <ephemeral pub, 32B>,
  "sig":     <Ed25519 sign(sk=identity_priv, msg=epk || to)>
}
```

`sig` binds the ephemeral key to the claimed sender and intended recipient, preventing key-substitution attacks by a relay.

The responder verifies `sig` using `from`, then generates its own ephemeral `(resk, repk)` and replies with a `HELLO_ACK` envelope of the same shape.

Both sides compute:

```
Z        = X25519(esk, repk)
IKM      = Z || epk || repk
session  = HKDF-SHA-256(
             ikm=IKM,
             salt=None,
             info=b"technocore-e2e-v1" + from + to,
             length=32
           )
```

`session` is the 32-byte root key for the session.

### 4.2 Transport (per message)

A symmetric ratchet derives a per-direction message key from a 32-byte chain key, initialised to `session`. Each step:

```
ck_{n+1} = HMAC-SHA-256(key=ck_n, msg=b"technocore-chain-v1")
mk_n    = HMAC-SHA-256(key=ck_{n+1}, msg=b"technocore-msg-v1")
```

The nonce for AES-GCM is `n.to_bytes(12, "big")`. Reuse of a `(key, nonce)` pair is prevented by the strictly increasing chain counter `n`.

The on-wire message body is:

```
HEADER   (32B) : SHA-256(session)  -- session binding
COUNTER  (8B)  : big-endian uint64 n
NONCE    (12B) : per-message nonce (currently == counter, reserved for future randomness)
CIPHERTEXT     : AES-256-GCM(mk_n, nonce, header || counter || nonce, plaintext)
```

The AAD binds the ciphertext to the session and counter, preventing cut-and-paste across sessions or reorder attacks that flip a counter.

### 4.3 Rekey

A rekey is required when the chain counter would exceed 2^48 or after 2^20 messages, whichever comes first. A rekey generates a fresh ephemeral pair and repeats the handshake, deriving a new `session` and resetting both chains to zero. The new session binding is the new header.

## 5. Transport Framing

`e2e/transport.py` provides length-prefixed framing over a duplex stream:

```
[u32 BE length][length bytes payload]
```

A payload is one of the JSON-serialised envelopes defined in section 4. Implementations MUST NOT assume the underlying transport is confidential; the cryptographic envelope provides confidentiality independently.

## 6. Error Handling

- Invalid signature on `HELLO` / `HELLO_ACK`: abort the session, log at WARNING.
- Counter regression or duplicate counter: abort, treat as active attack.
- AAD or tag verification failure: abort, do NOT auto-rekey (an attacker should not be able to force rekey by tampering).
- Session header mismatch: abort.

## 7. Security Considerations

- Forward secrecy is per-session, not per-message. For higher assurance, applications SHOULD rekey frequently.
- The protocol does not hide message length. Padding is the application's responsibility.
- Compromise of a long-term identity key allows an attacker to impersonate that party to peers who have not authenticated the identity out-of-band. Pair `technocore-e2e-crypto` with a TOFU or out-of-band fingerprint check.
- The session binding (`SHA-256(session)`) is logged in cleartext on the wire. A passive observer learns that two parties share a session, but not its contents.

## 8. Versioning

The `"v"` field of every envelope MUST be `1` for this specification. Future versions will be negotiated via a separate mechanism and are not covered here.

## 9. Test Vectors

Test vectors live in `tests/test_crypto.py` and `tests/test_keys.py`. They cover: key generation determinism from a seed, HKDF output, a known-answer handshake, and a known-answer encrypted round-trip. Any change to the primitives or their concatenation order MUST be accompanied by an updated vector.

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
