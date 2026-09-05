# API Reference: technocore-e2e-crypto

This document describes the public Python API exposed by the `e2e` package.
All primitives follow the patterns documented in `docs/protocol-spec.md` and
`docs/cryptography-architecture.md`. Cryptographic choices: X25519 for key
agreement, HKDF-SHA-256 for key derivation, AES-256-GCM for authenticated
encryption. Every public function accepts and returns objects whose
serializations are stable across the protocol boundary.

---

## Module: `e2e.session`

### `class E2ESession`

Stateful object that performs an X25519+HKDF+AESGCM handshake with a peer and
then encrypts/decrypts application payloads.

#### Constructor

```python
E2ESession(
    role: Literal["initiator", "responder"],
    static_private: x25519.X25519PrivateKey,
    static_public: x25519.X25519PublicKey,
    psk: bytes,
    *, 
    info: bytes = b"technocore-e2e/v1",
)
```

| Parameter      | Type                       | Description                                                                 |
| -------------- | -------------------------- | --------------------------------------------------------------------------- |
| `role`         | `str`                      | `"initiator"` if this side sends the first handshake message, else `"responder"`. |
| `static_private` | `X25519PrivateKey`       | This endpoint's long-term X25519 private key (32 bytes, raw).               |
| `static_public`  | `X25519PublicKey`        | This endpoint's long-term X25519 public key (32 bytes, raw).                |
| `psk`          | `bytes`                    | Pre-shared secret, mixed into HKDF as the salt. Recommended >= 32 bytes of high-entropy material. |
| `info`         | `bytes`                    | Context label for HKDF. Defaults to the protocol constant.                  |

The constructor validates key lengths and `psk` (must be >= 16 bytes). It does
not perform any I/O.

#### Methods

##### `create_handshake_message() -> HandshakeMessage`

Produces the local handshake message containing an ephemeral X25519 public key
and a nonce. The caller is responsible for transmitting this to the peer over
the (already authenticated) transport.

##### `process_handshake_message(msg: HandshakeMessage) -> None`

Validates and consumes the peer's handshake message. After successful
processing, both sides have derived the same 32-byte traffic key. Raises
`e2e.errors.HandshakeError` on protocol violations.

##### `encrypt(plaintext: bytes, *, aad: bytes = b"") -> bytes`

Encrypts `plaintext` with the session traffic key and returns a self-contained
ciphertext frame. `aad` is bound to the AEAD but is *not* encrypted; it is the
caller's responsibility to deliver identical `aad` on decryption. Output layout:

```
| 12-byte nonce | 16-byte tag | ciphertext ... |
```

##### `decrypt(frame: bytes, *, aad: bytes = b"") -> bytes`

Decrypts a frame produced by `encrypt`. The 28-byte overhead (nonce + tag) is
stripped. Raises `e2e.errors.DecryptError` on tag mismatch or wrong AAD.

##### Properties

* `is_handshake_complete: bool` — True once both sides have exchanged
  handshake messages.
* `session_id: bytes` — stable 16-byte identifier for the session, derived
  from the handshake transcript; useful for logging.
* `send_counter: int` — number of frames successfully encrypted by this side.
* `recv_counter: int` — number of frames successfully decrypted by this side.

---

## Module: `e2e.key_fingerprint`

### `fingerprint(public_key: x25519.X25519PublicKey | bytes, *, version: int = 1) -> str`

Returns a stable, lowercase, colon-separated hex fingerprint suitable for
out-of-band verification by humans. Format:

```
v<version>:<hex32>:<hex32>:<hex32>:<hex32>
```

The fingerprint is `HKDF-Extract-and-Expand` of the raw 32-byte public key with
an empty salt and the info string `b"technocore-e2e/fingerprint/v1"`, truncated
to 128 bits and grouped for readability.

### `class FingerprintMismatchError(Exception)`

Raised when verification helpers detect a peer fingerprint that does not
match the expected value. The exception carries `expected` and `got` string
attributes so UIs can render a clear warning.

---

## Module: `e2e.errors`

All exceptions raised by the package inherit from `E2EError`:

| Exception           | Cause                                                    |
| ------------------- | -------------------------------------------------------- |
| `HandshakeError`    | Protocol violation, missing message, or stale nonce.     |
| `DecryptError`      | AEAD authentication failure.                             |
| `KeyFormatError`    | A supplied key is not a valid 32-byte X25519 key.         |
| `ReplayedMessageError` | Replay protection triggered on handshake.             |

Catching `E2EError` is sufficient to handle any library failure.

---

## Module: `e2e.utils`

### `encode_point(pub: x25519.X25519PublicKey) -> bytes`

Returns the canonical 32-byte X25519 public key encoding.

### `decode_point(raw: bytes) -> x25519.X25519PublicKey`

Inverse of `encode_point`. Raises `KeyFormatError` for wrong lengths.

### `constant_time_eq(a: bytes, b: bytes) -> bool`

Constant-time comparison, intended for MAC/tag checks outside the AEAD layer.

---

## Example: end-to-end usage

```python
from cryptography.hazmat.primitives.asymmetric import x25519
from e2e.session import E2ESession
from e2e.key_fingerprint import fingerprint

alice_priv = x25519.X25519PrivateKey.generate()
bob_priv   = x25519.X25519PrivateKey.generate()

print("Alice FP:", fingerprint(alice_priv.public_key()))
print("Bob FP:  ", fingerprint(bob_priv.public_key()))

alice = E2ESession("initiator", alice_priv, alice_priv.public_key(), psk=b"shared-secret")
bob   = E2ESession("responder",  bob_priv,   bob_priv.public_key(),   psk=b"shared-secret")

ah = alice.create_handshake_message()
bh = bob.create_handshake_message()
alice.process_handshake_message(bh)
bob.process_handshake_message(ah)

ct = alice.encrypt(b"hello, bob", aad=b"msg/1")
pt = bob.decrypt(ct, aad=b"msg/1")
assert pt == b"hello, bob"
```

---

## Stability

The `e2e` package follows semantic versioning. The on-the-wire formats
described in `docs/protocol-spec.md` are stable across the `1.x` series.
Breaking a wire format requires a major version bump and a new `info` label
in HKDF.

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
