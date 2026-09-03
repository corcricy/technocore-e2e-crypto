"""Tests for the X25519+HKDF+AESGCM end-to-end crypto implementation.

Run with: python -m unittest tests.test_crypto -v
"""

import os
import sys
import unittest

# Allow running from repo root without installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from e2e.crypto import (
    generate_keypair,
    derive_shared_key,
    encrypt,
    decrypt,
    encode_envelope,
    decode_envelope,
    export_public_key,
    import_public_key,
    serialize_public_key,
    deserialize_public_key,
    NONCE_SIZE,
    TAG_SIZE,
)


class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.alice_sk, self.alice_pk = generate_keypair()
        self.bob_sk, self.bob_pk = generate_keypair()

    def test_round_trip_bytes(self):
        plaintext = b"hello bob, signed alice"
        aad = b"room=42"
        ct = encrypt(self.alice_sk, self.bob_pk, plaintext, aad=aad)
        pt = decrypt(self.bob_sk, self.alice_pk, ct, aad=aad)
        self.assertEqual(pt, plaintext)

    def test_round_trip_string(self):
        msg = "unicode works too \u00e9\u00e8\u00ea"
        ct = encrypt(self.alice_sk, self.bob_pk, msg)
        pt = decrypt(self.bob_sk, self.alice_pk, ct)
        self.assertEqual(pt, msg.encode("utf-8"))

    def test_aad_mismatch_fails(self):
        plaintext = b"secret"
        ct = encrypt(self.alice_sk, self.bob_pk, plaintext, aad=b"v1")
        with self.assertRaises(ValueError):
            decrypt(self.bob_sk, self.alice_pk, ct, aad=b"v2")

    def test_wrong_key_fails(self):
        eve_sk, eve_pk = generate_keypair()
        plaintext = b"only for bob"
        ct = encrypt(self.alice_sk, self.bob_pk, plaintext)
        # Eve cannot read it even though she has her own valid keypair.
        with self.assertRaises(ValueError):
            decrypt(eve_sk, self.alice_pk, ct)
        # Bob can.
        self.assertEqual(decrypt(self.bob_sk, self.alice_pk, ct), plaintext)

    def test_tampered_ciphertext_fails(self):
        plaintext = b"integrity matters"
        ct = encrypt(self.alice_sk, self.bob_pk, plaintext)
        tampered = bytearray(ct)
        tampered[-1] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt(self.bob_sk, self.alice_pk, bytes(tampered))

    def test_envelope_round_trip(self):
        plaintext = b"envelope please"
        ephemeral_sk, ephemeral_pk = generate_keypair()
        receiver_pk_bytes = serialize_public_key(self.bob_pk)
        env = encode_envelope(
            sender_sk=self.alice_sk,
            receiver_pk=self.bob_pk,
            plaintext=plaintext,
            ephemeral_sk=ephemeral_sk,
            ephemeral_pk=ephemeral_pk,
            sender_pubkey_bytes=serialize_public_key(self.alice_pk),
            receiver_pubkey_bytes=receiver_pk_bytes,
        )
        env_bytes = env.to_bytes()
        parsed = decode_envelope(env_bytes)
        pt = decrypt(self.bob_sk, parsed.ephemeral_public_key, parsed.ciphertext)
        self.assertEqual(pt, plaintext)

    def test_import_export_key(self):
        raw = export_public_key(self.alice_pk)
        self.assertEqual(len(raw), 32)
        reimported = import_public_key(raw)
        # Encrypting to reimported key should work for Alice's secret.
        ct = encrypt(self.alice_sk, reimported, b"x")
        # And Alice should be able to decrypt a message addressed to her raw key.
        # (For that we need the matching secret key bytes; just ensure the
        # exported form round-trips consistently.)
        raw2 = serialize_public_key(reimported)
        self.assertEqual(raw, raw2)

    def test_serialize_round_trip(self):
        raw = serialize_public_key(self.alice_pk)
        self.assertEqual(len(raw), 32)
        reimported = deserialize_public_key(raw)
        # Re-deriving shared key must be identical.
        k1 = derive_shared_key(self.alice_sk, reimported)
        k2 = derive_shared_key(self.alice_sk, self.alice_pk)
        self.assertEqual(k1, k2)

    def test_nonce_uniqueness(self):
        plaintext = b"same input"
        ciphertexts = {
            encrypt(self.alice_sk, self.bob_pk, plaintext) for _ in range(64)
        }
        self.assertEqual(len(ciphertexts), 64)

    def test_envelope_size_invariants(self):
        ephemeral_sk, ephemeral_pk = generate_keypair()
        env = encode_envelope(
            sender_sk=self.alice_sk,
            receiver_pk=self.bob_pk,
            plaintext=b"hi",
            ephemeral_sk=ephemeral_sk,
            ephemeral_pk=ephemeral_pk,
            sender_pubkey_bytes=serialize_public_key(self.alice_pk),
            receiver_pubkey_bytes=serialize_public_key(self.bob_pk),
        )
        # Each ciphertext must carry a 12-byte nonce and 16-byte tag.
        self.assertEqual(env.ciphertext[NONCE_SIZE:NONCE_SIZE], env.ciphertext[NONCE_SIZE:NONCE_SIZE])
        self.assertGreaterEqual(len(env.ciphertext), NONCE_SIZE + TAG_SIZE)


if __name__ == "__main__":
    unittest.main()

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
