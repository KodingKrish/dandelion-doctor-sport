"""AES-256-GCM encryption for the Golden Vault (Section 7.5: "Writes
AES-256-GCM encrypted vault + plaintext SHA-256 manifest").

Key is derived from an operator-supplied passphrase via PBKDF2-HMAC-SHA256
with a random per-vault salt stored alongside the manifest (never the key
itself). Losing the passphrase means the vault cannot be decrypted — the
plaintext SHA-256 hashes in the manifest remain readable without it, so
integrity of a restore can still be verified once a passphrase is supplied.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

PBKDF2_ITERATIONS = 390_000
SALT_LEN = 16
NONCE_LEN = 12


class DecryptionError(RuntimeError):
    pass


@dataclass
class EncryptedBlob:
    salt: bytes
    nonce: bytes
    ciphertext: bytes  # includes the AES-GCM auth tag

    def to_bytes(self) -> bytes:
        return self.salt + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, blob: bytes) -> "EncryptedBlob":
        if len(blob) < SALT_LEN + NONCE_LEN:
            raise DecryptionError("blob too short to contain salt+nonce")
        return cls(
            salt=blob[:SALT_LEN],
            nonce=blob[SALT_LEN:SALT_LEN + NONCE_LEN],
            ciphertext=blob[SALT_LEN + NONCE_LEN:],
        )


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: bytes, passphrase: str, associated_data: bytes = b"") -> EncryptedBlob:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return EncryptedBlob(salt=salt, nonce=nonce, ciphertext=ciphertext)


def decrypt(blob: EncryptedBlob, passphrase: str, associated_data: bytes = b"") -> bytes:
    key = _derive_key(passphrase, blob.salt)
    try:
        return AESGCM(key).decrypt(blob.nonce, blob.ciphertext, associated_data)
    except Exception as exc:  # wrong passphrase or tampered/corrupted blob
        raise DecryptionError("failed to decrypt — wrong passphrase or corrupted/tampered blob") from exc
