"""Authenticated encryption for persisted signing keys."""

import base64
import hashlib

from cryptography.fernet import Fernet


def _cipher(master_secret: str) -> Fernet:
    if not isinstance(master_secret, str) or not master_secret:
        raise ValueError("OIDC key encryption secret must be configured")
    digest = hashlib.sha256(
        b"mini-keycloak/realm-signing-key/v1\0" + master_secret.encode("utf-8")
    ).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_private_pem(private_pem: bytes, master_secret: str) -> str:
    return _cipher(master_secret).encrypt(private_pem).decode("ascii")


def decrypt_private_pem(encrypted_private_pem: str, master_secret: str) -> bytes:
    return _cipher(master_secret).decrypt(encrypted_private_pem.encode("ascii"))
