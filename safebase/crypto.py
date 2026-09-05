"""Encryption primitives for SafeBase.

Fernet (AES-128-CBC + HMAC-SHA256) is used for file content; PBKDF2-SHA256
derives a Fernet key from the human's password + per-bucket salt.
"""

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet

from safebase.config import _PBKDF2_ITERATIONS


def _derive_fernet_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password + per-bucket salt."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def _encrypt(fernet: Fernet, data: dict[str, Any]) -> bytes:
    plaintext = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return fernet.encrypt(plaintext)


def _decrypt(fernet: Fernet, ciphertext: bytes) -> dict[str, Any]:
    plaintext = fernet.decrypt(ciphertext)
    return json.loads(plaintext.decode("utf-8"))
