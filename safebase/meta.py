"""Per-bucket password metadata (bcrypt hash + PBKDF2 salt).

The raw password is NEVER stored on disk — only a one-way bcrypt hash and a
per-bucket salt live in `.safebase-meta.json`. Corrupted metadata is treated
as "no password set" so the create-password dialog re-appears on next use.
"""

import base64
import bcrypt
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from safebase.config import _META_VERSION
from safebase.paths import _meta_path


@dataclass
class BucketMeta:
    """Per-bucket password metadata. Stored as `.safebase-meta.json`."""
    bcrypt_hash: str       # bcrypt hash of the password (one-way)
    pbkdf2_salt: str       # base64-encoded per-bucket salt for Fernet key derivation
    created_at: str        # ISO timestamp


def _generate_bucket_meta(password: str) -> BucketMeta:
    """Generate salt + bcrypt hash for a password (in memory, no disk write)."""
    salt = secrets.token_bytes(32)
    bcrypt_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    return BucketMeta(
        bcrypt_hash=bcrypt_hash,
        pbkdf2_salt=base64.b64encode(salt).decode("ascii"),
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


def _write_bucket_meta(bucket_path: Path, meta: BucketMeta) -> None:
    """Write metadata file for a bucket to disk."""
    _meta_path(bucket_path).write_text(
        json.dumps({
            "version": _META_VERSION,
            "bcrypt_hash": meta.bcrypt_hash,
            "pbkdf2_salt": meta.pbkdf2_salt,
            "created_at": meta.created_at,
        }, indent=2),
        encoding="utf-8",
    )


def _store_bucket_meta(bucket_path: Path, password: str) -> BucketMeta:
    """Generate salt + bcrypt hash and write metadata file for a bucket."""
    meta = _generate_bucket_meta(password)
    _write_bucket_meta(bucket_path, meta)
    return meta


def _load_bucket_meta(bucket_path: Path) -> Optional[BucketMeta]:
    """Load metadata for a bucket. Returns None if no metadata file exists.

    Returns None (rather than raising) if the metadata file is corrupted,
    missing required keys, or contains invalid JSON. This lets the caller
    treat a corrupted bucket as having no password (triggering the
    create-password dialog on next use).
    """
    p = _meta_path(bucket_path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return BucketMeta(
            bcrypt_hash=data["bcrypt_hash"],
            pbkdf2_salt=data["pbkdf2_salt"],
            created_at=data["created_at"],
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        return None


def _verify_password(password: str, bcrypt_hash: str) -> bool:
    """Verify a password against a stored bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), bcrypt_hash.encode("utf-8"))


def _bucket_has_password(bucket_path: Path) -> bool:
    """Check whether a bucket has a password set (metadata file exists)."""
    return _meta_path(bucket_path).exists()
