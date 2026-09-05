"""Path resolution for the SafeBase storage tree.

Layout: SAFEBASE_ROOT / database / bucket / file.json.enc
Validation happens here so every caller gets consistent checks.
"""

import os
from pathlib import Path

from safebase.validation import _validate_name, _validate_filename


def _get_root() -> Path:
    root = os.environ.get("SAFEBASE_ROOT")
    if not root:
        raise RuntimeError("SAFEBASE_ROOT environment variable is not set")
    p = Path(root)
    if not p.exists():
        raise RuntimeError(f"SAFEBASE_ROOT does not exist: {root}")
    if not p.is_dir():
        raise RuntimeError(f"SAFEBASE_ROOT is not a directory: {root}")
    return p.resolve()


def _db_path(root: Path, database: str) -> Path:
    _validate_name(database, "database")
    return root / database


def _bucket_path(root: Path, database: str, bucket: str) -> Path:
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")
    return root / database / bucket


def _file_path(root: Path, database: str, bucket: str, filename: str) -> Path:
    _validate_filename(filename)
    return _bucket_path(root, database, bucket) / (filename + ".enc")


def _meta_path(bucket_path: Path) -> Path:
    from safebase.config import _META_FILENAME
    return bucket_path / _META_FILENAME
