"""SafeBase MCP Server - encrypted file-based storage accessed via MCP.

Organizes data as databases > buckets > files. Each file is an encrypted JSON
object. The server is schema-free: the caller decides what fields go in each
file. Encryption uses Fernet (AES-128-CBC + HMAC-SHA256).

The storage root is a git repository. Every put_file and delete_file operation
auto-commits, providing full history and reversion. Since all files are
encrypted (.enc), the git history contains only ciphertext.

Environment variables:
    SAFEBASE_ROOT     - root directory for all databases (required, must be a git repo or will be initialized as one)
    SAFEBASE_PASSWORD - password for encryption key derivation (required)
"""

import base64
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from mcp.server import MCPServer


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fixed salt for PBKDF2 key derivation. The salt does not need to be secret —
# its purpose is to prevent precomputed rainbow table attacks. A fixed
# application-specific salt is standard practice for local encryption tools.
# The security comes from the password, not the salt.
_PBKDF2_SALT = b"safebase-v1-pbkdf2-salt"
_PBKDF2_ITERATIONS = 600_000  # OWASP-recommended minimum for PBKDF2-SHA256


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


def _derive_fernet_key(password: str) -> bytes:
    """Derive a Fernet-compatible key from a password using PBKDF2-SHA256."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        _PBKDF2_SALT,
        _PBKDF2_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def _get_fernet() -> Fernet:
    password = os.environ.get("SAFEBASE_PASSWORD")
    if not password:
        raise RuntimeError("SAFEBASE_PASSWORD environment variable is not set")
    return Fernet(_derive_fernet_key(password))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


def _validate_name(name: str, label: str) -> str:
    if not name:
        raise ValueError(f"{label} cannot be empty")
    if not _NAME_PATTERN.match(name):
        raise ValueError(
            f"{label} '{name}' is invalid: must start with alphanumeric "
            f"and contain only alphanumeric, hyphen, or underscore"
        )
    return name


def _validate_filename(filename: str) -> str:
    if not filename:
        raise ValueError("filename cannot be empty")
    if not filename.endswith(".json"):
        raise ValueError(f"filename '{filename}' must end with .json")
    base = filename[:-5]
    if not _NAME_PATTERN.match(base):
        raise ValueError(
            f"filename '{filename}' is invalid: the part before .json "
            f"must start with alphanumeric and contain only alphanumeric, "
            f"hyphen, or underscore"
        )
    return filename


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _encrypt(fernet: Fernet, data: dict[str, Any]) -> bytes:
    plaintext = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return fernet.encrypt(plaintext)


def _decrypt(fernet: Fernet, ciphertext: bytes) -> dict[str, Any]:
    plaintext = fernet.decrypt(ciphertext)
    return json.loads(plaintext.decode("utf-8"))


# ---------------------------------------------------------------------------
# Git helpers (auto-commit for history and reversion)
# ---------------------------------------------------------------------------

def _git_init(root: Path) -> None:
    """Initialize a git repo at root if not already one. Idempotent."""
    git_dir = root / ".git"
    if git_dir.exists():
        return
    subprocess.run(
        ["git", "init"],
        cwd=str(root),
        capture_output=True,
        check=True,
    )
    # Set a default identity so commits work without global git config
    subprocess.run(
        ["git", "config", "user.name", "SafeBase MCP"],
        cwd=str(root),
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "safebase@local"],
        cwd=str(root),
        capture_output=True,
        check=True,
    )


def _git_commit(root: Path, message: str) -> None:
    """Stage all changes and commit. No-op if there are no changes."""
    _git_init(root)
    # Stage all (add new, modify, delete)
    subprocess.run(
        ["git", "add", "-A"],
        cwd=str(root),
        capture_output=True,
        check=True,
    )
    # Check if there are staged changes to commit
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=str(root),
        capture_output=True,
    )
    # Exit code 0 = no changes, 1 = changes present
    if result.returncode == 0:
        return
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=str(root),
        capture_output=True,
        check=True,
    )


# ---------------------------------------------------------------------------
# Core logic (plain functions, testable without MCP transport)
# ---------------------------------------------------------------------------

def _list_databases() -> list[str]:
    root = _get_root()
    databases = []
    for entry in sorted(root.iterdir()):
        if entry.is_dir() and not entry.name.startswith("."):
            databases.append(entry.name)
    return databases


def _create_database(database: str) -> str:
    root = _get_root()
    _validate_name(database, "database")
    db_path = _db_path(root, database)
    if db_path.exists():
        return f"Database '{database}' already exists"
    db_path.mkdir(parents=True, exist_ok=False)
    # Add .gitkeep so git tracks the empty directory
    (db_path / ".gitkeep").write_text("")
    _git_commit(root, f"create database: {database}")
    return f"Created database '{database}'"


def _list_buckets(database: str) -> list[str] | str:
    root = _get_root()
    db_path = _db_path(root, database)
    if not db_path.exists():
        return f"Database '{database}' does not exist"
    buckets = []
    for entry in sorted(db_path.iterdir()):
        if entry.is_dir() and not entry.name.startswith("."):
            buckets.append(entry.name)
    return buckets


def _create_bucket(database: str, bucket: str) -> str:
    root = _get_root()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")
    bucket_path = _bucket_path(root, database, bucket)
    if bucket_path.exists():
        return f"Bucket '{database}/{bucket}' already exists"
    bucket_path.mkdir(parents=True, exist_ok=False)
    # Add .gitkeep so git tracks the empty directory
    (bucket_path / ".gitkeep").write_text("")
    _git_commit(root, f"create bucket: {database}/{bucket}")
    return f"Created bucket '{database}/{bucket}'"


def _list_files(database: str, bucket: str) -> list[str] | str:
    root = _get_root()
    bucket_path = _bucket_path(root, database, bucket)
    if not bucket_path.exists():
        return f"Bucket '{database}/{bucket}' does not exist"
    files = []
    for entry in sorted(bucket_path.iterdir()):
        if entry.is_file() and entry.name.endswith(".enc"):
            files.append(entry.name[:-4])  # strip .enc
    return files


def _put_file(database: str, bucket: str, filename: str, content: dict[str, Any]) -> str:
    root = _get_root()
    fernet = _get_fernet()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")
    _validate_filename(filename)

    bucket_path = _bucket_path(root, database, bucket)
    if not bucket_path.exists():
        return f"Bucket '{database}/{bucket}' does not exist. Create it first."

    file_path = _file_path(root, database, bucket, filename)
    encrypted = _encrypt(fernet, content)
    file_path.write_bytes(encrypted)
    _git_commit(root, f"put: {database}/{bucket}/{filename}")
    return f"Wrote {database}/{bucket}/{filename} ({len(encrypted)} bytes encrypted)"


def _get_file(database: str, bucket: str, filename: str) -> dict[str, Any] | str:
    root = _get_root()
    fernet = _get_fernet()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")
    _validate_filename(filename)

    file_path = _file_path(root, database, bucket, filename)
    if not file_path.exists():
        return f"File '{database}/{bucket}/{filename}' does not exist"

    ciphertext = file_path.read_bytes()
    return _decrypt(fernet, ciphertext)


def _delete_file(database: str, bucket: str, filename: str) -> str:
    root = _get_root()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")
    _validate_filename(filename)

    file_path = _file_path(root, database, bucket, filename)
    if not file_path.exists():
        return f"File '{database}/{bucket}/{filename}' does not exist"

    file_path.unlink()
    _git_commit(root, f"delete: {database}/{bucket}/{filename}")
    return f"Deleted {database}/{bucket}/{filename}"


def _query_bucket(
    database: str,
    bucket: str,
    filter_fields: dict[str, Any] | None = None,
) -> list[dict[str, Any]] | str:
    root = _get_root()
    fernet = _get_fernet()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")

    bucket_path = _bucket_path(root, database, bucket)
    if not bucket_path.exists():
        return f"Bucket '{database}/{bucket}' does not exist"

    results = []
    for entry in sorted(bucket_path.iterdir()):
        if not (entry.is_file() and entry.name.endswith(".enc")):
            continue
        filename = entry.name[:-4]  # strip .enc
        try:
            data = _decrypt(fernet, entry.read_bytes())
        except Exception as e:
            results.append({"filename": filename, "error": f"Decryption failed: {e}"})
            continue

        if filter_fields:
            match = all(data.get(k) == v for k, v in filter_fields.items())
            if not match:
                continue

        results.append({"filename": filename, **data})

    return results


# ---------------------------------------------------------------------------
# MCP Server (thin wrappers around core logic)
# ---------------------------------------------------------------------------

mcp = MCPServer("SafeBase")


@mcp.tool()
def list_databases() -> str:
    """List all databases (top-level folders) in the storage root.

    Returns a JSON array of database names. A database is a folder directly
    under the storage root. Hidden folders (starting with a dot) are excluded.
    """
    return json.dumps(_list_databases(), indent=2)


@mcp.tool()
def create_database(database: str) -> str:
    """Create a new database (folder) in the storage root.

    Args:
        database: Name of the database to create. Must start with an
            alphanumeric character and contain only alphanumeric, hyphen,
            or underscore characters.

    Returns a confirmation message. If the database already exists, returns
    a message saying so (idempotent operation).
    """
    return _create_database(database)


@mcp.tool()
def list_buckets(database: str) -> str:
    """List all buckets (subfolders) in a database.

    Args:
        database: Name of the database to list buckets from.

    Returns a JSON array of bucket names. A bucket is a subfolder inside a
    database. Hidden folders (starting with a dot) are excluded.
    """
    result = _list_buckets(database)
    if isinstance(result, str):
        return result
    return json.dumps(result, indent=2)


@mcp.tool()
def create_bucket(database: str, bucket: str) -> str:
    """Create a new bucket (subfolder) in a database.

    Args:
        database: Name of the database to create the bucket in.
        bucket: Name of the bucket to create. Must start with an
            alphanumeric character and contain only alphanumeric, hyphen,
            or underscore characters.

    Returns a confirmation message. If the bucket already exists, returns
    a message saying so (idempotent operation).
    """
    return _create_bucket(database, bucket)


@mcp.tool()
def list_files(database: str, bucket: str) -> str:
    """List all files in a bucket.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.

    Returns a JSON array of filenames (without the .enc extension). Each
    filename corresponds to one encrypted JSON file in the bucket.
    """
    result = _list_files(database, bucket)
    if isinstance(result, str):
        return result
    return json.dumps(result, indent=2)


@mcp.tool()
def put_file(database: str, bucket: str, filename: str, content: dict[str, Any]) -> str:
    """Write an encrypted JSON file to a bucket.

    If the file already exists, it is overwritten. The content is serialized
    to JSON, encrypted with Fernet, and written to disk as {filename}.enc.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.
        filename: Name of the file (must end with .json). The stored file
            will have .enc appended.
        content: A JSON object (dict) with arbitrary fields. The structure
            is up to the caller - the server is schema-free.

    Returns a confirmation message.
    """
    return _put_file(database, bucket, filename, content)


@mcp.tool()
def get_file(database: str, bucket: str, filename: str) -> str:
    """Read and decrypt a file from a bucket.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.
        filename: Name of the file (must end with .json).

    Returns the decrypted JSON content as a formatted string. If the file
    does not exist, returns an error message.
    """
    result = _get_file(database, bucket, filename)
    if isinstance(result, str):
        return result
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)


@mcp.tool()
def delete_file(database: str, bucket: str, filename: str) -> str:
    """Delete a file from a bucket.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.
        filename: Name of the file (must end with .json).

    Returns a confirmation message. If the file does not exist, returns
    an error message.
    """
    return _delete_file(database, bucket, filename)


@mcp.tool()
def query_bucket(
    database: str,
    bucket: str,
    filter_fields: dict[str, Any] | None = None,
) -> str:
    """List all files in a bucket with optional field filtering.

    Loads and decrypts every file in the bucket, then optionally filters
    by matching fields. This is a linear scan (no indexes) - fine for
    small buckets, slower for large ones.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.
        filter_fields: Optional dict of field-value pairs to filter by.
            Only files where all specified fields match the specified
            values are returned. If None or empty, all files are returned.

    Returns a JSON array of objects, each containing the filename and its
    decrypted content. Example:
        [{"filename": "cand-001", "name": "Jane", ...}, ...]
    """
    result = _query_bucket(database, bucket, filter_fields)
    if isinstance(result, str):
        return result
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
