"""SafeBase MCP Server - encrypted file-based storage accessed via MCP.

Organizes data as databases > buckets > files. Each file is an encrypted JSON
object. The server is schema-free: the caller decides what fields go in each
file. Encryption uses Fernet (AES-128-CBC + HMAC-SHA256).

Each bucket has its own password, set by the human via a native OS dialog on
first use. The password is never stored in plaintext — only a bcrypt hash and
a per-bucket PBKDF2 salt live in `.safebase-meta.json` inside the bucket. The
raw password exists only in server memory for the duration the human chooses
(5/10/15 minutes, or process lifetime).

The AI agent never sees the password. The dialog is shown by this server
process directly on the human's desktop (via tkinter); the AI has no visibility
into it.

Environment variables:
    SAFEBASE_ROOT     - root directory for all databases (required, must be a
                        git repo or will be initialized as one)
"""

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import bcrypt
from cryptography.fernet import Fernet
from mcp.server import MCPServer


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 600_000  # OWASP-recommended minimum for PBKDF2-SHA256
_META_FILENAME = ".safebase-meta.json"
_META_VERSION = 1

# Session duration options in minutes. 0 means process lifetime (no timeout).
_DURATION_OPTIONS = (5, 10, 15, 0)
_DEFAULT_DURATION = 5  # preselected in the dialog


# ---------------------------------------------------------------------------
# Root access
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

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


def _meta_path(bucket_path: Path) -> Path:
    return bucket_path / _META_FILENAME


# ---------------------------------------------------------------------------
# Bucket metadata (password hash + salt)
# ---------------------------------------------------------------------------

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
# In-memory key cache (per bucket, with idle timeout)
# ---------------------------------------------------------------------------

@dataclass
class _CachedKey:
    fernet: Fernet
    expires_at: float       # unix timestamp; float("inf") for process lifetime
    duration_minutes: int   # original duration, for resetting the idle timer


_key_cache: dict[str, _CachedKey] = {}
# key: f"{database}/{bucket}"


def _cache_key(database: str, bucket: str) -> str:
    return f"{database}/{bucket}"


def _get_cached_key(database: str, bucket: str) -> Optional[Fernet]:
    """Return a cached Fernet if present and not expired, else None."""
    ck = _key_cache.get(_cache_key(database, bucket))
    if ck is None:
        return None
    if ck.expires_at != float("inf") and time.time() > ck.expires_at:
        _key_cache.pop(_cache_key(database, bucket), None)
        return None
    return ck.fernet


def _store_cached_key(database: str, bucket: str, fernet: Fernet, duration_minutes: int) -> None:
    """Store a Fernet key in the cache with the given idle timeout.

    Negative or non-integer durations are clamped to 0 (process lifetime)
    to prevent immediate expiry from a misbehaving dialog implementation.
    """
    if not isinstance(duration_minutes, int) or duration_minutes < 0:
        duration_minutes = 0
    if duration_minutes == 0:
        expires_at = float("inf")  # process lifetime
    else:
        expires_at = time.time() + (duration_minutes * 60)
    _key_cache[_cache_key(database, bucket)] = _CachedKey(
        fernet=fernet, expires_at=expires_at, duration_minutes=duration_minutes
    )


def _touch_cached_key(database: str, bucket: str) -> None:
    """Reset the idle timer for a cached key (called on each use)."""
    ck = _key_cache.get(_cache_key(database, bucket))
    if ck is None or ck.duration_minutes == 0:
        return
    ck.expires_at = time.time() + (ck.duration_minutes * 60)


def _clear_cached_key(database: str, bucket: str) -> None:
    """Remove a bucket's key from the cache (e.g. on password change or delete)."""
    _key_cache.pop(_cache_key(database, bucket), None)


# ---------------------------------------------------------------------------
# Dialog interface (injectable for tests)
# ---------------------------------------------------------------------------

@dataclass
class DialogResult:
    """Result of a password dialog. password is None if the human cancelled."""
    password: Optional[str]
    duration_minutes: int  # one of _DURATION_OPTIONS


# Module-level dialog function references. Default implementations use tkinter.
# Tests monkeypatch these to inject canned passwords without a GUI.
_prompt_create_password_fn: Callable[[str, str], Optional[DialogResult]] = None  # type: ignore
_prompt_enter_password_fn: Callable[[str, str], Optional[DialogResult]] = None  # type: ignore
_prompt_change_password_fn: Callable[[str, str], Optional[DialogResult]] = None  # type: ignore


def _default_create_password_dialog(database: str, bucket: str) -> Optional[DialogResult]:
    """Show a tkinter dialog to create a new bucket password."""
    return _tkinter_dialog(
        title=f"SafeBase — Create Password",
        prompt=f"Create a password for bucket:\n{database}/{bucket}",
        confirm=True,
    )


def _default_enter_password_dialog(database: str, bucket: str) -> Optional[DialogResult]:
    """Show a tkinter dialog to enter an existing bucket password."""
    return _tkinter_dialog(
        title=f"SafeBase — Enter Password",
        prompt=f"Enter password for bucket:\n{database}/{bucket}",
        confirm=False,
    )


def _default_change_password_dialog(database: str, bucket: str) -> Optional[DialogResult]:
    """Show a tkinter dialog to enter a new bucket password (for change)."""
    return _tkinter_dialog(
        title=f"SafeBase — New Password",
        prompt=f"Enter NEW password for bucket:\n{database}/{bucket}",
        confirm=True,
    )


def _tkinter_dialog(title: str, prompt: str, confirm: bool) -> Optional[DialogResult]:
    """Build and run a tkinter password dialog. Returns None on cancel."""
    try:
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        raise RuntimeError(
            "tkinter is not available. SafeBase requires a display and tkinter "
            "to prompt the human for the password. This cannot run headless."
        )

    result: dict[str, Any] = {"password": None, "duration": _DEFAULT_DURATION, "ok": False}

    def on_ok():
        if confirm and entry.get() != confirm_entry.get():
            error_label.config(text="Passwords do not match")
            return
        if not entry.get():
            error_label.config(text="Password cannot be empty")
            return
        result["password"] = entry.get()
        result["duration"] = int(duration_var.get())
        result["ok"] = True
        root.destroy()

    def on_cancel():
        root.destroy()

    root = tk.Tk()
    root.title(title)
    root.resizable(False, False)

    frame = ttk.Frame(root, padding=16)
    frame.grid(row=0, column=0, sticky="nsew")

    ttk.Label(frame, text=prompt).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

    ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky="w", pady=2)
    entry = ttk.Entry(frame, show="*", width=32)
    entry.grid(row=1, column=1, pady=2)
    entry.focus_set()

    confirm_entry = None
    if confirm:
        ttk.Label(frame, text="Confirm:").grid(row=2, column=0, sticky="w", pady=2)
        confirm_entry = ttk.Entry(frame, show="*", width=32)
        confirm_entry.grid(row=2, column=1, pady=2)

    ttk.Label(frame, text="Keep unlocked for:").grid(row=3, column=0, sticky="w", pady=(12, 2))
    duration_var = tk.IntVar(value=_DEFAULT_DURATION)
    dur_frame = ttk.Frame(frame)
    dur_frame.grid(row=3, column=1, sticky="w", pady=(12, 2))
    for i, mins in enumerate(_DURATION_OPTIONS):
        label = f"{mins} min" if mins > 0 else "Process lifetime"
        rb = ttk.Radiobutton(dur_frame, text=label, variable=duration_var, value=mins)
        rb.grid(row=0, column=i, padx=2)

    error_label = ttk.Label(frame, text="", foreground="red")
    error_label.grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))

    btn_frame = ttk.Frame(frame)
    btn_frame.grid(row=5, column=0, columnspan=2, pady=(16, 0))
    ttk.Button(btn_frame, text="Cancel", command=on_cancel).grid(row=0, column=0, padx=4)
    ttk.Button(btn_frame, text="Unlock" if not confirm else "Create", command=on_ok).grid(row=0, column=1, padx=4)

    root.bind("<Return>", lambda e: on_ok())
    root.bind("<Escape>", lambda e: on_cancel())

    root.mainloop()

    if not result["ok"]:
        return None
    return DialogResult(password=result["password"], duration_minutes=result["duration"])


# Initialize the dialog functions to the tkinter defaults.
# Tests override these after import.
_prompt_create_password_fn = _default_create_password_dialog
_prompt_enter_password_fn = _default_enter_password_dialog
_prompt_change_password_fn = _default_change_password_dialog


# ---------------------------------------------------------------------------
# Central gate: get a Fernet key for a bucket (prompting the human if needed)
# ---------------------------------------------------------------------------

class AccessDenied(Exception):
    """Raised when the human cancels the password dialog."""


_MAX_PASSWORD_ATTEMPTS = 3


def _get_bucket_key(database: str, bucket: str) -> Fernet:
    """Return a Fernet for the bucket, prompting the human if needed.

    This is the single gate through which all crypto operations pass. It:
    1. Checks the in-memory key cache — returns immediately if valid.
    2. If no key cached, checks for bucket metadata:
       a. No metadata (or corrupted) → first use → show create-password dialog.
       b. Metadata exists → show enter-password dialog, verify against bcrypt.
          Allows up to _MAX_PASSWORD_ATTEMPTS retries on wrong password.
    3. Derives the Fernet key from the raw password + stored salt.
    4. Caches the key with the human-chosen duration.
    5. Returns the Fernet.

    Raises AccessDenied if the human cancels the dialog or exceeds the
    maximum number of wrong-password attempts.
    """
    # 1. Check cache
    cached = _get_cached_key(database, bucket)
    if cached is not None:
        _touch_cached_key(database, bucket)
        return cached

    root = _get_root()
    bp = _bucket_path(root, database, bucket)
    if not bp.exists():
        raise RuntimeError(f"Bucket '{database}/{bucket}' does not exist")

    # 2a. First use — no metadata (or corrupted metadata) → create password
    meta = _load_bucket_meta(bp)
    if meta is None:
        result = _prompt_create_password_fn(database, bucket)
        if result is None or result.password is None:
            raise AccessDenied("User cancelled password creation")
        meta = _store_bucket_meta(bp, result.password)
    else:
        # 2b. Subsequent use — verify against stored bcrypt hash
        #     Allow retries on wrong password (up to _MAX_PASSWORD_ATTEMPTS).
        result = None
        for attempt in range(_MAX_PASSWORD_ATTEMPTS):
            result = _prompt_enter_password_fn(database, bucket)
            if result is None or result.password is None:
                raise AccessDenied("User cancelled password entry")
            if _verify_password(result.password, meta.bcrypt_hash):
                break
            if attempt < _MAX_PASSWORD_ATTEMPTS - 1:
                # Re-prompt — the dialog implementation is responsible for
                # showing an error message. Here we just loop.
                continue
            raise AccessDenied("Incorrect password (max attempts exceeded)")
        # result is guaranteed to be set and verified here

    # 3. Derive Fernet key
    salt = base64.b64decode(meta.pbkdf2_salt)
    fernet = Fernet(_derive_fernet_key(result.password, salt))

    # 4. Cache
    _store_cached_key(database, bucket, fernet, result.duration_minutes)

    return fernet


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
    subprocess.run(
        ["git", "add", "-A"],
        cwd=str(root),
        capture_output=True,
        check=True,
    )
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=str(root),
        capture_output=True,
    )
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
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")
    _validate_filename(filename)

    bucket_path = _bucket_path(root, database, bucket)
    if not bucket_path.exists():
        return f"Bucket '{database}/{bucket}' does not exist. Create it first."

    try:
        fernet = _get_bucket_key(database, bucket)
    except AccessDenied as e:
        return f"Access denied: {e}"

    file_path = _file_path(root, database, bucket, filename)
    encrypted = _encrypt(fernet, content)
    file_path.write_bytes(encrypted)
    _git_commit(root, f"put: {database}/{bucket}/{filename}")
    return f"Wrote {database}/{bucket}/{filename} ({len(encrypted)} bytes encrypted)"


def _get_file(database: str, bucket: str, filename: str) -> dict[str, Any] | str:
    root = _get_root()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")
    _validate_filename(filename)

    file_path = _file_path(root, database, bucket, filename)
    if not file_path.exists():
        return f"File '{database}/{bucket}/{filename}' does not exist"

    try:
        fernet = _get_bucket_key(database, bucket)
    except AccessDenied as e:
        return f"Access denied: {e}"

    ciphertext = file_path.read_bytes()
    try:
        return _decrypt(fernet, ciphertext)
    except Exception as e:
        return f"Decryption failed for '{database}/{bucket}/{filename}': {e}"


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


def _delete_bucket(database: str, bucket: str) -> str:
    """Delete a bucket folder and all its contents. No key needed."""
    root = _get_root()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")

    bucket_path = _bucket_path(root, database, bucket)
    if not bucket_path.exists():
        return f"Bucket '{database}/{bucket}' does not exist"

    shutil.rmtree(bucket_path)
    _clear_cached_key(database, bucket)
    _git_commit(root, f"delete bucket: {database}/{bucket}")
    return f"Deleted bucket '{database}/{bucket}'"


def _query_bucket(
    database: str,
    bucket: str,
    filter_fields: dict[str, Any] | None = None,
) -> list[dict[str, Any]] | str:
    root = _get_root()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")

    bucket_path = _bucket_path(root, database, bucket)
    if not bucket_path.exists():
        return f"Bucket '{database}/{bucket}' does not exist"

    try:
        fernet = _get_bucket_key(database, bucket)
    except AccessDenied as e:
        return f"Access denied: {e}"

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


def _change_bucket_password(database: str, bucket: str) -> str:
    """Change a bucket's password. Re-encrypts all files with the new key.

    Order of operations is critical for data safety:
    1. Verify old password
    2. Decrypt all files with old key (in memory)
    3. Generate new key (in memory only — do NOT write metadata yet)
    4. Re-encrypt all files with new key (write to disk)
    5. Only after all files are successfully re-encrypted, write new metadata
    6. Update the in-memory key cache

    If any step fails before step 5, the old metadata is still on disk and
    all files are still encrypted with the old key — no data loss.
    """
    root = _get_root()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")

    bucket_path = _bucket_path(root, database, bucket)
    if not bucket_path.exists():
        return f"Bucket '{database}/{bucket}' does not exist"

    meta = _load_bucket_meta(bucket_path)
    if meta is None:
        return f"Bucket '{database}/{bucket}' has no password set yet. Use put_file to set one."

    # Clear the old cached key before starting, so no stale key can be used
    # by another code path mid-operation.
    _clear_cached_key(database, bucket)

    # 1. Verify the old password
    old_result = _prompt_enter_password_fn(database, bucket)
    if old_result is None or old_result.password is None:
        return "Access denied: user cancelled"
    if not _verify_password(old_result.password, meta.bcrypt_hash):
        return "Access denied: incorrect current password"

    old_salt = base64.b64decode(meta.pbkdf2_salt)
    old_fernet = Fernet(_derive_fernet_key(old_result.password, old_salt))

    # 2. Get the new password
    new_result = _prompt_change_password_fn(database, bucket)
    if new_result is None or new_result.password is None:
        return "Password change cancelled"
    if new_result.password == old_result.password:
        return "New password must be different from the current one"

    # 3. Decrypt all files with the old key (in memory)
    enc_files: list[tuple[str, dict[str, Any]]] = []
    for entry in sorted(bucket_path.iterdir()):
        if not (entry.is_file() and entry.name.endswith(".enc")):
            continue
        filename = entry.name[:-4]
        try:
            data = _decrypt(old_fernet, entry.read_bytes())
        except Exception as e:
            return f"Failed to decrypt {filename} with old password: {e}. Aborting, no files changed."
        enc_files.append((filename, data))

    # 4. Generate new key (in memory only — do NOT write metadata yet)
    new_meta = _generate_bucket_meta(new_result.password)
    new_salt = base64.b64decode(new_meta.pbkdf2_salt)
    new_fernet = Fernet(_derive_fernet_key(new_result.password, new_salt))

    # 5. Re-encrypt all files with the new key (write to disk)
    #    If this fails partway, the old metadata is still on disk. Files
    #    that were already re-encrypted are lost, but the remaining files
    #    are still decryptable with the old password. This is the best we
    #    can do without a transactional filesystem.
    for filename, data in enc_files:
        file_path = bucket_path / (filename + ".enc")
        file_path.write_bytes(_encrypt(new_fernet, data))

    # 6. Only now write the new metadata to disk
    _write_bucket_meta(bucket_path, new_meta)

    # 7. Update the in-memory key cache
    _store_cached_key(database, bucket, new_fernet, new_result.duration_minutes)

    _git_commit(root, f"change password: {database}/{bucket}")
    return f"Password changed for '{database}/{bucket}'. {len(enc_files)} file(s) re-encrypted."


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

    The bucket has no password until the first put_file call, at which point
    a dialog will appear on the human's screen to create one.

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

    If this is the first write to the bucket, a dialog will appear on the
    human's screen to create a password for the bucket. On subsequent writes,
    if the key is not in memory (or has expired), a dialog will appear to
    enter the password.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.
        filename: Name of the file (must end with .json). The stored file
            will have .enc appended.
        content: A JSON object (dict) with arbitrary fields. The structure
            is up to the caller - the server is schema-free.

    Returns a confirmation message, or an access-denied message if the
    human cancels the password dialog.
    """
    return _put_file(database, bucket, filename, content)


@mcp.tool()
def get_file(database: str, bucket: str, filename: str) -> str:
    """Read and decrypt a file from a bucket.

    If the key is not in memory (or has expired), a dialog will appear on
    the human's screen to enter the bucket password.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.
        filename: Name of the file (must end with .json).

    Returns the decrypted JSON content as a formatted string. If the file
    does not exist, returns an error message. If the human cancels the
    password dialog, returns an access-denied message.
    """
    result = _get_file(database, bucket, filename)
    if isinstance(result, str):
        return result
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)


@mcp.tool()
def delete_file(database: str, bucket: str, filename: str) -> str:
    """Delete a file from a bucket. No password required.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.
        filename: Name of the file (must end with .json).

    Returns a confirmation message. If the file does not exist, returns
    an error message.
    """
    return _delete_file(database, bucket, filename)


@mcp.tool()
def delete_bucket(database: str, bucket: str) -> str:
    """Delete a bucket and all its contents. No password required.

    Removes the bucket folder, all encrypted files inside it, and the
    bucket's password metadata file. Clears the bucket's key from the
    in-memory cache if present. This is irreversible.

    Args:
        database: Name of the database.
        bucket: Name of the bucket to delete.

    Returns a confirmation message. If the bucket does not exist, returns
    an error message.
    """
    return _delete_bucket(database, bucket)


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

    If the key is not in memory (or has expired), a dialog will appear on
    the human's screen to enter the bucket password.

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


@mcp.tool()
def change_bucket_password(database: str, bucket: str) -> str:
    """Change a bucket's password. Re-encrypts all files with the new key.

    The human will be prompted (via a dialog on their screen) to enter the
    current password (verified against the stored bcrypt hash), then to
    enter and confirm a new password. All encrypted files in the bucket
    are decrypted with the old key and re-encrypted with the new key.

    If any file fails to decrypt with the old password, the operation
    aborts and no files are changed.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.

    Returns a confirmation message, or an error/access-denied message.
    """
    return _change_bucket_password(database, bucket)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
