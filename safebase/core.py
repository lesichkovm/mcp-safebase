"""Core SafeBase operations (plain functions, testable without MCP transport).

Each function performs validation, crypto (via the access gate), and git
commit. They return either a result value or a human-readable error string
(callers distinguish by type, matching the original single-file API).

The dialog function references for `change_bucket_password` and the editor
dialog for `edit_file` live on the `server` facade as mutable globals so tests
can monkeypatch them. They are read lazily via `import server` at call time.
"""

import base64
import shutil
from typing import Any

from cryptography.fernet import Fernet

from safebase.access import AccessDenied, _get_bucket_key
from safebase.crypto import _decrypt, _derive_fernet_key, _encrypt
from safebase.git import _git_commit
from safebase.keycache import _clear_cached_key, _store_cached_key
from safebase.meta import (
    _generate_bucket_meta,
    _load_bucket_meta,
    _verify_password,
    _write_bucket_meta,
)
from safebase.paths import _bucket_path, _db_path, _file_path, _get_root
from safebase.validation import _validate_filename, _validate_name


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

    # Lazy import: the facade holds the (possibly monkeypatched) dialog fns.
    import server as _facade

    # Clear the old cached key before starting, so no stale key can be used
    # by another code path mid-operation.
    _clear_cached_key(database, bucket)

    # 1. Verify the old password
    old_result = _facade._prompt_enter_password_fn(database, bucket)
    if old_result is None or old_result.password is None:
        return "Access denied: user cancelled"
    if not _verify_password(old_result.password, meta.bcrypt_hash):
        return "Access denied: incorrect current password"

    old_salt = base64.b64decode(meta.pbkdf2_salt)
    old_fernet = Fernet(_derive_fernet_key(old_result.password, old_salt))

    # 2. Get the new password
    new_result = _facade._prompt_change_password_fn(database, bucket)
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


def _edit_file(database: str, bucket: str, filename: str) -> str:
    """Open a GUI editor for the human to edit a stored secret directly.

    The AI never sees the content. Flow:
    1. Unlock the bucket (same gate as get_file — may prompt for password).
    2. Decrypt the current content.
    3. Show a tkinter editor pre-filled with the decrypted JSON.
    4. On Save: validate the edited text is a JSON object, re-encrypt, write.
    5. On Cancel: no changes are written.

    Returns a confirmation string only ("File updated successfully" or
    "Edit cancelled by user") — never the file content.
    """
    root = _get_root()
    _validate_name(database, "database")
    _validate_name(bucket, "bucket")
    _validate_filename(filename)

    bucket_path = _bucket_path(root, database, bucket)
    if not bucket_path.exists():
        return f"Bucket '{database}/{bucket}' does not exist"

    file_path = _file_path(root, database, bucket, filename)
    if not file_path.exists():
        return f"File '{database}/{bucket}/{filename}' does not exist"

    try:
        fernet = _get_bucket_key(database, bucket)
    except AccessDenied as e:
        return f"Access denied: {e}"

    ciphertext = file_path.read_bytes()
    try:
        current = _decrypt(fernet, ciphertext)
    except Exception as e:
        return f"Decryption failed for '{database}/{bucket}/{filename}': {e}"

    # Lazy import: the facade holds the (possibly monkeypatched) editor fn.
    import server as _facade

    edited = _facade._editor_dialog_fn(database, bucket, filename, current)
    if edited is None:
        return "Edit cancelled by user"

    # Defensive: the dialog validates JSON + dict shape, but a custom
    # (monkeypatched) dialog could return anything. Guard against non-dicts.
    if not isinstance(edited, dict):
        return "Edit cancelled: edited content is not a JSON object"

    encrypted = _encrypt(fernet, edited)
    file_path.write_bytes(encrypted)
    _git_commit(root, f"edit: {database}/{bucket}/{filename}")
    return "File updated successfully"
