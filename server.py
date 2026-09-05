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
into it. The `edit_file` tool goes further: the AI never even sees the secret
value — it only triggers an editor dialog on the human's screen.

This module is the public facade. Implementation lives in the `safebase/`
package. Mutable, test-monkeypatchable state (the dialog function references
and the key cache) is kept here so the existing test API (`server._prompt_*_fn`,
`server._key_cache`) keeps working unchanged.

Environment variables:
    SAFEBASE_ROOT     - root directory for all databases (required, must be a
                        git repo or will be initialized as one)
"""

import json
from typing import Any

from mcp.server import MCPServer

# Re-export internals so `from server import X` / `server.X` keep working.
from safebase.config import (  # noqa: F401
    _PBKDF2_ITERATIONS,
    _META_FILENAME,
    _META_VERSION,
    _DURATION_OPTIONS,
    _DEFAULT_DURATION,
)
from safebase.validation import _NAME_PATTERN, _validate_name, _validate_filename  # noqa: F401
from safebase.paths import (  # noqa: F401
    _get_root,
    _db_path,
    _bucket_path,
    _file_path,
    _meta_path,
)
from safebase.crypto import _derive_fernet_key, _encrypt, _decrypt  # noqa: F401
from safebase.meta import (  # noqa: F401
    BucketMeta,
    _generate_bucket_meta,
    _write_bucket_meta,
    _store_bucket_meta,
    _load_bucket_meta,
    _verify_password,
    _bucket_has_password,
)
from safebase.keycache import (  # noqa: F401
    _CachedKey,
    _key_cache,
    _cache_key,
    _get_cached_key,
    _store_cached_key,
    _touch_cached_key,
    _clear_cached_key,
)
from safebase.dialogs import (  # noqa: F401
    DialogResult,
    _default_create_password_dialog,
    _default_enter_password_dialog,
    _default_change_password_dialog,
    _default_editor_dialog,
    _tkinter_dialog,
)
from safebase.access import AccessDenied, _MAX_PASSWORD_ATTEMPTS, _get_bucket_key  # noqa: F401
from safebase.git import _git_init, _git_commit  # noqa: F401
from safebase.core import (  # noqa: F401
    _list_databases,
    _create_database,
    _list_buckets,
    _create_bucket,
    _list_files,
    _put_file,
    _get_file,
    _delete_file,
    _delete_bucket,
    _query_bucket,
    _change_bucket_password,
    _edit_file,
)

# ---------------------------------------------------------------------------
# Mutable state (monkeypatchable by tests; read lazily by safebase.access/core)
# ---------------------------------------------------------------------------
# These are module-level globals on the facade. `safebase.access` and
# `safebase.core` read them via `import server` at call time, so reassigning
# them here (as tests do) propagates to the internals.
_prompt_create_password_fn = _default_create_password_dialog
_prompt_enter_password_fn = _default_enter_password_dialog
_prompt_change_password_fn = _default_change_password_dialog
# Editor dialog for edit_file: (database, bucket, filename, content) -> dict | None
_editor_dialog_fn = _default_editor_dialog


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
def edit_file(database: str, bucket: str, filename: str) -> str:
    """Open a GUI editor so the human can edit a stored secret directly.

    The AI never sees the file content. The server unlocks the bucket (showing
    a password dialog on the human's screen if the key is not cached), decrypts
    the file, and opens a tkinter editor pre-filled with the decrypted JSON.
    The human edits the content and clicks Save; the server validates the
    edited text is a JSON object, re-encrypts it, and writes it to disk.

    Use this instead of put_file when a secret needs to be rotated or updated
    without the new value passing through the AI conversation.

    Args:
        database: Name of the database.
        bucket: Name of the bucket.
        filename: Name of the file (must end with .json).

    Returns "File updated successfully" on save, "Edit cancelled by user" on
    cancel, or an error/access-denied message if the bucket or file is missing
    or the human cancels the password dialog.
    """
    return _edit_file(database, bucket, filename)


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
