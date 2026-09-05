# Specification

## Overview

SafeBase is an encrypted file-based storage system accessed via MCP (Model Context Protocol). It organizes sensitive data as databases, buckets, and files — each file is an encrypted JSON object on disk. AI agents read and write data through MCP tool calls; the human gates access by entering per-bucket passwords into native OS dialogs that the server pops up on their desktop. The AI never sees the password.

## Goals

- Encrypted at rest — every file is Fernet ciphertext (AES-128-CBC + HMAC-SHA256) on disk
- Human-gated — the AI cannot obtain the encryption password; the human enters it directly into a server-side dialog
- Per-bucket passwords — each bucket is independently secured; no master password
- No plaintext passwords on disk — only bcrypt hashes and per-bucket PBKDF2 salts are persisted
- Schema-free — the server does not know what's in a bucket; each file is an arbitrary JSON object
- Local only — runs as a stdio MCP subprocess on the local machine, no network exposure
- Git history — the storage root is a git repo, auto-committed by the server for full ciphertext history and reversion

## Non-Goals

- Not a hosted/cloud service
- Not a multi-user system
- No password recovery (the bcrypt hash is one-way by design)
- No headless / CI / SSH-only support (the dialog requires a display and a human at the screen)
- No network server, no Docker, no cloud dependencies
- No password env var (there is no `SAFEBASE_PASSWORD`; the password is entered via dialog only)

## Threat Model

### What SafeBase protects against

- **The AI agent reading the password from a config file or env var** — there is none. The password is never stored in plaintext anywhere on disk.
- **The AI agent intercepting the password** — the dialog is a native OS window shown by the server process directly on the human's desktop. The AI has no visibility into the dialog, no access to keystrokes, and no way to intercept the password.
- **The secret value leaking into the AI conversation when rotated** — `edit_file` opens a GUI editor on the human's screen pre-filled with the decrypted JSON. The human edits and saves; the AI only receives `"File updated successfully"` or `"Edit cancelled by user"`. The new value never passes through the conversation.
- **An attacker with read access to the storage root** — files are encrypted; the metadata file contains only a one-way bcrypt hash and a per-bucket PBKDF2 salt.
- **Plaintext leaking into git history** — all files are `.enc` ciphertext; git diffs contain no plaintext.

### What SafeBase does not protect against

- **An attacker with read access to the server process memory while the key is cached** — the raw Fernet key is in memory for the human-chosen session duration.
- **The human forgetting the password** — there is no recovery. The bcrypt hash is one-way. Files become permanently undecryptable.
- **Headless / CI / SSH-only environments** — the dialog requires a display. SafeBase cannot run without a human at the screen.
- **The AI deleting data without human consent** — `delete_file` and `delete_bucket` do not require the bucket password (they are not crypto operations). This is a deliberate design decision: deletion is recoverable via git. If you need to prevent the AI from deleting, restrict these tools at the MCP client level or remove them from the server.

## Architecture

```
MCP Client (AI agent)
    |
    | MCP tool calls (list_databases, put_file, get_file, query_bucket, ...)
    v
SafeBase MCP Server (Python, this repo)
    |
    | needs encryption key for a bucket
    v
Native OS password dialog (tkinter, on the human's desktop)
    |
    | human types the password
    v
SafeBase MCP Server
    |
    | derives Fernet key in memory, decrypts/encrypts, returns result
    v
Encrypted file store (OUTSIDE the repo, path set via SAFEBASE_ROOT env var)
    |
    | on disk structure:
    v
{SAFEBASE_ROOT}/
  mydb/
    contacts/
      .safebase-meta.json     <- bcrypt hash + PBKDF2 salt (no plaintext)
      person-001.json.enc     <- encrypted with this bucket's key
      person-002.json.enc
    leads/
      .safebase-meta.json
      lead-001.json.enc
  personal/
    notes/
      .safebase-meta.json
      note-001.json.enc
```

## Storage Model

### Databases

- A database is a top-level folder under `SAFEBASE_ROOT`
- Hidden folders (starting with `.`) are excluded
- Databases have no password — only buckets are encrypted
- Created/deleted via MCP tools

### Buckets

- A bucket is a subfolder inside a database
- Each bucket has its own password, set by the human on first use via a native OS dialog
- Hidden folders (starting with `.`) are excluded
- A bucket's password metadata lives in `.safebase-meta.json` inside the bucket folder
- Deleting a bucket removes the folder, all `.enc` files, and the metadata file

### Files

- A file is one encrypted JSON object inside a bucket
- Stored on disk as `{filename}.enc` (the caller passes `filename.json`; `.enc` is appended)
- Schema-free — the server does not know or care what fields are in each file
- The caller decides the structure per bucket

## Encryption

### Algorithm

- **Fernet** (symmetric authenticated encryption)
- Underlying: AES-128-CBC + HMAC-SHA256
- Key derivation: PBKDF2-SHA256, 600,000 iterations (OWASP-recommended minimum)
- Per-bucket salt: 32 random bytes, generated by `secrets.token_bytes(32)`
- The Fernet key is derived from the raw password + per-bucket salt, in memory only

### Password Storage

The raw password is **never** stored on disk. Only a one-way hash and a salt are persisted:

```json
{
  "version": 1,
  "bcrypt_hash": "$2b$12$...",
  "pbkdf2_salt": "base64-encoded-32-random-bytes",
  "created_at": "2026-08-19T12:00:00Z"
}
```

- **bcrypt_hash** — one-way hash of the password, used to verify the human entered the correct password
- **pbkdf2_salt** — per-bucket salt for deriving the Fernet key from the raw password
- **created_at** — ISO timestamp of when the password was set

This file is not encrypted (it contains no secret material) and is committed to git. It is excluded from `list_files` and `query_bucket` results.

## Password Lifecycle

### First Use of a Bucket

When the AI calls `put_file` or any crypto-needing tool on a bucket with no password set:

1. The server detects no `.safebase-meta.json` in the bucket
2. The server shows a **create-password dialog** on the human's desktop:
   - "Create a password for bucket `mydb/contacts`"
   - Password field + confirm field
   - Duration selector (5 / 10 / 15 min / process lifetime, 5 min preselected)
   - Create / Cancel buttons
3. The human types and confirms the password, picks a duration, clicks Create
4. The server generates a random 32-byte PBKDF2 salt, bcrypt-hashes the password, and writes `.safebase-meta.json`
5. The server derives the Fernet key from the raw password + salt, holds it in memory for the chosen duration
6. The tool call completes

### Subsequent Use (Key Not in Memory or Expired)

1. The server shows an **enter-password dialog** on the human's desktop:
   - "Enter password for bucket `mydb/contacts`"
   - Password field
   - Duration selector (5 / 10 / 15 min / process lifetime, 5 min preselected)
   - Unlock / Cancel buttons
2. The human types the password, picks a duration, clicks Unlock
3. The server verifies the password against the stored bcrypt hash
4. If correct, it derives the Fernet key and caches it for the chosen duration
5. The tool call completes

If the human enters the wrong password, they can retry up to **3 attempts**. If they cancel or exceed the retry limit, the tool returns `"access denied"` to the AI.

### Key Already in Memory (Not Expired)

1. The server finds the key in the in-memory cache, still valid
2. The idle timer is reset (the timeout counts from the last tool call, not from unlock)
3. The tool call completes immediately — no dialog

### Human Cancels the Dialog

1. The tool returns `"access denied by user"` to the AI
2. The AI must inform the human and stop

### Session Duration

The dialog includes a duration selector:

| Option | Meaning |
|--------|---------|
| 5 minutes | Key expires after 5 minutes of inactivity (preselected) |
| 10 minutes | Key expires after 10 minutes of inactivity |
| 15 minutes | Key expires after 15 minutes of inactivity |
| Process lifetime | Key stays in memory until the MCP server process restarts |

The idle timer resets on each tool call using that bucket's key. After expiry, the next call shows the dialog again.

## Key Cache

The server holds derived Fernet keys in an in-memory dict, not persisted:

```python
_key_cache: dict[str, _CachedKey] = {}
# key: f"{database}/{bucket}"
# value: _CachedKey(fernet, expires_at, duration_minutes)
```

- **Idle timeout**: timer resets on each tool call using that bucket's key
- **On expiry**: key removed from cache, next call triggers dialog
- **Process lifetime**: `expires_at = infinity` (stays until server restarts)
- **On `delete_bucket`**: key removed from cache
- **On `change_bucket_password`**: old key cleared before the operation starts, new key stored after

## Changing a Bucket's Password

The `change_bucket_password` tool changes a bucket's password and re-encrypts all files. The order of operations is critical for data safety:

1. Clear the old cached key from the in-memory cache
2. Show a dialog asking for the current password (verified against the bcrypt hash)
3. Show a dialog asking for the new password (with confirmation)
4. Decrypt all `.enc` files in the bucket with the old key (in memory)
5. Generate the new key in memory (do **not** write metadata yet)
6. Re-encrypt all files with the new key (write to disk)
7. **Only after all files are successfully re-encrypted**, write the new `.safebase-meta.json`
8. Update the in-memory key cache with the new key
9. Auto-commit to git

If any step fails before step 7, the old metadata is still on disk and the remaining files are still decryptable with the old password — no data loss.

## Process Model

The server runs as a single-process stdio MCP subprocess. There is no web UI, no HTTP server, no background thread. The only interaction surface is:

- **MCP stdio** — for AI agent tool calls
- **tkinter dialog** — for human password entry (popped up on the human's desktop by the server process)

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SAFEBASE_ROOT` | Yes | — | Root directory for all databases. Must exist. Will be initialized as a git repo if not already one. |

There is no `SAFEBASE_PASSWORD` environment variable. The password is entered per-bucket by the human via a dialog.

## MCP Tools

| Tool | Args | Needs password? | Description |
|------|------|:---:|-------------|
| `list_databases` | — | No | List all databases (top-level folders) in the root |
| `create_database` | `database` | No | Create a new database (folder) |
| `list_buckets` | `database` | No | List buckets (subfolders) in a database |
| `create_bucket` | `database`, `bucket` | No | Create a new bucket (subfolder). Password is set on first `put_file`. |
| `list_files` | `database`, `bucket` | No | List files in a bucket (filenames only, no decryption) |
| `put_file` | `database`, `bucket`, `filename`, `content` | Yes | Write an encrypted JSON file to a bucket (overwrites if exists) |
| `get_file` | `database`, `bucket`, `filename` | Yes | Read and decrypt a file from a bucket |
| `edit_file` | `database`, `bucket`, `filename` | Yes | Open a GUI editor on the human's screen showing the decrypted JSON. The human edits and saves; the file is re-encrypted. The AI never sees the content — only `"File updated successfully"` or `"Edit cancelled by user"`. |
| `delete_file` | `database`, `bucket`, `filename` | No | Delete a file from a bucket |
| `delete_bucket` | `database`, `bucket` | No | Delete a bucket and all its contents (folder + metadata + key cache) |
| `query_bucket` | `database`, `bucket`, `filter_fields?` | Yes | List all files in a bucket with optional field-equality filtering |
| `change_bucket_password` | `database`, `bucket` | Yes | Change a bucket's password (re-encrypts all files) |

### Filename Rules

- The caller passes `filename.json` (must end with `.json`)
- The server stores it as `filename.json.enc` on disk
- The part before `.json` must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`

## Dialog Implementation

- **tkinter** (bundled with Python on Windows and macOS; on Linux may need `python3-tk`)
- The dialog is a real OS window on the human's desktop — the AI has no visibility into it
- The dialog blocks the tool call until the human responds
- If tkinter is not available, the server raises a `RuntimeError` explaining that a display is required

### Dialog Functions (Injectable)

The dialog functions are module-level references, injectable for testing:

```python
_prompt_create_password_fn: Callable[[str, str], Optional[DialogResult]]
_prompt_enter_password_fn:   Callable[[str, str], Optional[DialogResult]]
_prompt_change_password_fn:  Callable[[str, str], Optional[DialogResult]]
_editor_dialog_fn:           Callable[[str, str, str, dict], Optional[dict]]
```

`_editor_dialog_fn` (used by `edit_file`) receives the database, bucket,
filename, and the current decrypted content as a dict. It returns the edited
dict on Save, or `None` on Cancel. The default implementation opens a tkinter
`Toplevel` with a `scrolledtext.ScrolledText` widget pre-filled with the
pretty-printed JSON and validates the edited text is a JSON object on Save.

Tests monkeypatch these to inject canned passwords/edits without a GUI.

### DialogResult

```python
@dataclass
class DialogResult:
    password: Optional[str]     # None if the human cancelled
    duration_minutes: int       # one of (5, 10, 15, 0)
```

## Git History

The storage root is a git repo. Every mutation auto-commits:

| Operation | Commit message |
|-----------|---------------|
| `create_database` | `create database: {database}` |
| `create_bucket` | `create bucket: {database}/{bucket}` |
| `put_file` | `put: {database}/{bucket}/{filename}` |
| `edit_file` | `edit: {database}/{bucket}/{filename}` |
| `delete_file` | `delete: {database}/{bucket}/{filename}` |
| `delete_bucket` | `delete bucket: {database}/{bucket}` |
| `change_bucket_password` | `change password: {database}/{bucket}` |

The git repo is auto-initialized with identity `SafeBase MCP <safebase@local>` if it doesn't already exist. Since all files are `.enc` ciphertext, the git history contains no plaintext. Empty databases and buckets are tracked via `.gitkeep` files.

## Validation

- Database names: `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`
- Bucket names: `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`
- Filename bases (before `.json`): `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`
- No path traversal, no dots, no spaces

## Error Handling

- Corrupted `.safebase-meta.json` (invalid JSON, missing keys) → treated as no password set → triggers create-password dialog on next use
- Corrupted `.enc` file (invalid ciphertext, wrong key) → `get_file` returns `"Decryption failed for ..."`; `query_bucket` returns an error entry in the results array
- Wrong password (max 3 attempts) → `AccessDenied("Incorrect password (max attempts exceeded)")`
- Human cancels dialog → `AccessDenied("User cancelled password ...")`
- Bucket or database doesn't exist → returns a `"does not exist"` string
- Invalid names → raises `ValueError`

## Technology

- **Language**: Python 3.11+
- **MCP SDK**: `mcp>=2.0.0`
- **Encryption**: `cryptography>=42.0.0` (Fernet)
- **Password hashing**: `bcrypt>=4.0.0`
- **Dialog**: tkinter (stdlib)
- **No external network dependencies**

## Code Layout

The server is split into a thin facade plus an internal package:

```
server.py              # Facade: re-exports internals, holds mutable dialog
                       # refs + key cache, registers MCP tools, entry point.
safebase/
  config.py            # Tunable constants (PBKDF2 iterations, durations)
  validation.py        # Name/filename regex validation (pure functions)
  paths.py             # SAFEBASE_ROOT resolution + path helpers
  crypto.py            # Fernet encrypt/decrypt + key derivation
  meta.py              # BucketMeta: bcrypt hash + salt persistence
  keycache.py          # In-memory Fernet cache with idle timeout
  dialogs.py           # tkinter password + editor dialogs, DialogResult
  access.py            # Central gate: _get_bucket_key (prompts human)
  git.py               # Auto-init + auto-commit helpers
  core.py              # Core ops: list/create/put/get/edit/delete/query/change
```

The facade (`server.py`) keeps the public API stable: tests import `server`
and monkeypatch `server._prompt_*_fn`, `server._editor_dialog_fn`, and
`server._key_cache` exactly as before. The internal modules read those
references lazily via `import server` at call time, so monkeypatching the
facade propagates to the internals.

## Testing

```bash
# Full pytest suite (92 tests)
pytest test_server.py -v

# Quick smoke test (headless, dialogs mocked)
python test_smoke.py
```

Tests mock the dialog functions to inject canned passwords, so they run headless without tkinter or a display.

### Test Coverage

| Area | Tests |
|------|-------|
| Databases (create, list, validate) | 12 |
| Buckets (create, list, delete, validate) | 10 |
| Files (put, get, delete, list, validate) | 14 |
| edit_file (save, cancel, invalid JSON, missing file/bucket, access denied, MCP) | 9 |
| Query (filter, nested data, metadata exclusion) | 8 |
| Encryption (ciphertext on disk, wrong password, unicode, large files) | 8 |
| Per-bucket passwords (create, verify, change, cancel, wrong) | 13 |
| Key cache (caching, timeout, clearing, clamping) | 5 |
| Edge cases (corruption, partial failure, retry loop) | 8 |
| Git history (commits, no plaintext, reversion) | 11 |
| MCP transport (in-memory client, end-to-end) | 6 |

## License

AGPL-3.0 — see [LICENSE](../LICENSE). Commercial use requires a separate commercial license.
