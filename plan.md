# SafeBase Revision Plan — Human-Gated Per-Bucket Passwords

## Problem

The current design stores the encryption password in `SAFEBASE_PASSWORD` env var,
set in a plaintext MCP client config file on disk. Any process with filesystem
read access on the host — including the AI agent — can silently read that file,
extract the password, read `server.py` to learn the PBKDF2 salt and iteration
count (hardcoded constants), derive the Fernet key, and decrypt every `.enc`
file directly. The "MCP access only" principle is unenforceable against the AI
agent. The encryption is theater against the very threat model it claims to
address.

## Goal

The AI agent must never be able to obtain the encryption password. The human
must be prompted directly by the server process (via a native OS dialog) every
time access is needed and the key is not already in memory. The password is
never stored in plaintext, never passed through the AI, never in env vars or
config files.

## Design

### Per-bucket passwords

Each bucket has its own password. There is no master password. A database is
just a folder; it has no password. Only buckets are encrypted, and each bucket
is independently secured.

### Password lifecycle

**First use of a bucket** (no password set yet):
1. AI calls `put_file` or any crypto-needing tool on a bucket with no password
2. Server detects no `.safebase-meta.json` in the bucket
3. Server shows a **create-password dialog** on the human's screen:
   - "Create a password for bucket `coursethread/sme-candidates`"
   - Password field + confirm field
   - Duration selector (5 / 10 / 15 min / process lifetime)
   - Create / Cancel buttons
4. Human types and confirms the password, picks duration, clicks Create
5. Server generates a random per-bucket PBKDF2 salt (32 bytes)
6. Server bcrypt-hashes the password → stores in `.safebase-meta.json`
7. Server derives Fernet key from raw password + per-bucket salt via PBKDF2
8. Key held in memory for the chosen duration
9. Tool call completes

**Subsequent uses** (password already set, key not in memory or expired):
1. AI calls a crypto-needing tool on a bucket
2. Server checks in-memory key cache for this bucket — not present or expired
3. Server shows an **enter-password dialog** on the human's screen:
   - "Enter password for bucket `coursethread/sme-candidates`"
   - Password field
   - Duration selector (5 / 10 / 15 min / process lifetime)
   - Unlock / Cancel buttons
4. Human types the password, picks duration, clicks Unlock
5. Server verifies against stored bcrypt hash — if wrong, dialog shows error,
   human can retry or cancel
6. If verified, server derives Fernet key from raw password + stored salt
7. Key held in memory for the chosen duration
8. Tool call completes

**Key already in memory and not expired:**
1. AI calls a crypto-needing tool
2. Server finds key in cache, still valid
3. Tool call completes immediately — no dialog

**Human cancels the dialog:**
1. Tool returns `"access denied by user"` to the AI
2. AI must inform the human and stop

### Metadata file

Each bucket gets a `.safebase-meta.json` file inside the bucket folder:

```json
{
  "version": 1,
  "bcrypt_hash": "$2b$12$...",
  "pbkdf2_salt": "base64-encoded-32-random-bytes",
  "created_at": "2026-08-19T12:00:00Z"
}
```

- **Not encrypted** — contains only a one-way hash and a salt. Cannot be
  reversed to obtain the password.
- **Committed to git** — fine, bcrypt is designed for this. Reveals that a
  bucket is protected (already obvious from the folder existing).
- **Hidden from listings** — `list_files` and `query_bucket` skip files
  starting with `.` (already the case for folders; extend to files).

### Key cache

In-memory dict, not persisted:

```python
_key_cache: dict[str, _CachedKey] = {}
# key: f"{database}/{bucket}"
# value: _CachedKey(fernet=Fernet, expires_at=float)
```

- Idle timeout: timer resets on each tool call using that bucket's key
- On expiry: key removed from cache, next call triggers dialog
- "Process lifetime" option: `expires_at = infinity` (stays until server restarts)

### Which tools need the key

| Tool | Needs key? | Why |
|------|-----------|-----|
| `list_databases` | No | Lists folders |
| `create_database` | No | Creates a folder |
| `list_buckets` | No | Lists subfolders |
| `create_bucket` | No | Creates a folder (password set on first `put_file`) |
| `list_files` | No | Lists filenames only |
| `put_file` | **Yes** | Encrypts content |
| `get_file` | **Yes** | Decrypts content |
| `delete_file` | No | Deletes a file (no crypto) |
| `delete_bucket` | No | Deletes a folder (no crypto) |
| `change_bucket_password` | **Yes** | Decrypts + re-encrypts all files |
| `query_bucket` | **Yes** | Decrypts all files in bucket |

### Dialog implementation

- `tkinter` (bundled with Python on Windows and macOS, may need `python3-tk`
  on Linux)
- Dialog runs on the main thread or a dedicated UI thread; the tool call
  blocks (waiting on the MCP stdio response) until the human responds
- Dialog is a real OS window on the human's desktop — the AI has no visibility
  into it, no access to keystrokes, no way to intercept

### What is removed

- `SAFEBASE_PASSWORD` env var — gone entirely
- `_PBKDF2_SALT` global constant — replaced by per-bucket salts
- `_get_fernet()` reading from env — replaced by key cache + dialog flow

### What is added

- `bcrypt` to `requirements.txt` (for password verification)
- `.safebase-meta.json` per bucket (metadata file)
- `_key_cache` in-memory dict with idle-timeout expiry
- `_prompt_create_password(database, bucket)` — tkinter dialog for first use
- `_prompt_enter_password(database, bucket)` — tkinter dialog for subsequent use
- `_get_bucket_key(database, bucket)` — checks cache, prompts if needed,
  returns Fernet or raises access-denied
- `_store_bucket_meta(bucket_path, password)` — generates salt, bcrypt hash,
  writes metadata file
- `_load_bucket_meta(bucket_path)` — reads metadata file
- `_verify_password(password, bcrypt_hash)` — bcrypt verify

### Headless / CI / SSH

Not supported. This is by design — the whole point is human-in-the-loop. If
headless access is ever needed, it would require a separate CLI tool that the
human runs manually (not accessible to the AI), which is out of scope for this
revision.

### Password change

Handled by the `change_bucket_password` tool (see Additional tools section
below).

### Backward compatibility

None. Clean start — no existing `.enc` files to migrate. No backward-
compatibility code needed.

## Implementation steps

1. Add `bcrypt` to `requirements.txt`
2. Add metadata helpers (`_store_bucket_meta`, `_load_bucket_meta`,
   `_verify_password`)
3. Add key cache (`_key_cache`, `_CachedKey` dataclass)
4. Add tkinter dialog functions (`_prompt_create_password`,
   `_prompt_enter_password`, `_prompt_change_password`)
5. Add `_get_bucket_key(database, bucket)` — the central gate function
6. Refactor `_put_file`, `_get_file`, `_query_bucket` to use `_get_bucket_key`
   instead of `_get_fernet()`
7. Add `_delete_bucket` core logic + `delete_bucket` MCP tool
8. Add `_change_bucket_password` core logic + `change_bucket_password` MCP tool
9. Remove `SAFEBASE_PASSWORD` env var, `_PBKDF2_SALT` constant, `_get_fernet()`
10. Update `list_files` and `query_bucket` to skip `.safebase-meta.json`
11. Update tests — remove env-var-based tests, add dialog-mock-based tests
12. Update README — document the new flow, remove env var instructions
13. Test manually with a real MCP client

## Decisions (confirmed by GOD)

1. **Default duration** — 5 minutes preselected in the dialog radio buttons.
2. **Password change** — `change_bucket_password` tool included in this
   revision. Flow: human enters old password (verified against bcrypt), human
   enters new password, all `.enc` files in the bucket re-encrypted with new
   key, metadata file updated with new bcrypt hash and salt.
3. **Migration** — clean start. No existing `.enc` files to migrate. No
   backward-compatibility code needed.
4. **Delete bucket** — a new `delete_bucket` tool removes the whole bucket
   folder including `.safebase-meta.json`. No key needed (deleting is not a
   crypto operation). The folder and all contents are gone. Also clears the
   key from the in-memory cache if present.

## Additional tools in this revision

### `delete_bucket(database, bucket)`

Deletes a bucket folder and all its contents (`.enc` files +
`.safebase-meta.json`). No key needed — deletion is not a crypto operation.
Clears the bucket's key from the in-memory cache if present. Auto-commits to
git.

### `change_bucket_password(database, bucket)`

Changes a bucket's password. Flow:
1. Server shows a dialog: "Enter current password for bucket X" → human types
   it → verified against bcrypt hash. If wrong, dialog shows error, human can
   retry or cancel.
2. Server shows a dialog: "Enter new password for bucket X" + confirm field +
   duration selector → human types and confirms.
3. Server generates a new random PBKDF2 salt.
4. Server derives the **old** Fernet key (from old password + old salt),
   decrypts every `.enc` file in the bucket.
5. Server derives the **new** Fernet key (from new password + new salt),
   re-encrypts every `.enc` file.
6. Server writes new `.safebase-meta.json` with new bcrypt hash + new salt.
7. Server updates the in-memory key cache with the new key.
8. Auto-commits to git.

If any step fails, the operation aborts and no files are modified (decrypt all
first, then re-encrypt all, then write all — atomic-ish).
