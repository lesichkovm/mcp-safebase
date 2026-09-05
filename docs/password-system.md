# Password System

SafeBase uses per-bucket passwords. Each bucket has its own password, set by the human via a native OS dialog. There is no master password.

## First Use of a Bucket

When the AI calls `put_file` (or any crypto-needing tool) on a bucket that has no password set yet:

1. A dialog appears on your screen: "Create a password for bucket `mydb/contacts`"
2. You type and confirm a password, pick a duration (5 / 10 / 15 min / process lifetime), click Create
3. The server generates a random 32-byte PBKDF2 salt, bcrypt-hashes the password, and writes `.safebase-meta.json` inside the bucket
4. The server derives the Fernet key from the raw password + salt, holds it in memory for the chosen duration
5. The tool call completes

## Subsequent Use (Key Not in Memory or Expired)

1. A dialog appears: "Enter password for bucket `mydb/contacts`"
2. You type the password, pick a duration, click Unlock
3. The server verifies the password against the stored bcrypt hash
4. If correct, it derives the Fernet key and caches it for the chosen duration
5. The tool call completes

### Wrong Password

You can retry up to **3 attempts**. If you cancel or exceed the retry limit, the tool returns `"access denied"` to the AI.

### Human Cancels

The tool returns `"access denied by user"` to the AI. The AI must inform you and stop.

## Key Already in Memory (Not Expired)

No dialog appears. The server finds the key in the in-memory cache, resets the idle timer, and the tool call completes immediately.

## Session Duration

The dialog includes a duration selector:

| Option | Meaning |
|--------|---------|
| 5 minutes | Key expires after 5 minutes of inactivity (preselected) |
| 10 minutes | Key expires after 10 minutes of inactivity |
| 15 minutes | Key expires after 15 minutes of inactivity |
| Process lifetime | Key stays in memory until the MCP server process restarts |

The idle timer **resets on each tool call** — the timeout counts from the last activity, not from unlock. After expiry, the next call shows the dialog again.

## Changing a Bucket's Password

Call the `change_bucket_password` tool. Two dialogs will appear:

1. **Current password** — verified against the stored bcrypt hash
2. **New password** — with confirmation field and duration selector

The server then:

1. Decrypts all `.enc` files in the bucket with the old key (in memory)
2. Generates a new random salt and derives the new key (in memory only)
3. Re-encrypts all files with the new key (writes to disk)
4. **Only after all files are successfully re-encrypted**, writes the new `.safebase-meta.json`
5. Updates the in-memory key cache

### Data Safety

The metadata is written **after** all files are re-encrypted, not before. If any file fails to re-encrypt, the operation aborts and the old metadata remains on disk — the old password still works and the remaining files are still decryptable. No data loss.

If any file fails to decrypt with the old password, the operation aborts before any files are changed.

### Same Password Rejected

The new password must be different from the current one.

## What's Stored on Disk

Each bucket has a `.safebase-meta.json` file:

```json
{
  "version": 1,
  "bcrypt_hash": "$2b$12$...",
  "pbkdf2_salt": "base64-encoded-32-random-bytes",
  "created_at": "2026-08-19T12:00:00Z"
}
```

- **bcrypt_hash** — one-way hash, used to verify the human entered the correct password
- **pbkdf2_salt** — per-bucket salt for deriving the Fernet key from the raw password
- **created_at** — when the password was set

The raw password is **never** stored. This file is not encrypted (it contains no secret material) and is committed to git. It is excluded from `list_files` and `query_bucket` results.

## Key Cache

The server holds derived Fernet keys in an in-memory dict, not persisted:

- Keyed by `f"{database}/{bucket}"`
- Idle timeout resets on each tool call
- On expiry: key removed, next call triggers dialog
- On `delete_bucket`: key removed
- On `change_bucket_password`: old key cleared before the operation starts, new key stored after
