# SafeBase

Encrypted file-based storage accessed via MCP (Model Context Protocol), with human-gated per-bucket passwords.

## What it is

SafeBase is a Python MCP server that provides encrypted file-based storage organized as databases, buckets, and files. Think of it as a lightweight encrypted file system accessed through MCP tool calls.

- **Database** = a folder (like a database server has multiple databases)
- **Bucket** = a subfolder inside a database (like a database has tables)
- **File** = one encrypted JSON file inside a bucket (like a table has rows)

All files are encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256). Each bucket has its own password, set by the human via a native OS dialog on first use. The password is never stored in plaintext — only a bcrypt hash and a per-bucket PBKDF2 salt live in a metadata file inside the bucket.

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
Encrypted file store (OUTSIDE the repo, path set via env var)
    |
    | on disk structure:
    v
{SAFEBASE_ROOT}/
  coursethread/
    sme-candidates/
      .safebase-meta.json     ← bcrypt hash + PBKDF2 salt (no plaintext)
      cand-001.json.enc       ← encrypted with this bucket's key
      cand-002.json.enc
    tender-leads/
      .safebase-meta.json
      t-001.json.enc
  personal/
    notes/
      .safebase-meta.json
      note-001.json.enc
```

## Key principles

1. **Files live outside the repo** - the storage root is set via `SAFEBASE_ROOT` env var. No encrypted files are committed to any repo (the storage root is its own git repo, auto-committed by the server for history and reversion — see below).
2. **Encryption at rest** - every file is encrypted with Fernet (AES-128-CBC + HMAC-SHA256). Files on disk are ciphertext.
3. **Per-bucket passwords** - each bucket has its own password. There is no master password. A database (folder) has no password; only buckets are encrypted.
4. **Human-gated access** - the AI agent never sees the password. When a tool needs the encryption key and it's not already in memory, the server shows a native OS dialog on the human's desktop (via tkinter). The human types the password directly into the dialog. The AI has no visibility into the dialog, no access to the keystrokes, and no way to intercept the password.
5. **No plaintext passwords on disk** - the password is never stored in plaintext. Only a bcrypt hash (one-way) and a per-bucket PBKDF2 salt live in `.safebase-meta.json` inside each bucket. The raw password exists only in server memory for the duration the human chooses.
6. **Schema-free** - the server does not know what's in a bucket. Each file is a JSON object with arbitrary fields. The caller decides the structure per bucket.
7. **Local only** - no network server, no Docker, no cloud. Runs as a stdio MCP subprocess on the local machine.
8. **Git history** - the storage root is a git repo. Every `put_file`, `delete_file`, `create_database`, `create_bucket`, `delete_bucket`, and `change_bucket_password` operation auto-commits, providing full history and reversion. Since all files are encrypted (`.enc`), the git history contains only ciphertext.

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

Requires `tkinter` (bundled with Python on Windows and macOS; on Linux may need `python3-tk`).

### 2. Create the storage directory

Create a directory where encrypted databases will live. This should be outside any git repo.

```bash
mkdir C:\Users\YourName\safebase-data
```

### 3. Configure the MCP server

Add to your MCP client config (e.g., `mcp_config.json` for Windsurf):

```json
{
  "mcpServers": {
    "safebase": {
      "command": "python",
      "args": ["D:\\PROJECTs\\_modules_dracory\\mcp-safebase\\server.py"],
      "env": {
        "SAFEBASE_ROOT": "C:\\Users\\YourName\\safebase-data"
      }
    }
  }
}
```

- `SAFEBASE_ROOT` - the root directory where databases are stored. Create this directory before use.

**No password env var.** The password is set per-bucket by the human via a dialog on first use. There is no `SAFEBASE_PASSWORD` environment variable.

### 4. Start using

The MCP client starts the server automatically when an AI agent calls a tool. No manual startup needed.

The first time the AI calls `put_file` on a new bucket, a dialog will appear on your screen asking you to create a password for that bucket. On subsequent calls (if the key has expired from memory), a dialog will appear asking you to enter the password.

## Tools

| Tool | Description | Needs password? |
|------|-------------|:---:|
| `list_databases` | List all databases (folders) in the root | No |
| `create_database` | Create a new database (folder) | No |
| `list_buckets` | List buckets (subfolders) in a database | No |
| `create_bucket` | Create a new bucket (subfolder) in a database | No |
| `list_files` | List files in a bucket | No |
| `put_file` | Write an encrypted JSON file to a bucket | Yes |
| `get_file` | Read and decrypt a file from a bucket | Yes |
| `delete_file` | Delete a file from a bucket | No |
| `delete_bucket` | Delete a bucket and all its contents | No |
| `query_bucket` | List all files in a bucket with optional field filtering | Yes |
| `change_bucket_password` | Change a bucket's password (re-encrypts all files) | Yes |

## Password lifecycle

### First use of a bucket

When the AI calls `put_file` on a bucket that has no password set yet:

1. A dialog appears on your screen: "Create a password for bucket `coursethread/sme-candidates`"
2. You type and confirm a password, pick a duration (5 / 10 / 15 min / process lifetime), click Create
3. The server generates a random per-bucket PBKDF2 salt, bcrypt-hashes the password, and writes `.safebase-meta.json` inside the bucket
4. The server derives the Fernet key from the raw password + salt, holds it in memory for the chosen duration
5. The tool call completes

### Subsequent uses (key not in memory or expired)

1. A dialog appears: "Enter password for bucket `coursethread/sme-candidates`"
2. You type the password, pick a duration, click Unlock
3. The server verifies the password against the stored bcrypt hash
4. If correct, it derives the Fernet key and caches it for the chosen duration
5. The tool call completes

If you enter the wrong password, you can retry up to 3 times. If you cancel or exceed the retry limit, the tool returns "access denied" to the AI.

### Session duration

The dialog includes a duration selector (5 / 10 / 15 minutes, or process lifetime), with 5 minutes pre-selected. The key stays in memory for that long, resetting the idle timer on each tool call. After the timeout, the next call shows the dialog again.

### Changing a bucket's password

Call the `change_bucket_password` tool. The server will:

1. Show a dialog asking for the current password (verified against the bcrypt hash)
2. Show a dialog asking for the new password (with confirmation)
3. Decrypt all `.enc` files in the bucket with the old key (in memory)
4. Re-encrypt all files with the new key (write to disk)
5. **Only after all files are successfully re-encrypted**, update `.safebase-meta.json` with the new bcrypt hash and salt
6. Update the in-memory key cache

The metadata is written **after** all files are re-encrypted, not before. If any file fails to re-encrypt, the operation aborts and the old metadata remains on disk — no data loss.

If any file fails to decrypt with the old password, the operation aborts and no files are changed.

## Usage examples

### SME candidate roster

```
# Create structure
create_database("coursethread")
create_bucket("coursethread", "sme-candidates")

# Add a candidate — a dialog appears to create the bucket password
put_file("coursethread", "sme-candidates", "cand-001", {
    "name": "Jane Smith",
    "email": "jane@example.com",
    "domain": "Cybersecurity",
    "per_course_price_usd": 50,
    "vetting_status": "applied",
    "linkedin_url": "https://linkedin.com/in/janesmith",
    "fact_check_approach": "I verify claims against peer-reviewed sources..."
})

# List all candidates (no dialog if key still in memory)
list_files("coursethread", "sme-candidates")

# Get one candidate
get_file("coursethread", "sme-candidates", "cand-001")

# Find all candidates with a specific vetting status
query_bucket("coursethread", "sme-candidates", {"vetting_status": "applied"})

# Update vetting status (put_file overwrites)
put_file("coursethread", "sme-candidates", "cand-001", {
    "name": "Jane Smith",
    "email": "jane@example.com",
    "domain": "Cybersecurity",
    "per_course_price_usd": 50,
    "vetting_status": "md_reviewed",
    "linkedin_url": "https://linkedin.com/in/janesmith",
    "fact_check_approach": "I verify claims against peer-reviewed sources...",
    "vetting_notes": "Credentials verified via LinkedIn. Domain fit confirmed."
})
```

### Different use case (tender leads, different password)

```
create_bucket("coursethread", "tender-leads")

# A dialog appears to create a DIFFERENT password for this bucket
put_file("coursethread", "tender-leads", "t-001", {
    "title": "NHS Digital Training Framework",
    "deadline": "2026-09-15",
    "value_gbp": 50000,
    "status": "monitoring"
})

query_bucket("coursethread", "tender-leads", {"status": "monitoring"})
```

Same server, same tools, different bucket, different password.

## Security

- **Fernet encryption** - every file is encrypted with AES-128-CBC + HMAC-SHA256. Files on disk are ciphertext.
- **Per-bucket passwords** - each bucket has its own password. There is no master password. Compromising one bucket's password does not compromise other buckets.
- **Human-gated** - the password is entered by the human via a native OS dialog (tkinter) shown by the server process. The AI agent never sees the password. The dialog is a real OS window on the human's desktop — the AI has no visibility into it.
- **No plaintext passwords on disk** - only a bcrypt hash (one-way) and a per-bucket PBKDF2 salt are stored in `.safebase-meta.json`. The raw password exists only in server memory for the chosen session duration.
- **No password in env vars or config files** - there is no `SAFEBASE_PASSWORD` environment variable. The password cannot be read from a config file.
- **Git history is ciphertext** - the storage root is a git repo auto-committed by the server. Since all files are `.enc`, the git history contains only ciphertext. No plaintext appears in diffs.
- **Local only** - the server runs as a stdio subprocess. No network exposure.

### What this protects against

- The AI agent reading the password from a config file or env var (there is none)
- The AI agent intercepting the password (the dialog is a native OS window, not visible to the AI)
- An attacker with read access to the storage root (files are encrypted; the metadata contains only a one-way hash)
- Plaintext leaking into git history (all files are ciphertext)

### What this does not protect against

- An attacker with read access to the server process memory while the key is cached (the raw key is in memory for the chosen duration)
- The human forgetting the password (there is no recovery — by design, the bcrypt hash is one-way)
- Headless / CI / SSH-only environments (the dialog requires a display; SafeBase cannot run without a human at the screen)
- **The AI deleting data without human consent.** `delete_file` and `delete_bucket` do not require the bucket password — they are not crypto operations. The AI can delete files and buckets without prompting the human. This is a deliberate design decision: deletion is recoverable via git (the storage root is a git repo with full ciphertext history). If you need to prevent the AI from deleting, restrict these tools at the MCP client level or remove them from the server.

## Testing

```bash
# Run the full pytest suite (82 tests)
pytest test_server.py -v

# Quick smoke test (headless, no tkinter needed — dialogs are mocked)
python test_smoke.py
```

Tests mock the dialog functions to inject canned passwords, so they run headless without tkinter.

## License

MIT
