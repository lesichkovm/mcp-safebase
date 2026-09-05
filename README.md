# SafeBase

![Tests](https://github.com/lesichkovm/mcp-safebase/actions/workflows/test.yml/badge.svg)

An encrypted store for secrets and sensitive information that AI agents can read and write via MCP — but only when the human unlocks access. This keeps your data safe from leaks, accidental exposure, and AI mishaps. **The human controls access, not the AI.**

## Why

AI agents often need access to secrets and sensitive information — API keys, credentials, customer data. But you don't want the AI to have unrestricted access to all of it at all times. The more the AI can see, the more it can accidentally leak or misuse.

SafeBase gives you control over when and for how long the AI can access your data. When the AI needs it, you unlock the bucket. When you're done, it locks again. The AI only sees the content during the session you allow — not before, not after.

Three rules:

1. **Each bucket is encrypted with a separate password.** Compromising one bucket's password does not compromise the others.
2. **The AI can only see or edit data if the human unlocks the bucket.** When the AI needs to read or write data, SafeBase pops up a native OS password dialog on the human's desktop. Until the human unlocks it, the AI cannot see or modify anything in that bucket.
3. **Unlock is temporary.** The human chooses how long the key stays in memory: 5, 10, or 15 minutes, or for the lifetime of the server process. After that, the bucket locks again and the AI loses access until the human unlocks it next time.

The AI never sees the password.

## How it works

When the AI calls a tool that needs to decrypt data (`get_file`, `put_file`, `query_bucket`, `edit_file`), SafeBase checks whether that bucket's key is already in memory:

- **Bucket is locked** → a password dialog appears on the human's desktop. The human types the password and picks a duration. The server derives the encryption key and holds it in memory. Until the human does this, the AI cannot access any data in that bucket.
- **Bucket is unlocked** → the tool call completes immediately, no dialog.
- **Unlock has expired** → the bucket locks again. The dialog reappears. The AI must wait for the human to unlock it.

For secret rotation, `edit_file` opens a GUI editor on the human's screen pre-filled with the decrypted JSON. The human edits and saves. The AI receives only `"File updated successfully"` — never the new value.

## Data model

- **Database** = a folder
- **Bucket** = a subfolder inside a database, each with its own password
- **File** = one encrypted JSON file inside a bucket

All files are encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256). Passwords are never stored in plaintext — only bcrypt hashes and per-bucket salts live on disk.

## Quick Start

**1. Install:**

```bash
pip install mcp-safebase
```

Or use directly with `uvx` (no install needed):

```bash
uvx mcp-safebase
```

Requires `tkinter` (bundled with Python on Windows and macOS; on Linux may need `python3-tk`).

**2. Create the storage directory** (outside any git repo):

```bash
mkdir C:\Users\YourName\safebase-data
```

**3. Configure your MCP client** (e.g. Windsurf `mcp_config.json`):

```json
{
  "mcpServers": {
    "safebase": {
      "command": "uvx",
      "args": ["mcp-safebase"],
      "env": {
        "SAFEBASE_ROOT": "C:\\Users\\YourName\\safebase-data"
      }
    }
  }
}
```

No password env var. The password is set per-bucket by the human via a dialog on first use.

**4. Use it:**

The MCP client starts the server automatically when the AI calls a tool. The first time the AI writes to a new bucket, a dialog appears on your screen to create a password for that bucket.

## Tools

| Tool | Description | Password dialog? | Editor dialog? |
|------|-------------|:---:|:---:|
| `list_databases` | List all databases (folders) in the root | No | No |
| `create_database` | Create a new database (folder) | No | No |
| `list_buckets` | List buckets (subfolders) in a database | No | No |
| `create_bucket` | Create a new bucket (subfolder) in a database | No | No |
| `list_files` | List files in a bucket | No | No |
| `put_file` | Write an encrypted JSON file to a bucket | Yes¹ | No |
| `get_file` | Read and decrypt a file from a bucket | Yes¹ | No |
| `edit_file` | Open a GUI editor on the human's screen to edit a stored secret. The AI never sees the content — only a success/cancel confirmation. | Yes¹ | **Yes** |
| `delete_file` | Delete a file from a bucket | No | No |
| `delete_bucket` | Delete a bucket and all its contents | No | No |
| `query_bucket` | List all files in a bucket with optional field filtering | Yes¹ | No |
| `change_bucket_password` | Change a bucket's password (re-encrypts all files) | Yes² | No |

**Dialogs shown to the human (the AI never sees any dialog content):**

- **Password dialog** — a native OS window where the human enters or creates the bucket password. Shown by any tool marked "Yes¹" when the key is not already in memory (first use, or after the session duration expires). `change_bucket_password` (Yes²) shows it twice: once for the current password, once for the new one.
- **Editor dialog** — only `edit_file` opens this. It's a tkinter window with an editable text field pre-filled with the decrypted JSON. The human edits the content directly and clicks Save (or Cancel). The AI receives only `"File updated successfully"` or `"Edit cancelled by user"` — never the file content.

## Documentation

- [Specification](docs/specification.md) — full technical spec: architecture, storage model, encryption, password lifecycle, threat model, error handling
- [Password System](docs/password-system.md) — how per-bucket passwords work, session duration, changing passwords, what happens when you cancel
- [Security](docs/security.md) — threat model, what SafeBase protects against and what it doesn't
- [Usage Examples](docs/usage.md) — concrete examples: contact rosters, sales leads, secret rotation

## Testing

```bash
pytest test_server.py -v   # 101 tests
python test_smoke.py       # quick smoke test (headless)
```

Tests mock the dialog functions, so they run without tkinter or a display.

## License

AGPL-3.0 — see [LICENSE](LICENSE). Commercial use requires a separate commercial license.
