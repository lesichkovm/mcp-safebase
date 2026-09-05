# SafeBase

Encrypted file-based storage accessed via MCP, with human-gated per-bucket passwords.

## What it is

A Python MCP server that provides encrypted file-based storage organized as databases, buckets, and files. The AI agent reads and writes data through MCP tool calls. The human gates access by entering per-bucket passwords into native OS dialogs that the server pops up on their desktop. **The AI never sees the password.**

- **Database** = a folder
- **Bucket** = a subfolder inside a database, each with its own password
- **File** = one encrypted JSON file inside a bucket

All files are encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256). Passwords are never stored in plaintext — only bcrypt hashes and per-bucket salts live on disk.

## Quick Start

**1. Install:**

```bash
pip install -r requirements.txt
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
      "command": "python",
      "args": ["D:\\PROJECTs\\_modules_dracory\\mcp-safebase\\server.py"],
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

| Tool | Description | Needs password? |
|------|-------------|:---:|
| `list_databases` | List all databases (folders) in the root | No |
| `create_database` | Create a new database (folder) | No |
| `list_buckets` | List buckets (subfolders) in a database | No |
| `create_bucket` | Create a new bucket (subfolder) in a database | No |
| `list_files` | List files in a bucket | No |
| `put_file` | Write an encrypted JSON file to a bucket | Yes |
| `get_file` | Read and decrypt a file from a bucket | Yes |
| `edit_file` | Open a GUI editor on the human's screen to edit a stored secret. The AI never sees the content — only a success/cancel confirmation. | Yes |
| `delete_file` | Delete a file from a bucket | No |
| `delete_bucket` | Delete a bucket and all its contents | No |
| `query_bucket` | List all files in a bucket with optional field filtering | Yes |
| `change_bucket_password` | Change a bucket's password (re-encrypts all files) | Yes |

## Documentation

- [Specification](docs/specification.md) — full technical spec: architecture, storage model, encryption, password lifecycle, threat model, error handling
- [Password System](docs/password-system.md) — how per-bucket passwords work, session duration, changing passwords, what happens when you cancel
- [Security](docs/security.md) — threat model, what SafeBase protects against and what it doesn't
- [Usage Examples](docs/usage.md) — concrete examples: SME candidates, tender leads, different schemas

## Testing

```bash
pytest test_server.py -v   # 92 tests
python test_smoke.py       # quick smoke test (headless)
```

Tests mock the dialog functions, so they run without tkinter or a display.

## License

AGPL-3.0 — see [LICENSE](LICENSE). Commercial use requires a separate commercial license.
