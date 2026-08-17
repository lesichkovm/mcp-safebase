# SafeBase

Encrypted file-based storage accessed via MCP (Model Context Protocol).

## What it is

SafeBase is a Python MCP server that provides encrypted file-based storage organized as databases, buckets, and files. Think of it as a lightweight encrypted file system accessed through MCP tool calls.

- **Database** = a folder (like a database server has multiple databases)
- **Bucket** = a subfolder inside a database (like a database has tables)
- **File** = one encrypted JSON file inside a bucket (like a table has rows)

All files are encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256). The encryption key is provided via environment variable and never touches the stored files or the repo.

## Architecture

```
MCP Client (AI agent)
    |
    | MCP tool calls (list_databases, put_file, get_file, query_bucket, ...)
    v
SafeBase MCP Server (Python, this repo)
    |
    | reads/writes encrypted files
    v
Encrypted file store (OUTSIDE the repo, path set via env var)
    |
    | on disk structure:
    v
{SAFEBASE_ROOT}/
  coursethread/
    sme-candidates/
      cand-001.json.enc
      cand-002.json.enc
    tender-leads/
      t-001.json.enc
  personal/
    notes/
      note-001.json.enc
```

## Key principles

1. **Files live outside the repo** - the storage root is set via `SAFEBASE_ROOT` env var. No encrypted files are committed to any repo.
2. **Encryption at rest** - every file is encrypted with Fernet (AES-128-CBC + HMAC-SHA256). The key is in `SAFEBASE_KEY` env var.
3. **MCP access only** - the AI agent never touches files directly. It only calls MCP tools. PII appears only in ephemeral tool responses, never in repo files or persisted chat logs.
4. **Schema-free** - the server does not know what's in a bucket. Each file is a JSON object with arbitrary fields. The caller decides the structure per bucket.
5. **Local only** - no network server, no Docker, no cloud. Runs as a stdio MCP subprocess on the local machine.

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate an encryption key

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

Save this key somewhere safe (password manager). You will put it in the MCP config.

### 3. Configure the MCP server

Add to your MCP client config (e.g., `mcp_config.json` for Windsurf):

```json
{
  "mcpServers": {
    "safebase": {
      "command": "python",
      "args": ["D:\\PROJECTs\\_modules_dracory\\mcp-safebase\\server.py"],
      "env": {
        "SAFEBASE_ROOT": "C:\\Users\\SINEVIA\\safebase-data",
        "SAFEBASE_KEY": "<your-fernet-key-here>"
      }
    }
  }
}
```

- `SAFEBASE_ROOT` - the root directory where databases are stored. Create this directory before use.
- `SAFEBASE_KEY` - the Fernet encryption key. Generate one (see step 2).

### 4. Start using

The MCP client starts the server automatically when an AI agent calls a tool. No manual startup needed.

## Tools

| Tool | Description |
|------|-------------|
| `list_databases` | List all databases (folders) in the root |
| `create_database` | Create a new database (folder) |
| `list_buckets` | List buckets (subfolders) in a database |
| `create_bucket` | Create a new bucket (subfolder) in a database |
| `list_files` | List files in a bucket |
| `put_file` | Write an encrypted JSON file to a bucket |
| `get_file` | Read and decrypt a file from a bucket |
| `delete_file` | Delete a file from a bucket |
| `query_bucket` | List all files in a bucket with optional field filtering |

## Usage examples

### SME candidate roster

```
# Create structure
create_database("coursethread")
create_bucket("coursethread", "sme-candidates")

# Add a candidate
put_file("coursethread", "sme-candidates", "cand-001", {
    "name": "Jane Smith",
    "email": "jane@example.com",
    "domain": "Cybersecurity",
    "per_course_price_usd": 50,
    "vetting_status": "applied",
    "linkedin_url": "https://linkedin.com/in/janesmith",
    "fact_check_approach": "I verify claims against peer-reviewed sources..."
})

# List all candidates
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

### Completely different use case (tender leads)

```
create_bucket("coursethread", "tender-leads")

put_file("coursethread", "tender-leads", "t-001", {
    "title": "NHS Digital Training Framework",
    "deadline": "2026-09-15",
    "value_gbp": 50000,
    "status": "monitoring"
})

query_bucket("coursethread", "tender-leads", {"status": "monitoring"})
```

Same server, same tools, different bucket, different schema.

## Security

- **Fernet encryption** - every file is encrypted with AES-128-CBC + HMAC-SHA256. Files on disk are ciphertext.
- **Key in env, not in repo** - the encryption key is in `SAFEBASE_KEY` env var, set in the MCP client config. It never appears in the server code, in the stored files, or in chat logs.
- **No plaintext on disk** - the storage root contains only `.enc` files. No plaintext is ever written to disk.
- **Local only** - the server runs as a stdio subprocess. No network exposure.

## License

MIT
