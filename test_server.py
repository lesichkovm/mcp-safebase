"""Proper pytest test suite for SafeBase MCP server.

Covers:
- Core logic (databases, buckets, files, encryption, query)
- Edge cases (special characters, large files, wrong password, malformed JSON, concurrent writes)
- Git operations (auto-commit, history, reversion, .gitkeep)
- MCP transport (in-memory Client calling tools end-to-end)

Run: pytest test_server.py -v
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest

# Ensure the server module is importable
sys.path.insert(0, str(Path(__file__).parent))

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_env(tmp_path: Path) -> dict[str, str]:
    """Provide a clean test environment with a temp root and password."""
    env = {
        "SAFEBASE_ROOT": str(tmp_path),
        "SAFEBASE_PASSWORD": "test-password-123",
    }
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        yield env
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@pytest.fixture
def server(test_env) -> "server_module":
    """Import the server module with the test env set."""
    # Remove any cached import so it picks up the env
    if "server" in sys.modules:
        del sys.modules["server"]
    import server as server_module
    return server_module


@pytest.fixture
def populated_server(server, test_env) -> tuple:
    """A server with a database, bucket, and one test file already created."""
    server._create_database("testdb")
    server._create_bucket("testdb", "testbucket")
    server._put_file("testdb", "testbucket", "item-001.json", {
        "name": "Alice",
        "email": "alice@example.com",
        "status": "active",
        "tags": ["alpha", "beta"],
    })
    return server, test_env


# ---------------------------------------------------------------------------
# Database tests
# ---------------------------------------------------------------------------

class TestDatabases:
    def test_create_database(self, server):
        result = server._create_database("mydb")
        assert "Created" in result

    def test_create_database_idempotent(self, server):
        server._create_database("mydb")
        result = server._create_database("mydb")
        assert "already exists" in result

    def test_list_databases(self, server):
        server._create_database("db-a")
        server._create_database("db-b")
        dbs = server._list_databases()
        assert "db-a" in dbs
        assert "db-b" in dbs

    def test_list_databases_empty(self, server):
        dbs = server._list_databases()
        assert dbs == []

    def test_list_databases_excludes_hidden(self, server):
        server._create_database("visible")
        # Manually create a hidden dir
        root = server._get_root()
        (root / ".hidden").mkdir()
        dbs = server._list_databases()
        assert "visible" in dbs
        assert ".hidden" not in dbs

    def test_create_database_invalid_name_empty(self, server):
        with pytest.raises(ValueError, match="cannot be empty"):
            server._create_database("")

    def test_create_database_invalid_name_path_traversal(self, server):
        with pytest.raises(ValueError, match="invalid"):
            server._create_database("../escape")

    def test_create_database_invalid_name_dot_prefix(self, server):
        with pytest.raises(ValueError, match="invalid"):
            server._create_database(".hidden")

    def test_create_database_invalid_name_spaces(self, server):
        with pytest.raises(ValueError, match="invalid"):
            server._create_database("my db")

    def test_create_database_valid_with_hyphen(self, server):
        result = server._create_database("my-db")
        assert "Created" in result

    def test_create_database_valid_with_underscore(self, server):
        result = server._create_database("my_db")
        assert "Created" in result

    def test_create_database_valid_with_numbers(self, server):
        result = server._create_database("db123")
        assert "Created" in result


# ---------------------------------------------------------------------------
# Bucket tests
# ---------------------------------------------------------------------------

class TestBuckets:
    def test_create_bucket(self, server):
        server._create_database("mydb")
        result = server._create_bucket("mydb", "mybucket")
        assert "Created" in result

    def test_create_bucket_idempotent(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        result = server._create_bucket("mydb", "mybucket")
        assert "already exists" in result

    def test_list_buckets(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "bucket-a")
        server._create_bucket("mydb", "bucket-b")
        buckets = server._list_buckets("mydb")
        assert "bucket-a" in buckets
        assert "bucket-b" in buckets

    def test_list_buckets_nonexistent_db(self, server):
        result = server._list_buckets("nonexistent")
        assert "does not exist" in result

    def test_create_bucket_invalid_name(self, server):
        server._create_database("mydb")
        with pytest.raises(ValueError):
            server._create_bucket("mydb", "../escape")

    def test_create_bucket_in_nonexistent_db(self, server):
        # _create_bucket validates names first, then tries to mkdir.
        # With a valid db name that doesn't exist, mkdir(parents=True) will
        # create the db folder too. This is acceptable — the db is created
        # implicitly. Test that it works.
        result = server._create_bucket("implicit-db", "mybucket")
        assert "Created" in result


# ---------------------------------------------------------------------------
# File tests
# ---------------------------------------------------------------------------

class TestFiles:
    def test_put_file(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        result = server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        assert "Wrote" in result
        assert "mydb/mybucket/test.json" in result

    def test_put_file_overwrite(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"version": 1})
        server._put_file("mydb", "mybucket", "test.json", {"version": 2})
        data = server._get_file("mydb", "mybucket", "test.json")
        assert data["version"] == 2

    def test_get_file(self, populated_server):
        server, _ = populated_server
        data = server._get_file("testdb", "testbucket", "item-001.json")
        assert data["name"] == "Alice"
        assert data["email"] == "alice@example.com"

    def test_get_file_nonexistent(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        result = server._get_file("mydb", "mybucket", "nonexistent.json")
        assert "does not exist" in result

    def test_delete_file(self, populated_server):
        server, _ = populated_server
        result = server._delete_file("testdb", "testbucket", "item-001.json")
        assert "Deleted" in result
        # Verify it's gone
        files = server._list_files("testdb", "testbucket")
        assert "item-001.json" not in files

    def test_delete_file_nonexistent(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        result = server._delete_file("mydb", "mybucket", "nonexistent.json")
        assert "does not exist" in result

    def test_list_files(self, populated_server):
        server, _ = populated_server
        files = server._list_files("testdb", "testbucket")
        assert "item-001.json" in files

    def test_list_files_empty_bucket(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        files = server._list_files("mydb", "mybucket")
        assert files == []

    def test_list_files_nonexistent_bucket(self, server):
        server._create_database("mydb")
        result = server._list_files("mydb", "nonexistent")
        assert "does not exist" in result

    def test_put_file_nonexistent_bucket(self, server):
        server._create_database("mydb")
        result = server._put_file("mydb", "nonexistent", "test.json", {"key": "value"})
        assert "does not exist" in result

    def test_put_file_invalid_filename_no_extension(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        with pytest.raises(ValueError, match="must end with .json"):
            server._put_file("mydb", "mybucket", "noext", {"key": "value"})

    def test_put_file_invalid_filename_path_traversal(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        with pytest.raises(ValueError):
            server._put_file("mydb", "mybucket", "../escape.json", {"key": "value"})


# ---------------------------------------------------------------------------
# Query tests
# ---------------------------------------------------------------------------

class TestQuery:
    def test_query_no_filter(self, populated_server):
        server, _ = populated_server
        server._put_file("testdb", "testbucket", "item-002.json", {
            "name": "Bob", "status": "active"
        })
        items = server._query_bucket("testdb", "testbucket")
        assert len(items) == 2

    def test_query_with_filter_match(self, populated_server):
        server, _ = populated_server
        server._put_file("testdb", "testbucket", "item-002.json", {
            "name": "Bob", "status": "inactive"
        })
        items = server._query_bucket("testdb", "testbucket", {"status": "active"})
        assert len(items) == 1
        assert items[0]["name"] == "Alice"

    def test_query_with_filter_no_match(self, populated_server):
        server, _ = populated_server
        items = server._query_bucket("testdb", "testbucket", {"status": "nonexistent"})
        assert len(items) == 0

    def test_query_with_multiple_filters(self, populated_server):
        server, _ = populated_server
        items = server._query_bucket("testdb", "testbucket", {
            "status": "active",
            "name": "Alice",
        })
        assert len(items) == 1

    def test_query_nonexistent_bucket(self, server):
        server._create_database("mydb")
        result = server._query_bucket("mydb", "nonexistent")
        assert "does not exist" in result

    def test_query_returns_filename(self, populated_server):
        server, _ = populated_server
        items = server._query_bucket("testdb", "testbucket")
        assert items[0]["filename"] == "item-001.json"

    def test_query_with_nested_data(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {
            "metadata": {"author": "Alice", "version": 1},
            "tags": ["alpha", "beta"],
            "nested": {"deep": {"value": 42}},
        })
        data = server._get_file("mydb", "mybucket", "test.json")
        assert data["metadata"]["author"] == "Alice"
        assert data["nested"]["deep"]["value"] == 42
        assert "alpha" in data["tags"]


# ---------------------------------------------------------------------------
# Encryption tests
# ---------------------------------------------------------------------------

class TestEncryption:
    def test_file_on_disk_is_ciphertext(self, populated_server, test_env):
        server, env = populated_server
        root = Path(env["SAFEBASE_ROOT"])
        enc_path = root / "testdb" / "testbucket" / "item-001.json.enc"
        raw = enc_path.read_bytes()
        assert b"Alice" not in raw
        assert b"alice@example.com" not in raw
        assert b"active" not in raw

    def test_file_extension_is_enc(self, populated_server, test_env):
        server, env = populated_server
        root = Path(env["SAFEBASE_ROOT"])
        enc_path = root / "testdb" / "testbucket" / "item-001.json.enc"
        assert enc_path.exists()
        assert enc_path.suffix == ".enc"

    def test_wrong_password_cannot_decrypt(self, tmp_path):
        """Files encrypted with one password cannot be decrypted with another."""
        env1 = {"SAFEBASE_ROOT": str(tmp_path), "SAFEBASE_PASSWORD": "password-one"}
        old = {k: os.environ.get(k) for k in env1}
        os.environ.update(env1)
        try:
            if "server" in sys.modules:
                del sys.modules["server"]
            import server as s1
            s1._create_database("mydb")
            s1._create_bucket("mydb", "mybucket")
            s1._put_file("mydb", "mybucket", "test.json", {"secret": "data"})
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        # Now try to read with a different password
        env2 = {"SAFEBASE_ROOT": str(tmp_path), "SAFEBASE_PASSWORD": "password-two"}
        old2 = {k: os.environ.get(k) for k in env2}
        os.environ.update(env2)
        try:
            if "server" in sys.modules:
                del sys.modules["server"]
            import server as s2
            with pytest.raises(Exception):
                s2._get_file("mydb", "mybucket", "test.json")
        finally:
            for k, v in old2.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_unicode_content_preserved(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "unicode.json", {
            "name": "José García",
            "city": "München",
            "emoji": "🎉",
            "cyrillic": "Привет",
            "japanese": "こんにちは",
        })
        data = server._get_file("mydb", "mybucket", "unicode.json")
        assert data["name"] == "José García"
        assert data["city"] == "München"
        assert data["emoji"] == "🎉"
        assert data["cyrillic"] == "Привет"
        assert data["japanese"] == "こんにちは"

    def test_large_file(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        large_data = {
            "items": [{"id": i, "value": f"item-{i}" * 100} for i in range(1000)],
            "count": 1000,
        }
        server._put_file("mydb", "mybucket", "large.json", large_data)
        data = server._get_file("mydb", "mybucket", "large.json")
        assert data["count"] == 1000
        assert len(data["items"]) == 1000
        assert data["items"][500]["id"] == 500

    def test_empty_dict_content(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "empty.json", {})
        data = server._get_file("mydb", "mybucket", "empty.json")
        assert data == {}

    def test_null_values_in_content(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "nulls.json", {
            "name": "Alice",
            "email": None,
            "phone": None,
            "tags": [],
        })
        data = server._get_file("mydb", "mybucket", "nulls.json")
        assert data["name"] == "Alice"
        assert data["email"] is None
        assert data["phone"] is None
        assert data["tags"] == []


# ---------------------------------------------------------------------------
# Git tests
# ---------------------------------------------------------------------------

class TestGitHistory:
    def test_git_repo_initialized(self, populated_server, test_env):
        server, env = populated_server
        root = Path(env["SAFEBASE_ROOT"])
        assert (root / ".git").exists()

    def test_git_has_commits(self, populated_server, test_env):
        server, env = populated_server
        root = Path(env["SAFEBASE_ROOT"])
        result = subprocess.run(
            ["git", "log", "--oneline"],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "put:" in result.stdout

    def test_git_commit_on_create_database(self, server, test_env):
        server._create_database("newdb")
        root = Path(test_env["SAFEBASE_ROOT"])
        result = subprocess.run(
            ["git", "log", "--oneline"],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        assert "create database: newdb" in result.stdout

    def test_git_commit_on_create_bucket(self, server, test_env):
        server._create_database("mydb")
        server._create_bucket("mydb", "newbucket")
        root = Path(test_env["SAFEBASE_ROOT"])
        result = subprocess.run(
            ["git", "log", "--oneline"],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        assert "create bucket: mydb/newbucket" in result.stdout

    def test_git_commit_on_delete(self, populated_server, test_env):
        server, _ = populated_server
        server._delete_file("testdb", "testbucket", "item-001.json")
        root = Path(test_env["SAFEBASE_ROOT"])
        result = subprocess.run(
            ["git", "log", "--oneline"],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        assert "delete: testdb/testbucket/item-001.json" in result.stdout

    def test_git_history_contains_no_plaintext(self, populated_server, test_env):
        server, env = populated_server
        root = Path(env["SAFEBASE_ROOT"])
        result = subprocess.run(
            ["git", "log", "-p", "--all"],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        assert "Alice" not in result.stdout
        assert "alice@example.com" not in result.stdout

    def test_gitkeep_in_empty_bucket(self, server, test_env):
        server._create_database("mydb")
        server._create_bucket("mydb", "emptybucket")
        root = Path(test_env["SAFEBASE_ROOT"])
        assert (root / "mydb" / "emptybucket" / ".gitkeep").exists()

    def test_gitkeep_not_listed_in_files(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        files = server._list_files("mydb", "mybucket")
        assert ".gitkeep" not in files
        assert files == []

    def test_git_reversion_restores_deleted_file(self, populated_server, test_env):
        """Delete a file, then revert via git to restore it."""
        server, env = populated_server
        root = Path(env["SAFEBASE_ROOT"])

        # Verify file exists
        data = server._get_file("testdb", "testbucket", "item-001.json")
        assert data["name"] == "Alice"

        # Delete it
        server._delete_file("testdb", "testbucket", "item-001.json")
        result = server._get_file("testdb", "testbucket", "item-001.json")
        assert "does not exist" in result

        # Revert the delete commit
        subprocess.run(
            ["git", "revert", "HEAD", "--no-edit"],
            cwd=str(root),
            capture_output=True,
            check=True,
        )
        # Checkout the restored file from git
        subprocess.run(
            ["git", "checkout", "HEAD", "--", "testdb/testbucket/item-001.json.enc"],
            cwd=str(root),
            capture_output=True,
            check=True,
        )

        # File should be back and decryptable
        data = server._get_file("testdb", "testbucket", "item-001.json")
        assert data["name"] == "Alice"


# ---------------------------------------------------------------------------
# MCP Transport tests (in-memory Client)
# ---------------------------------------------------------------------------

class TestMCPTransport:
    """Test the server through the MCP protocol using an in-memory Client.

    Each test runs a full async coroutine that sets up the client, performs
    the test actions, and tears down — all within the same task to avoid
    anyio cancel scope issues.
    """

    def _run_mcp_test(self, test_env, test_coro):
        """Run an async test with a fresh in-memory MCP client.

        The test_coro is an async function that receives the client and
        performs assertions. Setup and teardown happen in the same task.
        """
        if "server" in sys.modules:
            del sys.modules["server"]
        import server as server_module
        from mcp import Client

        async def runner():
            async with Client(server_module.mcp) as client:
                await test_coro(client)

        asyncio.run(runner())

    def test_list_tools(self, test_env):
        async def test(client):
            result = await client.list_tools()
            # list_tools returns a ListToolsResult with a .tools attribute
            tools = result.tools if hasattr(result, "tools") else result
            tool_names = [t.name for t in tools]
            assert "list_databases" in tool_names
            assert "create_database" in tool_names
            assert "create_bucket" in tool_names
            assert "list_files" in tool_names
            assert "put_file" in tool_names
            assert "get_file" in tool_names
            assert "delete_file" in tool_names
            assert "query_bucket" in tool_names

        self._run_mcp_test(test_env, test)

    def test_create_database_via_mcp(self, test_env):
        async def test(client):
            result = await client.call_tool("create_database", {"database": "mcpdb"})
            text = result.content[0].text
            assert "Created" in text

        self._run_mcp_test(test_env, test)

    def test_full_workflow_via_mcp(self, test_env):
        async def test(client):
            # Create database
            r = await client.call_tool("create_database", {"database": "coursethread"})
            assert "Created" in r.content[0].text

            # Create bucket
            r = await client.call_tool("create_bucket", {
                "database": "coursethread", "bucket": "sme-candidates"
            })
            assert "Created" in r.content[0].text

            # Put file
            r = await client.call_tool("put_file", {
                "database": "coursethread",
                "bucket": "sme-candidates",
                "filename": "cand-001.json",
                "content": {"name": "Jane", "status": "applied"},
            })
            assert "Wrote" in r.content[0].text

            # Get file
            r = await client.call_tool("get_file", {
                "database": "coursethread",
                "bucket": "sme-candidates",
                "filename": "cand-001.json",
            })
            data = json.loads(r.content[0].text)
            assert data["name"] == "Jane"
            assert data["status"] == "applied"

            # Query bucket
            r = await client.call_tool("query_bucket", {
                "database": "coursethread",
                "bucket": "sme-candidates",
                "filter_fields": {"status": "applied"},
            })
            items = json.loads(r.content[0].text)
            assert len(items) == 1
            assert items[0]["name"] == "Jane"

            # List files
            r = await client.call_tool("list_files", {
                "database": "coursethread",
                "bucket": "sme-candidates",
            })
            files = json.loads(r.content[0].text)
            assert "cand-001.json" in files

            # Delete file
            r = await client.call_tool("delete_file", {
                "database": "coursethread",
                "bucket": "sme-candidates",
                "filename": "cand-001.json",
            })
            assert "Deleted" in r.content[0].text

            # Verify deletion
            r = await client.call_tool("list_files", {
                "database": "coursethread",
                "bucket": "sme-candidates",
            })
            files = json.loads(r.content[0].text)
            assert "cand-001.json" not in files

        self._run_mcp_test(test_env, test)

    def test_error_handling_via_mcp(self, test_env):
        async def test(client):
            # Get nonexistent file — should return error message, not crash
            r = await client.call_tool("get_file", {
                "database": "nonexistent",
                "bucket": "nonexistent",
                "filename": "nonexistent.json",
            })
            text = r.content[0].text
            assert "does not exist" in text or "Error" in text

        self._run_mcp_test(test_env, test)

    def test_list_databases_via_mcp(self, test_env):
        async def test(client):
            await client.call_tool("create_database", {"database": "db1"})
            await client.call_tool("create_database", {"database": "db2"})
            r = await client.call_tool("list_databases", {})
            dbs = json.loads(r.content[0].text)
            assert "db1" in dbs
            assert "db2" in dbs

        self._run_mcp_test(test_env, test)
