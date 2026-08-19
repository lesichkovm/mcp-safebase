"""Proper pytest test suite for SafeBase MCP server.

Covers:
- Core logic (databases, buckets, files, encryption, query)
- Per-bucket password system (create, enter, verify, change, delete bucket)
- Key cache (caching, idle timeout, cache clear on delete)
- Edge cases (special characters, large files, wrong password, malformed JSON)
- Git operations (auto-commit, history, reversion, .gitkeep)
- MCP transport (in-memory Client calling tools end-to-end)

The dialog functions are monkeypatched to inject canned passwords so tests
run headless without tkinter.

Run: pytest test_server.py -v
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Generator, Optional

import pytest

# Ensure the server module is importable
sys.path.insert(0, str(Path(__file__).parent))


# ---------------------------------------------------------------------------
# Dialog mock helpers
# ---------------------------------------------------------------------------

def make_create_dialog(password: str = "test-pass-123", duration: int = 5):
    """Return a mock create-password dialog that always returns the given password."""
    def _mock(database: str, bucket: str):
        from server import DialogResult
        return DialogResult(password=password, duration_minutes=duration)
    return _mock


def make_enter_dialog(password: str = "test-pass-123", duration: int = 5):
    """Return a mock enter-password dialog that always returns the given password."""
    def _mock(database: str, bucket: str):
        from server import DialogResult
        return DialogResult(password=password, duration_minutes=duration)
    return _mock


def make_cancel_dialog():
    """Return a mock dialog that simulates the human cancelling."""
    def _mock(database: str, bucket: str):
        return None
    return _mock


def make_change_dialog(new_password: str = "new-pass-456", duration: int = 5):
    """Return a mock change-password dialog that returns the new password."""
    def _mock(database: str, bucket: str):
        from server import DialogResult
        return DialogResult(password=new_password, duration_minutes=duration)
    return _mock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_env(tmp_path: Path) -> dict[str, str]:
    """Provide a clean test environment with a temp root. No password env var."""
    env = {"SAFEBASE_ROOT": str(tmp_path)}
    old = {k: os.environ.get(k) for k in env}
    # Also clear any leftover SAFEBASE_PASSWORD from old runs
    old_pw = os.environ.get("SAFEBASE_PASSWORD")
    os.environ.pop("SAFEBASE_PASSWORD", None)
    os.environ.update(env)
    try:
        yield env
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if old_pw is not None:
            os.environ["SAFEBASE_PASSWORD"] = old_pw
        else:
            os.environ.pop("SAFEBASE_PASSWORD", None)


@pytest.fixture
def server(test_env) -> "server_module":
    """Import the server module with the test env set and default dialog mocks."""
    if "server" in sys.modules:
        del sys.modules["server"]
    import server as server_module

    # Install default dialog mocks so tests don't need tkinter
    server_module._prompt_create_password_fn = make_create_dialog()
    server_module._prompt_enter_password_fn = make_enter_dialog()
    server_module._prompt_change_password_fn = make_change_dialog()

    # Clear the key cache between tests
    server_module._key_cache.clear()
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
    # Clear the key cache after population so subsequent get_file re-prompts
    # (simulating a fresh session). Tests that want the key to persist can
    # skip this — but the dialog mock returns instantly so it doesn't matter.
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
        result = server._create_bucket("implicit-db", "mybucket")
        assert "Created" in result

    def test_delete_bucket(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        result = server._delete_bucket("mydb", "mybucket")
        assert "Deleted bucket" in result
        # Verify the folder is gone
        root = server._get_root()
        assert not (root / "mydb" / "mybucket").exists()

    def test_delete_bucket_nonexistent(self, server):
        server._create_database("mydb")
        result = server._delete_bucket("mydb", "nonexistent")
        assert "does not exist" in result

    def test_delete_bucket_clears_key_cache(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        # Key should be in cache after put_file
        assert "mydb/mybucket" in server._key_cache
        server._delete_bucket("mydb", "mybucket")
        assert "mydb/mybucket" not in server._key_cache


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
        server._put_file("mydb", "mybucket", "dummy.json", {"k": "v"})
        result = server._get_file("mydb", "mybucket", "nonexistent.json")
        assert "does not exist" in result

    def test_delete_file(self, populated_server):
        server, _ = populated_server
        result = server._delete_file("testdb", "testbucket", "item-001.json")
        assert "Deleted" in result
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

    def test_list_files_excludes_meta_file(self, server):
        """The .safebase-meta.json file should not appear in list_files."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        files = server._list_files("mydb", "mybucket")
        assert ".safebase-meta.json" not in files
        assert "test.json" in files


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

    def test_query_excludes_meta_file(self, server):
        """query_bucket should not return the .safebase-meta.json as a file."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        items = server._query_bucket("mydb", "mybucket")
        filenames = [i["filename"] for i in items]
        assert ".safebase-meta.json" not in filenames
        assert "test.json" in filenames


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
        """Files encrypted with one bucket password cannot be decrypted with another.

        With per-bucket passwords, entering the wrong password is caught by the
        bcrypt verification in _get_bucket_key, which raises AccessDenied. The
        _get_file wrapper catches that and returns an access-denied string.
        So the test checks for the access-denied message, not an exception.
        """
        env = {"SAFEBASE_ROOT": str(tmp_path)}
        old = {k: os.environ.get(k) for k in env}
        os.environ.pop("SAFEBASE_PASSWORD", None)
        os.environ.update(env)
        try:
            if "server" in sys.modules:
                del sys.modules["server"]
            import server as s1
            s1._prompt_create_password_fn = make_create_dialog("password-one")
            s1._prompt_enter_password_fn = make_enter_dialog("password-one")
            s1._prompt_change_password_fn = make_change_dialog()
            s1._key_cache.clear()
            s1._create_database("mydb")
            s1._create_bucket("mydb", "mybucket")
            s1._put_file("mydb", "mybucket", "test.json", {"secret": "data"})
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        # Now try to read with a different password — should get access denied
        os.environ["SAFEBASE_ROOT"] = str(tmp_path)
        try:
            if "server" in sys.modules:
                del sys.modules["server"]
            import server as s2
            s2._prompt_create_password_fn = make_create_dialog("password-two")
            s2._prompt_enter_password_fn = make_enter_dialog("password-two")
            s2._prompt_change_password_fn = make_change_dialog()
            s2._key_cache.clear()
            result = s2._get_file("mydb", "mybucket", "test.json")
            assert isinstance(result, str)
            assert "Access denied" in result
            assert "incorrect" in result.lower()
        finally:
            for k, v in old.items():
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
# Per-bucket password tests
# ---------------------------------------------------------------------------

class TestPerBucketPasswords:
    def test_first_put_creates_metadata(self, server, test_env):
        """First put_file on a bucket creates .safebase-meta.json."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        root = Path(test_env["SAFEBASE_ROOT"])
        meta_path = root / "mydb" / "mybucket" / ".safebase-meta.json"
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        assert "bcrypt_hash" in meta
        assert "pbkdf2_salt" in meta
        assert meta["version"] == 1

    def test_metadata_not_in_file_list(self, server):
        """The metadata file should not appear in list_files."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        files = server._list_files("mydb", "mybucket")
        assert all(not f.startswith(".") for f in files)

    def test_metadata_contains_no_plaintext_password(self, server, test_env):
        """The metadata file must not contain the raw password."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        root = Path(test_env["SAFEBASE_ROOT"])
        meta_path = root / "mydb" / "mybucket" / ".safebase-meta.json"
        meta_text = meta_path.read_text()
        assert "test-pass-123" not in meta_text

    def test_cancel_create_dialog_returns_access_denied(self, server):
        """If the human cancels the create-password dialog, put_file returns access denied."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._prompt_create_password_fn = make_cancel_dialog()
        result = server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        assert "Access denied" in result

    def test_cancel_enter_dialog_returns_access_denied(self, server):
        """If the human cancels the enter-password dialog, get_file returns access denied."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        # Clear cache so the next call re-prompts
        server._key_cache.clear()
        server._prompt_enter_password_fn = make_cancel_dialog()
        result = server._get_file("mydb", "mybucket", "test.json")
        assert "Access denied" in result

    def test_wrong_password_returns_access_denied(self, server):
        """Entering the wrong password returns access denied."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        # Clear cache, then use a wrong password
        server._key_cache.clear()
        server._prompt_enter_password_fn = make_enter_dialog("wrong-password")
        result = server._get_file("mydb", "mybucket", "test.json")
        assert "Access denied" in result
        assert "incorrect" in result.lower() or "Incorrect" in result

    def test_different_buckets_different_passwords(self, server):
        """Two buckets can have different passwords and operate independently."""
        server._create_database("mydb")
        server._create_bucket("mydb", "bucket-a")
        server._create_bucket("mydb", "bucket-b")

        # Set different passwords for each bucket
        server._prompt_create_password_fn = make_create_dialog("pass-a")
        server._put_file("mydb", "bucket-a", "a.json", {"data": "alpha"})

        server._prompt_create_password_fn = make_create_dialog("pass-b")
        server._put_file("mydb", "bucket-b", "b.json", {"data": "beta"})

        # Clear cache; read each with the correct password
        server._key_cache.clear()
        server._prompt_enter_password_fn = make_enter_dialog("pass-a")
        data_a = server._get_file("mydb", "bucket-a", "a.json")
        assert data_a["data"] == "alpha"

        server._key_cache.clear()
        server._prompt_enter_password_fn = make_enter_dialog("pass-b")
        data_b = server._get_file("mydb", "bucket-b", "b.json")
        assert data_b["data"] == "beta"

    def test_change_bucket_password(self, server):
        """change_bucket_password re-encrypts all files with the new key."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "f1.json", {"val": 1})
        server._put_file("mydb", "mybucket", "f2.json", {"val": 2})

        # Change password: enter old, then new
        server._prompt_enter_password_fn = make_enter_dialog("test-pass-123")
        server._prompt_change_password_fn = make_change_dialog("new-pass-456")
        result = server._change_bucket_password("mydb", "mybucket")
        assert "Password changed" in result
        assert "2 file" in result

        # Clear cache; read with the new password
        server._key_cache.clear()
        server._prompt_enter_password_fn = make_enter_dialog("new-pass-456")
        data1 = server._get_file("mydb", "mybucket", "f1.json")
        data2 = server._get_file("mydb", "mybucket", "f2.json")
        assert data1["val"] == 1
        assert data2["val"] == 2

    def test_change_password_wrong_old_password_fails(self, server):
        """change_bucket_password with wrong old password fails."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "f1.json", {"val": 1})

        server._prompt_enter_password_fn = make_enter_dialog("wrong-old-pass")
        server._prompt_change_password_fn = make_change_dialog("new-pass-456")
        result = server._change_bucket_password("mydb", "mybucket")
        assert "incorrect" in result.lower() or "Incorrect" in result

    def test_change_password_same_password_rejected(self, server):
        """change_bucket_password rejects the same password as the new one."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "f1.json", {"val": 1})

        server._prompt_enter_password_fn = make_enter_dialog("test-pass-123")
        server._prompt_change_password_fn = make_change_dialog("test-pass-123")
        result = server._change_bucket_password("mydb", "mybucket")
        assert "different" in result.lower()

    def test_change_password_cancelled(self, server):
        """change_bucket_password cancelled by human returns cancelled message."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "f1.json", {"val": 1})

        server._prompt_enter_password_fn = make_cancel_dialog()
        result = server._change_bucket_password("mydb", "mybucket")
        assert "cancelled" in result.lower() or "denied" in result.lower()

    def test_change_password_nonexistent_bucket(self, server):
        server._create_database("mydb")
        result = server._change_bucket_password("mydb", "nonexistent")
        assert "does not exist" in result

    def test_change_password_bucket_with_no_password(self, server):
        """change_bucket_password on a bucket with no files (no password set) returns error."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        result = server._change_bucket_password("mydb", "mybucket")
        assert "no password" in result.lower()


# ---------------------------------------------------------------------------
# Key cache tests
# ---------------------------------------------------------------------------

class TestKeyCache:
    def test_key_cached_after_first_use(self, server):
        """After the first put_file, the key is in the cache (no re-prompt for get_file)."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")

        prompt_count = [0]
        def counting_enter(db, bk):
            prompt_count[0] += 1
            from server import DialogResult
            return DialogResult(password="test-pass-123", duration_minutes=5)
        server._prompt_enter_password_fn = counting_enter

        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        # get_file should use the cached key, not re-prompt
        data = server._get_file("mydb", "mybucket", "test.json")
        assert data["key"] == "value"
        assert prompt_count[0] == 0  # enter dialog never called

    def test_key_cache_cleared_on_delete_bucket(self, server):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        assert "mydb/mybucket" in server._key_cache
        server._delete_bucket("mydb", "mybucket")
        assert "mydb/mybucket" not in server._key_cache

    def test_key_cache_cleared_on_password_change(self, server):
        """After change_bucket_password, the old key is replaced with the new one."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        old_key = server._key_cache["mydb/mybucket"].fernet

        server._prompt_enter_password_fn = make_enter_dialog("test-pass-123")
        server._prompt_change_password_fn = make_change_dialog("new-pass-456")
        server._change_bucket_password("mydb", "mybucket")

        new_key = server._key_cache["mydb/mybucket"].fernet
        assert old_key != new_key  # different Fernet object (different key)

    def test_key_cache_idle_timeout_expiry(self, server):
        """A cached key expires after the idle timeout and re-prompts."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")

        # Use a very short duration: 1 minute, then manually expire it
        server._prompt_create_password_fn = make_create_dialog(duration=1)
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        assert "mydb/mybucket" in server._key_cache

        # Manually set the expiry to the past to simulate timeout
        server._key_cache["mydb/mybucket"].expires_at = time.time() - 1

        # The next get_file should detect expiry and re-prompt
        prompt_count = [0]
        def counting_enter(db, bk):
            prompt_count[0] += 1
            from server import DialogResult
            return DialogResult(password="test-pass-123", duration_minutes=5)
        server._prompt_enter_password_fn = counting_enter

        data = server._get_file("mydb", "mybucket", "test.json")
        assert data["key"] == "value"
        assert prompt_count[0] == 1  # re-prompted once

    def test_key_cache_negative_duration_clamped(self, server):
        """A negative duration from a misbehaving dialog is clamped to 0 (process lifetime)."""
        from cryptography.fernet import Fernet
        fernet = Fernet(Fernet.generate_key())
        server._store_cached_key("mydb", "mybucket", fernet, -5)
        ck = server._key_cache["mydb/mybucket"]
        assert ck.duration_minutes == 0
        assert ck.expires_at == float("inf")


# ---------------------------------------------------------------------------
# Edge case tests (from code review)
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_get_file_decryption_failure(self, server, test_env):
        """_get_file returns an error string (not an exception) on decryption failure."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})

        # Corrupt the .enc file on disk
        root = Path(test_env["SAFEBASE_ROOT"])
        enc_path = root / "mydb" / "mybucket" / "test.json.enc"
        enc_path.write_bytes(b"this is not valid ciphertext")

        # Clear cache so we re-enter with the key, then try to decrypt
        server._key_cache.clear()
        result = server._get_file("mydb", "mybucket", "test.json")
        assert isinstance(result, str)
        assert "Decryption failed" in result

    def test_load_bucket_meta_corrupted_json(self, server, test_env):
        """_load_bucket_meta returns None for corrupted JSON (not an exception)."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})

        # Corrupt the metadata file
        root = Path(test_env["SAFEBASE_ROOT"])
        meta_path = root / "mydb" / "mybucket" / ".safebase-meta.json"
        meta_path.write_text("this is not json {{{")

        # Should return None, not raise
        bp = root / "mydb" / "mybucket"
        result = server._load_bucket_meta(bp)
        assert result is None

    def test_load_bucket_meta_missing_key(self, server, test_env):
        """_load_bucket_meta returns None if a required key is missing."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})

        # Write metadata missing the bcrypt_hash key
        root = Path(test_env["SAFEBASE_ROOT"])
        meta_path = root / "mydb" / "mybucket" / ".safebase-meta.json"
        meta_path.write_text(json.dumps({"version": 1, "pbkdf2_salt": "abc"}))

        bp = root / "mydb" / "mybucket"
        result = server._load_bucket_meta(bp)
        assert result is None

    def test_corrupted_metadata_triggers_create_dialog(self, server, test_env):
        """If metadata is corrupted, _get_bucket_key treats it as first use (create dialog)."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})

        # Corrupt the metadata
        root = Path(test_env["SAFEBASE_ROOT"])
        meta_path = root / "mydb" / "mybucket" / ".safebase-meta.json"
        meta_path.write_text("corrupted")

        # Clear cache; the create dialog should be called (not enter)
        server._key_cache.clear()
        create_called = [False]
        def tracking_create(db, bk):
            create_called[0] = True
            from server import DialogResult
            return DialogResult(password="new-pass-789", duration_minutes=5)
        server._prompt_create_password_fn = tracking_create
        server._prompt_enter_password_fn = make_enter_dialog("test-pass-123")

        # put_file should trigger the create dialog (overwriting corrupted metadata)
        result = server._put_file("mydb", "mybucket", "test2.json", {"key": "value2"})
        assert create_called[0]
        assert "Wrote" in result

    def test_change_password_partial_failure_preserves_old_metadata(self, server, test_env, monkeypatch):
        """If re-encryption fails partway, the old metadata is still on disk.

        _change_bucket_password does not catch OSError from write_bytes (it's
        an unexpected I/O failure), so the exception propagates. The key
        safety property is that the metadata file was NOT updated before the
        failure — so the old password still works and the remaining files
        are still decryptable.
        """
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "f1.json", {"val": 1})
        server._put_file("mydb", "mybucket", "f2.json", {"val": 2})

        # Save the old metadata content for comparison
        root = Path(test_env["SAFEBASE_ROOT"])
        meta_path = root / "mydb" / "mybucket" / ".safebase-meta.json"
        old_meta_content = meta_path.read_text()

        # Monkeypatch write_bytes on Path to fail on the second .enc file
        original_write = Path.write_bytes
        def failing_write(self, data):
            if self.name.endswith(".enc") and "f2" in self.name:
                raise OSError("Simulated disk full")
            return original_write(self, data)
        monkeypatch.setattr(Path, "write_bytes", failing_write)

        server._prompt_enter_password_fn = make_enter_dialog("test-pass-123")
        server._prompt_change_password_fn = make_change_dialog("new-pass-456")

        # The call should raise OSError (propagated from write_bytes)
        with pytest.raises(OSError, match="Simulated disk full"):
            server._change_bucket_password("mydb", "mybucket")

        # The old metadata should be unchanged (new metadata was NOT written)
        assert meta_path.read_text() == old_meta_content

    def test_wrong_password_retry_then_success(self, server):
        """_get_bucket_key retries on wrong password, then succeeds."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})

        # Clear cache
        server._key_cache.clear()

        # First two attempts: wrong password. Third attempt: correct.
        attempts = [0]
        def retrying_dialog(db, bk):
            attempts[0] += 1
            from server import DialogResult
            if attempts[0] < 3:
                return DialogResult(password="wrong", duration_minutes=5)
            return DialogResult(password="test-pass-123", duration_minutes=5)
        server._prompt_enter_password_fn = retrying_dialog

        data = server._get_file("mydb", "mybucket", "test.json")
        assert data["key"] == "value"
        assert attempts[0] == 3  # two wrong + one correct

    def test_wrong_password_max_attempts_exceeded(self, server):
        """_get_bucket_key raises AccessDenied after max wrong attempts."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})

        server._key_cache.clear()
        server._prompt_enter_password_fn = make_enter_dialog("always-wrong")

        result = server._get_file("mydb", "mybucket", "test.json")
        assert "Access denied" in result
        assert "max attempts" in result.lower()

    def test_change_password_clears_cache_before_starting(self, server):
        """The old key is cleared from the cache before change_bucket_password starts."""
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        assert "mydb/mybucket" in server._key_cache

        # Start a password change — the cache should be cleared early
        # We'll cancel at the enter dialog; the cache should already be empty
        server._prompt_enter_password_fn = make_cancel_dialog()
        server._change_bucket_password("mydb", "mybucket")

        # Cache should be empty (cleared before the dialog was even shown)
        assert "mydb/mybucket" not in server._key_cache


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

    def test_git_commit_on_delete_bucket(self, server, test_env):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        server._delete_bucket("mydb", "mybucket")
        root = Path(test_env["SAFEBASE_ROOT"])
        result = subprocess.run(
            ["git", "log", "--oneline"],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        assert "delete bucket: mydb/mybucket" in result.stdout

    def test_git_commit_on_change_password(self, server, test_env):
        server._create_database("mydb")
        server._create_bucket("mydb", "mybucket")
        server._put_file("mydb", "mybucket", "test.json", {"key": "value"})
        server._prompt_enter_password_fn = make_enter_dialog("test-pass-123")
        server._prompt_change_password_fn = make_change_dialog("new-pass-456")
        server._change_bucket_password("mydb", "mybucket")
        root = Path(test_env["SAFEBASE_ROOT"])
        result = subprocess.run(
            ["git", "log", "--oneline"],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        assert "change password: mydb/mybucket" in result.stdout

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

        data = server._get_file("testdb", "testbucket", "item-001.json")
        assert data["name"] == "Alice"

        server._delete_file("testdb", "testbucket", "item-001.json")
        result = server._get_file("testdb", "testbucket", "item-001.json")
        assert "does not exist" in result

        subprocess.run(
            ["git", "revert", "HEAD", "--no-edit"],
            cwd=str(root),
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "checkout", "HEAD", "--", "testdb/testbucket/item-001.json.enc"],
            cwd=str(root),
            capture_output=True,
            check=True,
        )

        data = server._get_file("testdb", "testbucket", "item-001.json")
        assert data["name"] == "Alice"


# ---------------------------------------------------------------------------
# MCP Transport tests (in-memory Client)
# ---------------------------------------------------------------------------

class TestMCPTransport:
    """Test the server through the MCP protocol using an in-memory Client."""

    def _run_mcp_test(self, test_env, test_coro):
        if "server" in sys.modules:
            del sys.modules["server"]
        import server as server_module
        from mcp import Client

        # Install default dialog mocks
        server_module._prompt_create_password_fn = make_create_dialog()
        server_module._prompt_enter_password_fn = make_enter_dialog()
        server_module._prompt_change_password_fn = make_change_dialog()
        server_module._key_cache.clear()

        async def runner():
            async with Client(server_module.mcp) as client:
                await test_coro(client)

        asyncio.run(runner())

    def test_list_tools(self, test_env):
        async def test(client):
            result = await client.list_tools()
            tools = result.tools if hasattr(result, "tools") else result
            tool_names = [t.name for t in tools]
            assert "list_databases" in tool_names
            assert "create_database" in tool_names
            assert "create_bucket" in tool_names
            assert "list_files" in tool_names
            assert "put_file" in tool_names
            assert "get_file" in tool_names
            assert "delete_file" in tool_names
            assert "delete_bucket" in tool_names
            assert "query_bucket" in tool_names
            assert "change_bucket_password" in tool_names

        self._run_mcp_test(test_env, test)

    def test_create_database_via_mcp(self, test_env):
        async def test(client):
            result = await client.call_tool("create_database", {"database": "mcpdb"})
            assert "Created" in result.content[0].text

        self._run_mcp_test(test_env, test)

    def test_full_workflow_via_mcp(self, test_env):
        async def test(client):
            r = await client.call_tool("create_database", {"database": "coursethread"})
            assert "Created" in r.content[0].text

            r = await client.call_tool("create_bucket", {
                "database": "coursethread", "bucket": "sme-candidates"
            })
            assert "Created" in r.content[0].text

            r = await client.call_tool("put_file", {
                "database": "coursethread",
                "bucket": "sme-candidates",
                "filename": "cand-001.json",
                "content": {"name": "Jane", "status": "applied"},
            })
            assert "Wrote" in r.content[0].text

            r = await client.call_tool("get_file", {
                "database": "coursethread",
                "bucket": "sme-candidates",
                "filename": "cand-001.json",
            })
            data = json.loads(r.content[0].text)
            assert data["name"] == "Jane"
            assert data["status"] == "applied"

            r = await client.call_tool("query_bucket", {
                "database": "coursethread",
                "bucket": "sme-candidates",
                "filter_fields": {"status": "applied"},
            })
            items = json.loads(r.content[0].text)
            assert len(items) == 1
            assert items[0]["name"] == "Jane"

            r = await client.call_tool("list_files", {
                "database": "coursethread",
                "bucket": "sme-candidates",
            })
            files = json.loads(r.content[0].text)
            assert "cand-001.json" in files

            r = await client.call_tool("delete_file", {
                "database": "coursethread",
                "bucket": "sme-candidates",
                "filename": "cand-001.json",
            })
            assert "Deleted" in r.content[0].text

            r = await client.call_tool("list_files", {
                "database": "coursethread",
                "bucket": "sme-candidates",
            })
            files = json.loads(r.content[0].text)
            assert "cand-001.json" not in files

        self._run_mcp_test(test_env, test)

    def test_delete_bucket_via_mcp(self, test_env):
        async def test(client):
            await client.call_tool("create_database", {"database": "mydb"})
            await client.call_tool("create_bucket", {"database": "mydb", "bucket": "mybucket"})
            await client.call_tool("put_file", {
                "database": "mydb", "bucket": "mybucket",
                "filename": "test.json", "content": {"k": "v"},
            })
            r = await client.call_tool("delete_bucket", {
                "database": "mydb", "bucket": "mybucket",
            })
            assert "Deleted bucket" in r.content[0].text

        self._run_mcp_test(test_env, test)

    def test_error_handling_via_mcp(self, test_env):
        async def test(client):
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
