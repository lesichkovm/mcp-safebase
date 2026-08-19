"""Quick smoke test for SafeBase server logic (no MCP transport).

Tests the core encryption, file I/O, query logic, and the per-bucket password
system directly. The dialog functions are mocked to inject canned passwords
so this runs headless without tkinter.

Run: python test_smoke.py
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

_test_root = Path(tempfile.mkdtemp(prefix="safebase-test-"))
os.environ["SAFEBASE_ROOT"] = str(_test_root)
os.environ.pop("SAFEBASE_PASSWORD", None)  # ensure no leftover env var

sys.path.insert(0, str(Path(__file__).parent))
import server


# --- Mock the dialog functions so this runs headless ---

def make_dialog(password, duration=5):
    def _mock(database, bucket):
        return server.DialogResult(password=password, duration_minutes=duration)
    return _mock

def cancel_dialog():
    def _mock(database, bucket):
        return None
    return _mock

server._prompt_create_password_fn = make_dialog("smoke-pass-123")
server._prompt_enter_password_fn = make_dialog("smoke-pass-123")
server._prompt_change_password_fn = make_dialog("new-smoke-pass-456")


def test_full_workflow():
    print("=== SafeBase Smoke Test ===\n")

    # 1. Create database
    result = server._create_database("coursethread")
    print(f"create_database: {result}")
    assert "Created" in result

    # 2. List databases
    dbs = server._list_databases()
    print(f"list_databases: {dbs}")
    assert "coursethread" in dbs

    # 3. Create bucket
    result = server._create_bucket("coursethread", "sme-candidates")
    print(f"create_bucket: {result}")
    assert "Created" in result

    # 4. List buckets
    buckets = server._list_buckets("coursethread")
    print(f"list_buckets: {buckets}")
    assert "sme-candidates" in buckets

    # 5. Put a file (this triggers the create-password dialog mock)
    result = server._put_file("coursethread", "sme-candidates", "cand-001.json", {
        "name": "Jane Smith",
        "email": "jane@example.com",
        "domain": "Cybersecurity",
        "per_course_price_usd": 50,
        "vetting_status": "applied",
        "linkedin_url": "https://linkedin.com/in/janesmith",
        "fact_check_approach": "I verify claims against peer-reviewed sources."
    })
    print(f"put_file: {result}")
    assert "Wrote" in result

    # 6. Put another file
    result = server._put_file("coursethread", "sme-candidates", "cand-002.json", {
        "name": "Bob Jones",
        "email": "bob@example.com",
        "domain": "Data & Analytics",
        "per_course_price_usd": 40,
        "vetting_status": "applied",
        "linkedin_url": "https://linkedin.com/in/bobjones",
        "fact_check_approach": "I cross-reference with textbooks and recent papers."
    })
    print(f"put_file (2): {result}")
    assert "Wrote" in result

    # 7. List files
    files = server._list_files("coursethread", "sme-candidates")
    print(f"list_files: {files}")
    assert "cand-001.json" in files
    assert "cand-002.json" in files
    # Metadata file should NOT appear
    assert ".safebase-meta.json" not in files

    # 8. Get a file
    data = server._get_file("coursethread", "sme-candidates", "cand-001.json")
    print(f"get_file: name={data['name']}, status={data['vetting_status']}")
    assert data["name"] == "Jane Smith"
    assert data["vetting_status"] == "applied"

    # 9. Verify file on disk is encrypted (not plaintext)
    root = server._get_root()
    enc_path = root / "coursethread" / "sme-candidates" / "cand-001.json.enc"
    raw_bytes = enc_path.read_bytes()
    assert b"Jane Smith" not in raw_bytes, "File on disk contains plaintext!"
    assert b"jane@example.com" not in raw_bytes, "File on disk contains plaintext!"
    print(f"Encryption check: PASS (file is ciphertext, {len(raw_bytes)} bytes)")

    # 9b. Verify metadata file exists and contains no plaintext password
    meta_path = root / "coursethread" / "sme-candidates" / ".safebase-meta.json"
    assert meta_path.exists(), "Metadata file not created!"
    meta_text = meta_path.read_text()
    assert "smoke-pass-123" not in meta_text, "Plaintext password in metadata!"
    print("Metadata check: PASS (bcrypt hash + salt, no plaintext password)")

    # 10. Query bucket (no filter)
    items = server._query_bucket("coursethread", "sme-candidates")
    print(f"query_bucket (no filter): {len(items)} items")
    assert len(items) == 2

    # 11. Query bucket (with filter)
    items = server._query_bucket("coursethread", "sme-candidates", {"vetting_status": "applied"})
    print(f"query_bucket (filter=applied): {len(items)} items")
    assert len(items) == 2

    # 12. Update a file (overwrite)
    result = server._put_file("coursethread", "sme-candidates", "cand-001.json", {
        "name": "Jane Smith",
        "email": "jane@example.com",
        "domain": "Cybersecurity",
        "per_course_price_usd": 50,
        "vetting_status": "md_reviewed",
        "linkedin_url": "https://linkedin.com/in/janesmith",
        "fact_check_approach": "I verify claims against peer-reviewed sources.",
        "vetting_notes": "Credentials verified. Domain fit confirmed."
    })
    print(f"put_file (update): {result}")

    # 13. Verify update
    data = server._get_file("coursethread", "sme-candidates", "cand-001.json")
    assert data["vetting_status"] == "md_reviewed"
    assert data["vetting_notes"] == "Credentials verified. Domain fit confirmed."
    print(f"Update check: PASS (vetting_status={data['vetting_status']})")

    # 14. Query with filter for updated status
    items = server._query_bucket("coursethread", "sme-candidates", {"vetting_status": "md_reviewed"})
    print(f"query_bucket (filter=md_reviewed): {len(items)} items")
    assert len(items) == 1
    assert items[0]["filename"] == "cand-001.json"

    # 15. Delete a file
    result = server._delete_file("coursethread", "sme-candidates", "cand-002.json")
    print(f"delete_file: {result}")
    assert "Deleted" in result

    # 16. Verify deletion
    files = server._list_files("coursethread", "sme-candidates")
    assert "cand-002.json" not in files
    assert "cand-001.json" in files
    print(f"Delete check: PASS (cand-002 gone, cand-001 remains)")

    # 17. Test a second bucket (different schema, different password)
    server._prompt_create_password_fn = make_dialog("tender-pass-456")
    result = server._create_bucket("coursethread", "tender-leads")
    print(f"\ncreate_bucket (tender-leads): {result}")

    result = server._put_file("coursethread", "tender-leads", "t-001.json", {
        "title": "NHS Digital Training Framework",
        "deadline": "2026-09-15",
        "value_gbp": 50000,
        "status": "monitoring"
    })
    print(f"put_file (tender): {result}")

    # Clear cache so query re-prompts with the tender password
    server._key_cache.clear()
    server._prompt_enter_password_fn = make_dialog("tender-pass-456")
    items = server._query_bucket("coursethread", "tender-leads", {"status": "monitoring"})
    print(f"query_bucket (tender, filter=monitoring): {len(items)} items")
    assert len(items) == 1
    assert items[0]["title"] == "NHS Digital Training Framework"

    # 18. Test name validation (path traversal protection)
    try:
        server._create_database("../escape")
        assert False, "Should have rejected path traversal"
    except ValueError as e:
        print(f"\nValidation check: PASS (rejected '../escape': {e})")

    try:
        server._create_database(".hidden")
        assert False, "Should have rejected dot prefix"
    except ValueError as e:
        print(f"Validation check: PASS (rejected '.hidden': {e})")

    # 19. Test idempotent operations
    result = server._create_database("coursethread")
    print(f"\nIdempotent create_database: {result}")
    assert "already exists" in result

    result = server._create_bucket("coursethread", "sme-candidates")
    print(f"Idempotent create_bucket: {result}")
    assert "already exists" in result

    # 20. Test error: get nonexistent file
    result = server._get_file("coursethread", "sme-candidates", "nonexistent.json")
    print(f"Get nonexistent: {result}")
    assert "does not exist" in result

    # 21. Test error: list nonexistent bucket
    result = server._list_files("coursethread", "nonexistent")
    print(f"List nonexistent bucket: {result}")
    assert "does not exist" in result

    # 22. Test access denied (cancel dialog)
    server._key_cache.clear()
    server._prompt_enter_password_fn = cancel_dialog()
    result = server._get_file("coursethread", "sme-candidates", "cand-001.json")
    print(f"Access denied (cancel): {result}")
    assert "Access denied" in result
    # Restore the dialog mock
    server._prompt_enter_password_fn = make_dialog("smoke-pass-123")

    # 23. Test wrong password
    server._key_cache.clear()
    server._prompt_enter_password_fn = make_dialog("wrong-password")
    result = server._get_file("coursethread", "sme-candidates", "cand-001.json")
    print(f"Wrong password: {result}")
    assert "Access denied" in result
    server._prompt_enter_password_fn = make_dialog("smoke-pass-123")

    # 24. Test change_bucket_password
    server._key_cache.clear()
    server._prompt_enter_password_fn = make_dialog("smoke-pass-123")
    server._prompt_change_password_fn = make_dialog("new-smoke-pass-456")
    result = server._change_bucket_password("coursethread", "sme-candidates")
    print(f"change_bucket_password: {result}")
    assert "Password changed" in result

    # Verify we can read with the new password
    server._key_cache.clear()
    server._prompt_enter_password_fn = make_dialog("new-smoke-pass-456")
    data = server._get_file("coursethread", "sme-candidates", "cand-001.json")
    assert data["name"] == "Jane Smith"
    print("Password change check: PASS (files decrypt with new password)")

    # 25. Test delete_bucket
    result = server._delete_bucket("coursethread", "tender-leads")
    print(f"delete_bucket: {result}")
    assert "Deleted bucket" in result
    assert not (root / "coursethread" / "tender-leads").exists()
    print("Delete bucket check: PASS")

    # 26. Verify git history was created
    import subprocess
    git_log = subprocess.run(
        ["git", "log", "--oneline"],
        cwd=str(_test_root),
        capture_output=True,
        text=True,
    )
    print(f"\nGit log:\n{git_log.stdout}")
    assert git_log.returncode == 0, "git log failed"
    assert "put:" in git_log.stdout, "No put commits in git log"
    assert "delete:" in git_log.stdout, "No delete commits in git log"
    assert "create database:" in git_log.stdout, "No create database commits in git log"
    assert "create bucket:" in git_log.stdout, "No create bucket commits in git log"
    assert "delete bucket:" in git_log.stdout, "No delete bucket commits in git log"
    assert "change password:" in git_log.stdout, "No change password commits in git log"
    print("Git history check: PASS")

    # 27. Verify git history contains only ciphertext (no plaintext in diffs)
    git_diff = subprocess.run(
        ["git", "log", "-p", "--all"],
        cwd=str(_test_root),
        capture_output=True,
        text=True,
    )
    assert "Jane Smith" not in git_diff.stdout, "Plaintext 'Jane Smith' found in git history!"
    assert "jane@example.com" not in git_diff.stdout, "Plaintext email found in git history!"
    assert "smoke-pass-123" not in git_diff.stdout, "Plaintext password found in git history!"
    print("Git history encryption check: PASS (no plaintext in diffs)")

    print("\n=== ALL TESTS PASSED ===")


if __name__ == "__main__":
    try:
        test_full_workflow()
    finally:
        shutil.rmtree(_test_root, ignore_errors=True)
        print(f"\nCleaned up test root: {_test_root}")
