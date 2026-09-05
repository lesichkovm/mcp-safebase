"""Git auto-commit helpers for SafeBase history/reversion.

The storage root is auto-initialized as a git repo. All files are `.enc`
ciphertext, so git history never contains plaintext.
"""

import subprocess
from pathlib import Path


def _git_init(root: Path) -> None:
    """Initialize a git repo at root if not already one. Idempotent."""
    git_dir = root / ".git"
    if git_dir.exists():
        return
    subprocess.run(
        ["git", "init"],
        cwd=str(root),
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "SafeBase MCP"],
        cwd=str(root),
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "safebase@local"],
        cwd=str(root),
        capture_output=True,
        check=True,
    )


def _git_commit(root: Path, message: str) -> None:
    """Stage all changes and commit. No-op if there are no changes."""
    _git_init(root)
    subprocess.run(
        ["git", "add", "-A"],
        cwd=str(root),
        capture_output=True,
        check=True,
    )
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=str(root),
        capture_output=True,
    )
    if result.returncode == 0:
        return
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=str(root),
        capture_output=True,
        check=True,
    )
