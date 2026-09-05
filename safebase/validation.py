"""Name and filename validation for SafeBase paths.

Pure functions with no I/O — safe to import from anywhere.
"""

import re

_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")


def _validate_name(name: str, label: str) -> str:
    if not name:
        raise ValueError(f"{label} cannot be empty")
    if not _NAME_PATTERN.match(name):
        raise ValueError(
            f"{label} '{name}' is invalid: must start with alphanumeric "
            f"and contain only alphanumeric, hyphen, or underscore"
        )
    return name


def _validate_filename(filename: str) -> str:
    if not filename:
        raise ValueError("filename cannot be empty")
    if not filename.endswith(".json"):
        raise ValueError(f"filename '{filename}' must end with .json")
    base = filename[:-5]
    if not _NAME_PATTERN.match(base):
        raise ValueError(
            f"filename '{filename}' is invalid: the part before .json "
            f"must start with alphanumeric and contain only alphanumeric, "
            f"hyphen, or underscore"
        )
    return filename
