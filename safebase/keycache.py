"""In-memory Fernet key cache with idle timeout.

Keys are cached per bucket so the human is not re-prompted on every operation.
Each entry has an expiry timestamp; `0` duration means process lifetime.
The cache dict is module-level so it is shared across all callers in the
process; tests clear it between runs.
"""

import time
from dataclasses import dataclass
from typing import Optional

from cryptography.fernet import Fernet


@dataclass
class _CachedKey:
    fernet: Fernet
    expires_at: float       # unix timestamp; float("inf") for process lifetime
    duration_minutes: int   # original duration, for resetting the idle timer


_key_cache: dict[str, _CachedKey] = {}
# key: f"{database}/{bucket}"


def _cache_key(database: str, bucket: str) -> str:
    return f"{database}/{bucket}"


def _get_cached_key(database: str, bucket: str) -> Optional[Fernet]:
    """Return a cached Fernet if present and not expired, else None."""
    ck = _key_cache.get(_cache_key(database, bucket))
    if ck is None:
        return None
    if ck.expires_at != float("inf") and time.time() > ck.expires_at:
        _key_cache.pop(_cache_key(database, bucket), None)
        return None
    return ck.fernet


def _store_cached_key(database: str, bucket: str, fernet: Fernet, duration_minutes: int) -> None:
    """Store a Fernet key in the cache with the given idle timeout.

    Negative or non-integer durations are clamped to 0 (process lifetime)
    to prevent immediate expiry from a misbehaving dialog implementation.
    """
    if not isinstance(duration_minutes, int) or duration_minutes < 0:
        duration_minutes = 0
    if duration_minutes == 0:
        expires_at = float("inf")  # process lifetime
    else:
        expires_at = time.time() + (duration_minutes * 60)
    _key_cache[_cache_key(database, bucket)] = _CachedKey(
        fernet=fernet, expires_at=expires_at, duration_minutes=duration_minutes
    )


def _touch_cached_key(database: str, bucket: str) -> None:
    """Reset the idle timer for a cached key (called on each use)."""
    ck = _key_cache.get(_cache_key(database, bucket))
    if ck is None or ck.duration_minutes == 0:
        return
    ck.expires_at = time.time() + (ck.duration_minutes * 60)


def _clear_cached_key(database: str, bucket: str) -> None:
    """Remove a bucket's key from the cache (e.g. on password change or delete)."""
    _key_cache.pop(_cache_key(database, bucket), None)
