"""Central crypto gate: obtain a Fernet key for a bucket.

`_get_bucket_key` is the single chokepoint through which all crypto operations
pass. It checks the in-memory key cache, prompts the human (via the dialog
functions on the `server` facade) if needed, derives the Fernet key, caches it,
and returns it.

The dialog function references live on the `server` facade as mutable globals
(`server._prompt_create_password_fn`, `server._prompt_enter_password_fn`) so
tests can monkeypatch them. This module reads them lazily via `import server`
at call time — that retrieves the (possibly freshly re-imported) facade from
`sys.modules` and sees the patched values. The lazy import also breaks what
would otherwise be a circular import (server imports core imports access).
"""

import base64

from cryptography.fernet import Fernet

from safebase.crypto import _derive_fernet_key
from safebase.keycache import (
    _get_cached_key,
    _store_cached_key,
    _touch_cached_key,
)
from safebase.meta import _load_bucket_meta, _store_bucket_meta, _verify_password
from safebase.paths import _bucket_path, _get_root


class AccessDenied(Exception):
    """Raised when the human cancels the password dialog."""


_MAX_PASSWORD_ATTEMPTS = 3


def _get_bucket_key(database: str, bucket: str) -> Fernet:
    """Return a Fernet for the bucket, prompting the human if needed.

    This is the single gate through which all crypto operations pass. It:
    1. Checks the in-memory key cache — returns immediately if valid.
    2. If no key cached, checks for bucket metadata:
       a. No metadata (or corrupted) → first use → show create-password dialog.
       b. Metadata exists → show enter-password dialog, verify against bcrypt.
          Allows up to _MAX_PASSWORD_ATTEMPTS retries on wrong password.
    3. Derives the Fernet key from the raw password + stored salt.
    4. Caches the key with the human-chosen duration.
    5. Returns the Fernet.

    Raises AccessDenied if the human cancels the dialog or exceeds the
    maximum number of wrong-password attempts.
    """
    # 1. Check cache
    cached = _get_cached_key(database, bucket)
    if cached is not None:
        _touch_cached_key(database, bucket)
        return cached

    root = _get_root()
    bp = _bucket_path(root, database, bucket)
    if not bp.exists():
        raise RuntimeError(f"Bucket '{database}/{bucket}' does not exist")

    # Lazy import: the facade holds the (possibly monkeypatched) dialog fns.
    import server as _facade

    # 2a. First use — no metadata (or corrupted metadata) → create password
    meta = _load_bucket_meta(bp)
    if meta is None:
        result = _facade._prompt_create_password_fn(database, bucket)
        if result is None or result.password is None:
            raise AccessDenied("User cancelled password creation")
        meta = _store_bucket_meta(bp, result.password)
    else:
        # 2b. Subsequent use — verify against stored bcrypt hash
        #     Allow retries on wrong password (up to _MAX_PASSWORD_ATTEMPTS).
        result = None
        for attempt in range(_MAX_PASSWORD_ATTEMPTS):
            result = _facade._prompt_enter_password_fn(database, bucket)
            if result is None or result.password is None:
                raise AccessDenied("User cancelled password entry")
            if _verify_password(result.password, meta.bcrypt_hash):
                break
            if attempt < _MAX_PASSWORD_ATTEMPTS - 1:
                # Re-prompt — the dialog implementation is responsible for
                # showing an error message. Here we just loop.
                continue
            raise AccessDenied("Incorrect password (max attempts exceeded)")
        # result is guaranteed to be set and verified here

    # 3. Derive Fernet key
    salt = base64.b64decode(meta.pbkdf2_salt)
    fernet = Fernet(_derive_fernet_key(result.password, salt))

    # 4. Cache
    _store_cached_key(database, bucket, fernet, result.duration_minutes)

    return fernet
