"""SafeBase configuration constants.

Centralizes tunable parameters so the rest of the package does not hard-code
magic numbers. Kept dependency-free so any module can import it without risk
of cycles.
"""

_PBKDF2_ITERATIONS = 600_000  # OWASP-recommended minimum for PBKDF2-SHA256
_META_FILENAME = ".safebase-meta.json"
_META_VERSION = 1

# Session duration options in minutes. 0 means process lifetime (no timeout).
_DURATION_OPTIONS = (1, 5, 10, 15, 0)
_DEFAULT_DURATION = 1  # preselected in the dialog — most operations finish quickly
