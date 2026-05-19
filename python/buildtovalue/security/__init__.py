"""Security primitives — HMAC keys, secrets handling.

Single source of truth for cryptographic material across the Python codebase.
See ADR-0005 (HMAC integrity), ADR-0011 (policy engine), ADR-0028 (verdict signing).

Usage rules:
    - Only HMAC-domain callers should import ``get_hmac_key``. For policy YAML
      origin verification (Ed25519), use ``governance.policy_loader`` (ADR-064).
    - ``init_hmac_key()`` must be called once at process startup (FastAPI
      ``lifespan``), BEFORE any pre-fork worker. Lazy init exists as a fallback
      for tests/scripts but emits a warning in production.
    - On SIGHUP after credential rotation (e.g. ``fly secrets set``), call
      ``rotate_hmac_key()`` to refresh the holder and zeroize the old buffer.
"""

from buildtovalue.security.keys import (
    HmacKeyNotInitializedError,
    HmacKeyUnsetError,
    InsecureHmacKeyError,
    get_hmac_key,
    init_hmac_key,
    rotate_hmac_key,
)

__all__ = [
    "get_hmac_key",
    "init_hmac_key",
    "rotate_hmac_key",
    "HmacKeyUnsetError",
    "InsecureHmacKeyError",
    "HmacKeyNotInitializedError",
]
