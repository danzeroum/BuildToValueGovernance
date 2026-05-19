"""Security primitives — HMAC keys, secrets handling.

Single source of truth for cryptographic material across the Python codebase.
See ADR-0005 (HMAC integrity), ADR-0011 (policy engine), ADR-0028 (verdict signing).
"""

from buildtovalue.security.keys import (
    HmacKeyUnsetError,
    InsecureHmacKeyError,
    get_hmac_key,
)

__all__ = ["get_hmac_key", "HmacKeyUnsetError", "InsecureHmacKeyError"]
