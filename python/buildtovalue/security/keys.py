"""Centralized HMAC key resolution — single source of truth.

Replaces five divergent hardcoded keys previously scattered across
``api/app.py``, ``api/routes/agent_decide.py``, ``governance/contestability_loop.py``,
``governance/policy_engine.py`` (and the Rust kernel). Cross-module HMAC
verification was silently broken because each site used a different literal.

Behavior:
    - ``BTV_HMAC_KEY`` env var is the only legitimate source.
    - In ``BTV_ENV=production``, raises if unset or matches a known dev
      sentinel — fail-closed by construction.
    - In dev, returns the env value or a clearly-marked dev fallback with a
      warning log.

Generate a real key with: ``python -c "import secrets; print(secrets.token_hex(32))"``
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache

logger = logging.getLogger(__name__)

_DEV_FALLBACK = b"btv-dev-key-NOT-FOR-PRODUCTION!!"

_INSECURE_MARKERS = (
    "NOT-FOR-PRODUCTION",
    "demo-key",
    "btv-dev-key",
    "btv-policy-engine-v1",
    "btv-verdict-hmac-v1",
    "btv-kernel-supply-guard",
)


class HmacKeyUnsetError(RuntimeError):
    """Raised in production when BTV_HMAC_KEY is missing."""


class InsecureHmacKeyError(RuntimeError):
    """Raised in production when BTV_HMAC_KEY matches a known dev sentinel."""


def _is_insecure(key: str) -> bool:
    return any(marker in key for marker in _INSECURE_MARKERS)


@lru_cache(maxsize=1)
def get_hmac_key() -> bytes:
    """Return the HMAC key from env. Fail-closed in production."""
    env = os.environ.get("BTV_ENV", "development").lower()
    raw = os.environ.get("BTV_HMAC_KEY")

    if env == "production":
        if not raw:
            raise HmacKeyUnsetError(
                "BTV_HMAC_KEY must be set in production. "
                "Generate one with: "
                'python -c "import secrets; print(secrets.token_hex(32))"'
            )
        if _is_insecure(raw):
            raise InsecureHmacKeyError(
                "BTV_HMAC_KEY contains a development sentinel and is unsafe "
                "for production use. Rotate to a freshly generated 32-byte key."
            )
        return raw.encode("utf-8")

    if raw:
        return raw.encode("utf-8")

    logger.warning(
        "BTV_HMAC_KEY not set; using insecure dev fallback. "
        "Set BTV_HMAC_KEY before deploying."
    )
    return _DEV_FALLBACK
