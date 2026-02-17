"""
API Key Authentication — Gap #6.
FastAPI dependency for X-API-Key validation.
"""

import os
import logging
from typing import Optional, Set
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_valid_keys: Optional[Set[str]] = None
_auth_enabled: bool = False


def init_auth():
    """Load API keys from BTV_API_KEYS env var."""
    global _valid_keys, _auth_enabled

    raw = os.environ.get("BTV_API_KEYS", "")
    keys = {k.strip() for k in raw.split(",") if k.strip()}

    if not keys:
        env = os.environ.get("BTV_ENV", "development")
        if env == "production":
            raise RuntimeError("BTV_API_KEYS must be set in production")
        logger.warning("⚠️  BTV_API_KEYS not set — auth disabled (dev)")
        _auth_enabled = False
        return

    _valid_keys = keys
    _auth_enabled = True
    logger.info(f"API key auth enabled: {len(keys)} keys loaded")


async def require_api_key(api_key: str = Security(_api_key_header)):
    """FastAPI dependency — validates X-API-Key header."""
    if not _auth_enabled:
        return

    if not api_key or api_key not in _valid_keys:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "UNAUTHORIZED",
                "message": "Invalid or missing API key.",
            },
        )