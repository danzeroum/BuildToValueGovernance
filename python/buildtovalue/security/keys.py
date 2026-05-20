"""Centralized HMAC key resolution — single source of truth.

Replaces five divergent hardcoded keys previously scattered across
``api/app.py``, ``api/routes/agent_decide.py``, ``governance/contestability_loop.py``,
``governance/policy_engine.py`` (and the Rust kernel). Cross-module HMAC
verification was silently broken because each site used a different literal.

# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN 1 — get_hmac_key(): HMAC-SHA256 for OUTPUT authenticity
#   Use cases:
#     - TechnicalEvidence signing (rust/kernel/src/gatekeeper.rs)
#     - Verdict integrity (governance/contestability_loop.py)
#     - PolicyEvalResult self-signing (governance/policy_engine.py)
#   Threat model: detect tampering of decisions emitted by BTV.
#
# DOMAIN 2 — Ed25519 public key: INPUT origin verification (ADR-064)
#   Use cases:
#     - Policy YAML signature verification at _load_policies()
#   Threat model: ensure loaded policies originate from an authorized signer.
#   DO NOT reuse get_hmac_key() for policy verification. See policy_loader.py.
# ─────────────────────────────────────────────────────────────────────────────

Lifecycle:
    - ``init_hmac_key()`` is called once at process startup, BEFORE any
      pre-fork worker (FastAPI lifespan, Gunicorn ``post_fork`` is too late).
    - ``BTV_HMAC_KEY`` is removed from ``os.environ`` immediately after
      consumption (defense in depth vs ``/proc/self/environ`` leaks).
    - The key lives in a mutable ``bytearray`` inside ``_KeyHolder`` so the
      buffer can be zeroized in place on rotation or shutdown. Using
      ``functools.lru_cache`` here is unsafe — the cache pins an immutable
      ``bytes`` object that cannot be wiped.

Generate a real key with: ``python -c "import secrets; print(secrets.token_hex(32))"``
"""

from __future__ import annotations

import ctypes
import logging
import os
from typing import Optional

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


class HmacKeyNotInitializedError(RuntimeError):
    """Raised when get_hmac_key() is called before init_hmac_key()."""


def _is_insecure(key: str) -> bool:
    return any(marker in key for marker in _INSECURE_MARKERS)


class _KeyHolder:
    """Holds the HMAC key in a mutable buffer that can be zeroized in place.

    Using a ``bytearray`` (not ``bytes``) is intentional: ``bytes`` objects
    are immutable and Python may intern short literals into pools that
    survive scope, making true zeroization impossible.
    """

    __slots__ = ("_buf",)

    def __init__(self, buf: bytearray) -> None:
        self._buf = buf

    def borrow(self) -> bytes:
        """Return an immutable view for HMAC consumption.

        Note: ``bytes(self._buf)`` copies the bytes. Callers should not
        retain the returned value beyond a single hashing operation.
        """
        return bytes(self._buf)

    def zeroize(self) -> None:
        n = len(self._buf)
        if n:
            ctypes.memset(
                (ctypes.c_char * n).from_buffer(self._buf), 0, n
            )
        self._buf = bytearray(0)


_KEY_HOLDER: Optional[_KeyHolder] = None


def _resolve_key_as_bytearray() -> bytearray:
    """Read env, apply fail-closed rules, return mutable buffer."""
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
        return bytearray(raw, "utf-8")

    if raw:
        return bytearray(raw, "utf-8")

    logger.warning(
        "BTV_HMAC_KEY not set; using insecure dev fallback. "
        "Set BTV_HMAC_KEY before deploying."
    )
    return bytearray(_DEV_FALLBACK)


def init_hmac_key() -> None:
    """Initialize the HMAC key singleton.

    Call exactly once during process startup, BEFORE any worker fork
    (FastAPI ``lifespan`` is the canonical hook). After init, the raw
    ``BTV_HMAC_KEY`` is removed from the environment.

    Calling twice replaces the holder after zeroizing the previous one —
    useful for SIGHUP-driven rotation after ``fly secrets set``.
    """
    global _KEY_HOLDER
    new_buf = _resolve_key_as_bytearray()
    old = _KEY_HOLDER
    _KEY_HOLDER = _KeyHolder(new_buf)
    if old is not None:
        old.zeroize()
    # Defense in depth: scrub the env var so /proc/self/environ does not
    # leak the key to other processes in the same namespace.
    os.environ.pop("BTV_HMAC_KEY", None)


def get_hmac_key() -> bytes:
    """Return the HMAC key. Requires prior init_hmac_key().

    Returned value is a fresh ``bytes`` copy; do not retain it across
    rotation events. For finer control (single-use buffer), see roadmap
    item in docs/status.md for the context-manager API.
    """
    if _KEY_HOLDER is None:
        # Lazy init for legacy call sites (tests, single-shot scripts).
        # Production code should always call init_hmac_key() at startup.
        init_hmac_key()
    if _KEY_HOLDER is None:
        # init_hmac_key() failed to populate the global (would only happen
        # under a patched-out init in tests). Raise explicitly so the
        # error survives PYTHONOPTIMIZE=1, which strips `assert`.
        raise HmacKeyNotInitializedError(
            "get_hmac_key() called before init_hmac_key() succeeded. "
            "Ensure init_hmac_key() runs in the FastAPI lifespan."
        )
    return _KEY_HOLDER.borrow()


def rotate_hmac_key() -> None:
    """SIGHUP / control-plane hook to re-read BTV_HMAC_KEY after rotation.

    Caller is responsible for ensuring the new key has been written to the
    process environment before this is invoked (e.g. via ``fly deploy``
    with new secrets or systemd ``EnvironmentFile`` reload).
    """
    init_hmac_key()


def _zeroize_for_tests() -> None:
    """Test-only helper: clear the holder so the next init reads fresh env."""
    global _KEY_HOLDER
    if _KEY_HOLDER is not None:
        _KEY_HOLDER.zeroize()
        _KEY_HOLDER = None
