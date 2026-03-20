"""
Exponential backoff retry utility for httpx requests.
"""
from __future__ import annotations

import time
from typing import Callable, TypeVar

import httpx

from .exceptions import BTVGatewayError, BTVRateLimitError

T = TypeVar("T")

# Status codes that warrant a retry
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def retry_sync(
    fn: Callable[[], httpx.Response],
    max_retries: int = 3,
    base_delay: float = 2.0,
) -> httpx.Response:
    """
    Call fn() with exponential backoff on network errors and 5xx/429 responses.
    Delays: 2s, 4s, 8s (by default).
    """
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            resp = fn()
            if resp.status_code not in _RETRYABLE_STATUS:
                return resp
            # Retryable HTTP status
            if attempt == max_retries:
                if resp.status_code == 429:
                    retry_after = _parse_retry_after(resp)
                    raise BTVRateLimitError(retry_after)
                raise BTVGatewayError(resp.status_code, resp.text[:200])
            delay = base_delay * (2 ** attempt)
            time.sleep(delay)
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            last_exc = exc
            if attempt == max_retries:
                raise BTVGatewayError(0, str(exc)) from exc
            delay = base_delay * (2 ** attempt)
            time.sleep(delay)

    # Should be unreachable
    raise BTVGatewayError(0, str(last_exc))


async def retry_async(
    fn: Callable[[], "Awaitable[httpx.Response]"],
    max_retries: int = 3,
    base_delay: float = 2.0,
) -> httpx.Response:
    """Async version of retry_sync."""
    import asyncio

    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            resp = await fn()
            if resp.status_code not in _RETRYABLE_STATUS:
                return resp
            if attempt == max_retries:
                if resp.status_code == 429:
                    retry_after = _parse_retry_after(resp)
                    raise BTVRateLimitError(retry_after)
                raise BTVGatewayError(resp.status_code, resp.text[:200])
            delay = base_delay * (2 ** attempt)
            await asyncio.sleep(delay)
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            last_exc = exc
            if attempt == max_retries:
                raise BTVGatewayError(0, str(exc)) from exc
            delay = base_delay * (2 ** attempt)
            await asyncio.sleep(delay)

    raise BTVGatewayError(0, str(last_exc))


def _parse_retry_after(resp: httpx.Response) -> int | None:
    val = resp.headers.get("Retry-After")
    if val and val.isdigit():
        return int(val)
    return None
