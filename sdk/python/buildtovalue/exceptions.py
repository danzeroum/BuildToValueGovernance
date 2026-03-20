"""
Exceptions raised by the BTVClient.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Verdict, ValidateVerdict


class BTVError(Exception):
    """Base exception for all BTV SDK errors."""


class BTVAuthError(BTVError):
    """API key missing or invalid (HTTP 401)."""


class BTVBlockedError(BTVError):
    """
    Raised when a verdict action is BLOCK and raise_on_block=True.

    Attributes:
        verdict: The full Verdict object that triggered the block.
    """

    def __init__(self, verdict: "Verdict | ValidateVerdict") -> None:
        self.verdict = verdict
        super().__init__(
            f"Input blocked by BTV governance. "
            f"verdict_id={verdict.verdict_id} "
            f"contestable={verdict.contestable}"
        )


class BTVRateLimitError(BTVError):
    """Rate limit exceeded (HTTP 429)."""

    def __init__(self, retry_after: int | None = None) -> None:
        self.retry_after = retry_after
        msg = "BTV rate limit exceeded"
        if retry_after:
            msg += f" — retry after {retry_after}s"
        super().__init__(msg)


class BTVGatewayError(BTVError):
    """Gateway returned an unexpected error (HTTP 5xx)."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = status_code
        super().__init__(f"BTV gateway error {status_code}: {detail}")


class BTVValidationError(BTVError):
    """Request was rejected by the gateway (HTTP 4xx, not 401/429)."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = status_code
        super().__init__(f"BTV validation error {status_code}: {detail}")


class BTVAppealError(BTVError):
    """Appeal submission or retrieval failed."""
