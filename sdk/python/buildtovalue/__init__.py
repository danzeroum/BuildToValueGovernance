"""
BuildToValue Python SDK — ethical AI governance in 5 minutes.

Quick start:
    pip install buildtovalue

    from buildtovalue import BTVClient

    btv = BTVClient(api_key="your-key", gateway_url="http://localhost:8080")
    verdict = btv.decide("Meu CPF é 123.456.789-09", session_id="sess-001", profile="healthcare")

    if verdict.action == "BLOCK":
        print(verdict.explanation)
        appeal = btv.appeal(
            verdict.verdict_id,
            reason="CPF de teste ABNT — não é dado real",
            grounds=["technical_error", "false_positive"],
        )
"""

from .client import AsyncBTVClient, AsyncBTVSession, BTVClient, BTVSession
from .exceptions import (
    BTVAppealError,
    BTVAuthError,
    BTVBlockedError,
    BTVError,
    BTVGatewayError,
    BTVRateLimitError,
    BTVValidationError,
)
from .models import (
    Appeal,
    AppealGrounds,
    AppealStatus,
    DriftLevel,
    ExplainDecision,
    SanitizeResult,
    TrustScore,
    ValidateVerdict,
    Verdict,
    VerdictAction,
)

__version__ = "0.1.0"

__all__ = [
    # Clients
    "BTVClient",
    "BTVSession",
    "AsyncBTVClient",
    "AsyncBTVSession",
    # Exceptions
    "BTVError",
    "BTVAuthError",
    "BTVBlockedError",
    "BTVRateLimitError",
    "BTVGatewayError",
    "BTVValidationError",
    "BTVAppealError",
    # Models
    "Verdict",
    "ValidateVerdict",
    "ExplainDecision",
    "Appeal",
    "TrustScore",
    "SanitizeResult",
    "VerdictAction",
    "AppealStatus",
    "AppealGrounds",
    "DriftLevel",
]
