"""
BuildToValue Grant Decision Adapter — Public API

Exports the primary surface for external consumers (e.g. Gitcoin Round Manager,
community grant portals) that need to route grant proposals through the
BTV ethical governance kernel.

Usage::

    from btv_grants import GrantDecisionAdapter, GrantProposal, GrantCategory
    from btv_grants.exceptions import GrantBlockedError

    adapter = GrantDecisionAdapter(gateway_url="https://btv.example.com")
    proposal = GrantProposal(
        applicant_id="0xabc123",
        title="Open Source Toolkit",
        description="...",
        category=GrantCategory.PUBLIC_GOODS,
        budget_usd=75_000,
    )
    try:
        verdict = adapter.evaluate(proposal)
        print(f"Approved: {verdict.verdict_id}")
    except GrantBlockedError as e:
        print(f"Blocked: {e.rationale} | Contestable: {e.contestable}")
"""

from .adapter import GrantDecisionAdapter
from .exceptions import GrantBlockedError, GrantValidationError
from .models import (
    BiasDeclaration,
    GrantCategory,
    GrantProposal,
    GrantVerdict,
    LinguisticGroup,
)

__all__ = [
    "GrantDecisionAdapter",
    "GrantBlockedError",
    "GrantValidationError",
    "BiasDeclaration",
    "GrantCategory",
    "GrantProposal",
    "GrantVerdict",
    "LinguisticGroup",
]

__version__ = "1.0.0"
