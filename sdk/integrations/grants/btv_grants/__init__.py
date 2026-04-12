"""
btv_grants — BTV Grant Decision Adapter

Public API for the BuildToValue Grant governance integration.
Provides GrantGuard, domain models, and exceptions for evaluating
grant proposals through the BTV ethical governance pipeline.

Usage:
    from buildtovalue import BTVClient
    from btv_grants import GrantGuard, GrantProposal, GrantCategory
    from btv_grants import GrantBlockedError

    client = BTVClient(api_key="...")
    guard = GrantGuard(client)

    proposal = GrantProposal(
        applicant_id="0xabc...123",
        title="Decentralized Water Quality Monitoring",
        description="We will deploy IoT sensors in Amazonian communities...",
        category=GrantCategory.PUBLIC_GOODS,
        budget_usd=50_000,
        linguistic_group=LinguisticGroup.PT_BR,
    )

    try:
        verdict = guard.evaluate(proposal)
        print(f"ALLOWED — risk: {verdict.composite_risk}")
    except GrantBlockedError as e:
        print(f"BLOCKED — contestable: {e.contestable}")
        if e.contestable:
            print(f"File appeal within {e.appeal_deadline_hours}h")

Architecture:
    Follows the BTV 4-element adapter pattern:
      1. Custom Exception  -> GrantBlockedError (contestability-aware)
      2. Guard Class        -> GrantGuard (configurable, hookable)
      3. _validate()        -> Structural pre-flight checks
      4. _sanitize()        -> Input normalization for safe kernel processing

    Design decisions documented in ADR-043:
      - use_decide=True (full ethical pipeline for financial risk)
      - HMAC-SHA256 for session_id (Rust kernel handles BLAKE3)
      - JSON minified serialization (language-detector-safe)
      - hard_blocked checked before action (fail-secure)

File Structure:
    btv_grants/
    ├── __init__.py          # This file — public API exports
    ├── adapter.py           # GrantGuard — main adapter class
    ├── models.py            # GrantProposal, BiasDeclaration, enums
    └── exceptions.py        # GrantBlockedError, GrantValidationError, etc.
"""

from .adapter import GrantGuard, GrantGuardConfig
from .exceptions import (
    BiasDeclarationError,
    GrantBlockedError,
    GrantSanitizationError,
    GrantValidationError,
)
from .models import (
    ActionImpact,
    BiasDeclaration,
    DEFAULT_BIAS_DECLARATIONS,
    GrantCategory,
    GrantProposal,
    GrantStage,
    LinguisticGroup,
)

__all__ = [
    # Main adapter
    "GrantGuard",
    "GrantGuardConfig",
    # Domain models
    "GrantProposal",
    "GrantCategory",
    "GrantStage",
    "LinguisticGroup",
    "ActionImpact",
    "BiasDeclaration",
    "DEFAULT_BIAS_DECLARATIONS",
    # Exceptions
    "GrantBlockedError",
    "GrantValidationError",
    "GrantSanitizationError",
    "BiasDeclarationError",
]

__version__ = "0.1.0-alpha"
__adapter_name__ = "btv-grants"
__btv_min_version__ = "0.8.0"
