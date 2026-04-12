"""
BuildToValue Grant Decision Adapter — Public API

This package provides the GrantGuard adapter for integrating BTV ethical
governance into grant evaluation pipelines (Gitcoin Rounds, DAO treasury,
quadratic funding platforms).

Quick start:
    from btv_grants import GrantGuard, GrantGuardConfig, GrantProposal
    from btv_grants import GrantCategory, LinguisticGroup
    from btv_grants import GrantBlockedError, GrantValidationError

    guard = GrantGuard(client, GrantGuardConfig(dry_run=True))
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
    GrantVerdict,
    LinguisticGroup,
)

__all__ = [
    # Adapter
    "GrantGuard",
    "GrantGuardConfig",
    # Exceptions
    "GrantBlockedError",
    "GrantValidationError",
    "GrantSanitizationError",
    "BiasDeclarationError",
    # Models
    "GrantProposal",
    "GrantVerdict",
    "GrantCategory",
    "GrantStage",
    "LinguisticGroup",
    "ActionImpact",
    "BiasDeclaration",
    "DEFAULT_BIAS_DECLARATIONS",
]

__version__ = "1.0.0"
