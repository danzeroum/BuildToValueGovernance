"""
BuildToValue Grant Decision Adapter — Domain Models

Defines the data structures used by the grant governance pipeline:
  - LinguisticGroup: Enum for the 4 supported languages
  - GrantCategory: Enum for grant categories mapped to BTV policy sectors
  - BiasDeclaration: Calibrated FPR/FNR per linguistic group (Jonas integrity)
  - GrantProposal: Input dataclass with structural validation + HMAC session_id
  - GrantVerdict: Output dataclass wrapping BTV Verdict with grant-specific fields

All models follow BTV invariants:
  - No .unwrap() equivalents (explicit error handling)
  - No arbitrary clone/copy without justification
  - Fail-secure: validation errors are explicit, not silently swallowed
  - HMAC-SHA256 for session_id (not BLAKE3 — that's the Rust kernel's domain)
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .exceptions import GrantValidationError

# HMAC key for session_id derivation.
# In production, load from environment: os.environ["BTV_GRANT_HMAC_KEY"]
# Default is a non-secret placeholder for local development only.
_SESSION_HMAC_KEY: bytes = b"btv-grant-adapter-dev-key-change-in-prod"

# Wallet address validation: must start with 0x followed by 40 hex chars (EIP-55)
_WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Maximum description length (characters). Content beyond this is truncated by sanitizer.
_DESC_MAX_LEN: int = 50_000

# Maximum allowed budget in USD.
_BUDGET_MAX_USD: float = 10_000_000.0


class LinguisticGroup(str, Enum):
    """Supported linguistic groups for BiasDeclaration calibration."""
    EN_US = "en-US"
    PT_BR = "pt-BR"
    ES = "es"
    SW = "sw"


class GrantCategory(str, Enum):
    """Grant categories mapped to BTV policy sectors.

    These values align with the sector YAML files under data/policies/sectors/.
    """
    PUBLIC_GOODS = "public_goods"
    DEFI = "defi"
    EDUCATION = "education"
    HEALTHCARE = "healthcare"
    INFRASTRUCTURE = "infrastructure"
    RESEARCH = "research"
    COMMUNITY = "community"
    ENVIRONMENT = "environment"
    OTHER = "other"


@dataclass
class BiasDeclaration:
    """Calibrated fairness metrics per linguistic group.

    Jonas Responsibility Principle: if calibration data is unavailable for a
    linguistic group, the FPR/FNR fields MUST be None — fabricating metrics
    is more harmful than admitting uncertainty. Swahili (sw) is currently
    uncalibrated; setting non-None values for sw raises ValueError.

    Attributes:
        group: The linguistic group this declaration applies to.
        fpr: False Positive Rate (blocking legitimate proposals). None = uncalibrated.
        fnr: False Negative Rate (approving harmful proposals). None = uncalibrated.
        notes: Free-text notes on calibration methodology or known limitations.
    """
    group: LinguisticGroup
    fpr: Optional[float] = None
    fnr: Optional[float] = None
    notes: str = ""

    def __post_init__(self) -> None:
        # Jonas integrity: uncalibrated groups must declare null metrics
        if self.group == LinguisticGroup.SW:
            if self.fpr is not None or self.fnr is not None:
                raise ValueError(
                    "[Jonas] Swahili group is uncalibrated. "
                    "Set fpr=None and fnr=None to declare honest uncertainty. "
                    "Do not fabricate metrics."
                )
        # Validate range for calibrated groups
        for attr_name, value in (("fpr", self.fpr), ("fnr", self.fnr)):
            if value is not None:
                if not (0.0 <= value <= 1.0):
                    raise ValueError(
                        f"[BiasDeclaration] {attr_name}={value} out of range [0.0, 1.0]"
                    )


@dataclass
class GrantProposal:
    """A grant proposal submitted for BTV governance evaluation.

    Validates structural constraints in __post_init__ before the proposal
    reaches the sanitization pipeline or the BTV kernel.

    Attributes:
        applicant_id: Unique identifier for the applicant (wallet address,
                      DID, or platform-specific ID). Must not be empty.
        title: Short title for the grant proposal. Must not be empty.
        description: Full proposal narrative. Must not be empty.
                     Truncated to _DESC_MAX_LEN by the sanitizer if exceeded.
        category: Grant category determining which policy YAML is consulted.
        budget_usd: Requested funding amount in USD. Must be >= 0 and <= $10M.
        team_size: Number of team members. Must be >= 1 if provided.
        wallet_address: Optional EVM wallet address for fund disbursement.
                        Must match ^0x[0-9a-fA-F]{40}$ if provided.
        country_code: ISO 3166-1 alpha-2 country code. Used for OFAC/sanctions checks.
        prior_grants: Number of prior BTV grants received. Used for trust calibration.
        linguistic_group: Override for language detection. If None, the BTV kernel
                          performs automatic detection via LanguageDetector.
    """
    applicant_id: str
    title: str
    description: str
    category: GrantCategory = GrantCategory.OTHER
    budget_usd: float = 0.0
    team_size: int = 1
    wallet_address: Optional[str] = None
    country_code: Optional[str] = None
    prior_grants: int = 0
    linguistic_group: Optional[LinguisticGroup] = None

    def __post_init__(self) -> None:
        """Structural validation — fail fast before reaching the BTV kernel."""
        if not self.applicant_id or not self.applicant_id.strip():
            raise GrantValidationError("applicant_id", "must not be empty or whitespace-only")
        if not self.title or not self.title.strip():
            raise GrantValidationError("title", "must not be empty or whitespace-only")
        if not self.description or not self.description.strip():
            raise GrantValidationError("description", "must not be empty or whitespace-only")
        if self.budget_usd < 0:
            raise GrantValidationError("budget_usd", f"must be >= 0, got {self.budget_usd}")
        if self.budget_usd > _BUDGET_MAX_USD:
            raise GrantValidationError(
                "budget_usd",
                f"must be <= ${_BUDGET_MAX_USD:,.0f}, got ${self.budget_usd:,.2f}"
            )
        if self.team_size < 1:
            raise GrantValidationError("team_size", f"must be >= 1, got {self.team_size}")
        if self.wallet_address is not None:
            if not _WALLET_RE.match(self.wallet_address):
                raise GrantValidationError(
                    "wallet_address",
                    f"must match ^0x[0-9a-fA-F]{{40}}$, got '{self.wallet_address}'"
                )

    def to_session_id(self) -> str:
        """Derive a deterministic, HMAC-SHA256 session identifier.

        Uses HMAC-SHA256 (not BLAKE3 — that is the Rust kernel's domain).
        The session_id is deterministic per applicant_id, enabling idempotent
        re-evaluation of the same proposal within a governance round.

        Returns:
            64-character lowercase hex string (256-bit HMAC-SHA256 digest).
        """
        mac = hmac_lib.new(
            _SESSION_HMAC_KEY,
            self.applicant_id.encode("utf-8"),
            hashlib.sha256,
        )
        return mac.hexdigest()

    def to_btv_input(self) -> str:
        """Serialize proposal to JSON for the BTV kernel input pipeline.

        Produces a compact JSON string (no English-language prefixes like
        'Title:' or 'Description:') to avoid confusing the BTV LanguageDetector
        when processing non-English proposals (pt-BR, es, sw).

        Returns:
            Compact JSON string with all proposal fields.
        """
        payload: dict = {
            "applicant_id": self.applicant_id,
            "title": self.title,
            "description": self.description[:_DESC_MAX_LEN],
            "category": self.category.value,
            "budget_usd": self.budget_usd,
            "team_size": self.team_size,
            "session_id": self.to_session_id(),
        }
        if self.wallet_address:
            payload["wallet_address"] = self.wallet_address
        if self.country_code:
            payload["country_code"] = self.country_code
        if self.prior_grants:
            payload["prior_grants"] = self.prior_grants
        if self.linguistic_group:
            payload["linguistic_group"] = self.linguistic_group.value
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


@dataclass
class GrantVerdict:
    """Enriched verdict returned to the caller after successful evaluation.

    Wraps the BTV Verdict with grant-specific computed fields for
    convenience (can_appeal, is_hard_block, explanation).

    Attributes:
        verdict_id: Unique ULID from the BTV kernel.
        action: Final governance action after all pipeline stages.
        composite_risk: Aggregate risk score (0.0-1.0).
        trust_score: Post-pipeline trust score.
        mercy_applied: Whether Gilligan mercy intervention occurred.
        contestable: Whether the verdict can be appealed.
        appeal_deadline_hours: Hours remaining to file an appeal.
        rawls_rationale: Rawls fairness analysis.
        levinas_rationale: Levinas responsibility analysis.
        jonas_rationale: Jonas precautionary analysis.
        gilligan_rationale: Gilligan mercy analysis.
        explanation: Combined human-readable explanation for the applicant.
        can_appeal: Derived: True if contestable and appeal_deadline_hours > 0.
        is_hard_block: Derived: True if hard_blocked field is True in underlying Verdict.
    """
    verdict_id: str
    action: str
    composite_risk: float
    trust_score: float
    mercy_applied: bool
    contestable: bool
    appeal_deadline_hours: int
    rawls_rationale: str = ""
    levinas_rationale: str = ""
    jonas_rationale: str = ""
    gilligan_rationale: str = ""
    explanation: str = ""
    can_appeal: bool = field(init=False)
    is_hard_block: bool = False

    def __post_init__(self) -> None:
        self.can_appeal = self.contestable and self.appeal_deadline_hours > 0
        if not self.explanation:
            parts = [
                p for p in [
                    self.rawls_rationale,
                    self.levinas_rationale,
                    self.jonas_rationale,
                    self.gilligan_rationale,
                ] if p
            ]
            self.explanation = " | ".join(parts) if parts else "No explanation available."
