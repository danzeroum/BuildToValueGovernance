"""
BuildToValue Grant Decision Adapter — Domain Models

Defines the GrantProposal dataclass and supporting types for the
grant governance pipeline. These models are the adapter's internal
representation — they get serialized to JSON minified format before
being sent to the BTV kernel via /v1/decide.

CRITICAL DESIGN DECISIONS (see ADR-043):
  1. to_btv_input() uses JSON minified — NOT text with English prefixes.
     Text prefixes like "Title:", "Description:" would confuse the BTV
     language detector for non-English proposals (pt-BR, es, sw).
  2. to_session_id() uses HMAC-SHA256 — NOT hashlib.blake3. The Rust kernel
     handles BLAKE3 internally; adapters must NOT double-hash.
  3. BiasDeclaration uses null for uncalibrated linguistic groups (sw).
     Never fabricate FPR/FNR values — BTV integrity principle (Jonas).
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class GrantCategory(str, Enum):
    """Standard grant categories aligned with Gitcoin rounds + BTV sectors."""
    PUBLIC_GOODS = "public_goods"
    INFRASTRUCTURE = "infrastructure"
    COMMUNITY = "community"
    EDUCATION = "education"
    CLIMATE = "climate"
    DEFI = "defi"
    GOVERNANCE = "governance"
    OPEN_SOURCE = "open_source"
    RESEARCH = "research"
    OTHER = "other"


class GrantStage(str, Enum):
    """Lifecycle stage of a grant proposal. Affects risk weighting."""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    FUNDED = "funded"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class LinguisticGroup(str, Enum):
    """Primary linguistic group of the proposal, used for bias declaration."""
    EN_US = "en-US"
    PT_BR = "pt-BR"
    ES = "es"
    SW = "sw"  # Swahili — uncalibrated, BiasDeclaration FPR/FNR must be null


class ActionImpact(str, Enum):
    """Impact classification for the BTV fail-secure pipeline.

    If a proposal does not declare an ActionImpact, the BTV Rust gatekeeper
    defaults to IRREVERSIBLE (which triggers BLOCK on any critical finding).
    This is by design — fail-secure by default.
    """
    REVERSIBLE = "reversible"
    CONDITIONALLY_REVERSIBLE = "conditionally_reversible"
    IRREVERSIBLE = "irreversible"


# ---------------------------------------------------------------------------
# Bias Declaration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BiasDeclaration:
    """Explicit bias calibration data for a linguistic group.

    BTV requires adapters to declare their bias characteristics per group.
    For uncalibrated groups (e.g. Swahili), FPR and FNR MUST be None —
    the Jonas integrity principle forbids fabricating calibration data.

    Attributes:
        group: Linguistic group this declaration covers.
        fpr: False Positive Rate (0.0-1.0) or None if uncalibrated.
        fnr: False Negative Rate (0.0-1.0) or None if uncalibrated.
        sample_size: Number of real-world samples used for calibration.
        calibration_date: ISO 8601 date of last calibration, or None.
        notes: Free-form notes about calibration methodology.
    """
    group: LinguisticGroup
    fpr: Optional[float] = None
    fnr: Optional[float] = None
    sample_size: int = 0
    calibration_date: Optional[str] = None
    notes: str = ""

    def __post_init__(self) -> None:
        """Validate bias declaration integrity (Jonas principle)."""
        if self.group == LinguisticGroup.SW and (self.fpr is not None or self.fnr is not None):
            raise ValueError(
                f"BiasDeclaration for '{self.group.value}' (Swahili) must have "
                f"FPR=None and FNR=None — group is uncalibrated. "
                f"Fabricating bias data violates the Jonas integrity principle."
            )
        if self.fpr is not None and not (0.0 <= self.fpr <= 1.0):
            raise ValueError(f"FPR must be in [0.0, 1.0], got {self.fpr}")
        if self.fnr is not None and not (0.0 <= self.fnr <= 1.0):
            raise ValueError(f"FNR must be in [0.0, 1.0], got {self.fnr}")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for BTV metadata header."""
        return {
            "group": self.group.value,
            "fpr": self.fpr,
            "fnr": self.fnr,
            "sample_size": self.sample_size,
            "calibration_date": self.calibration_date,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Grant Proposal
# ---------------------------------------------------------------------------

_SESSION_SALT = b"btv-grant-adapter-v1"


@dataclass
class GrantProposal:
    """Core data model for a grant proposal entering the BTV governance pipeline.

    Serialized via to_btv_input() into JSON minified format before being sent
    to the BTV kernel. JSON preserves the original language of all text fields,
    critical for the BTV language detector and multilingual governance.

    Attributes:
        applicant_id: Unique identifier for the grant applicant. Used to derive
                      session_id via HMAC-SHA256 — NOT sent in plaintext to BTV.
        title: Grant proposal title in the applicant's own language.
        description: Full proposal description in the applicant's own language.
        category: Grant category for sector-specific policy routing.
        stage: Current lifecycle stage of the proposal.
        budget_usd: Requested funding amount in USD.
        team_size: Number of team members involved.
        linguistic_group: Primary language of the proposal content.
        wallet_address: Optional Ethereum wallet address (0x + 40 hex chars).
        country_code: ISO 3166-1 alpha-2 country code for jurisdiction checks.
        action_impact: Reversibility classification — defaults to IRREVERSIBLE.
        tags: Free-form tags for additional context.
        metadata: Arbitrary key-value metadata for extensibility.
    """
    applicant_id: str
    title: str
    description: str
    category: GrantCategory = GrantCategory.OTHER
    stage: GrantStage = GrantStage.DRAFT
    budget_usd: float = 0.0
    team_size: int = 1
    linguistic_group: LinguisticGroup = LinguisticGroup.EN_US
    wallet_address: Optional[str] = None
    country_code: Optional[str] = None
    action_impact: ActionImpact = ActionImpact.IRREVERSIBLE
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Structural validation — runs before the proposal reaches the BTV kernel."""
        from .exceptions import GrantValidationError

        if not self.applicant_id or not self.applicant_id.strip():
            raise GrantValidationError(
                field="applicant_id",
                reason="applicant_id must not be empty or whitespace-only",
                proposal_ref=self,
            )
        if not self.title or not self.title.strip():
            raise GrantValidationError(
                field="title",
                reason="title must not be empty",
                proposal_ref=self,
            )
        if not self.description or not self.description.strip():
            raise GrantValidationError(
                field="description",
                reason="description must not be empty",
                proposal_ref=self,
            )
        if self.budget_usd < 0:
            raise GrantValidationError(
                field="budget_usd",
                reason=f"budget_usd must be >= 0, got {self.budget_usd}",
                proposal_ref=self,
            )
        if self.budget_usd > 10_000_000:
            raise GrantValidationError(
                field="budget_usd",
                reason=f"budget_usd exceeds $10M maximum, got {self.budget_usd}",
                proposal_ref=self,
            )
        if self.team_size < 1:
            raise GrantValidationError(
                field="team_size",
                reason=f"team_size must be >= 1, got {self.team_size}",
                proposal_ref=self,
            )
        if self.wallet_address is not None:
            self._validate_wallet_address(self.wallet_address)

    def _validate_wallet_address(self, address: str) -> None:
        """Validate Ethereum wallet address format (0x + 40 hex chars)."""
        from .exceptions import GrantValidationError
        import re
        pattern = re.compile(r'^0x[0-9a-fA-F]{40}$')
        if not pattern.match(address):
            raise GrantValidationError(
                field="wallet_address",
                reason=(
                    f"wallet_address must match 0x[0-9a-fA-F]{{40}}, got '{address}'. "
                    f"Ensure address starts with '0x' and contains 40 hex characters."
                ),
                proposal_ref=self,
            )

    def to_session_id(self) -> str:
        """Derive a deterministic session ID using HMAC-SHA256.

        Uses applicant_id as the message and a fixed salt as the key.
        Produces a stable 64-character hex string for the same applicant_id.

        Returns:
            64-character lowercase hex string (HMAC-SHA256 digest).

        Note:
            Uses HMAC-SHA256, NOT hashlib.blake3. The Rust gatekeeper uses
            BLAKE3 internally — adapters must not replicate kernel primitives.
        """
        mac = hmac_lib.new(
            key=_SESSION_SALT,
            msg=self.applicant_id.encode("utf-8"),
            digestmod=hashlib.sha256,
        )
        return mac.hexdigest()

    def to_btv_input(self) -> str:
        """Serialize the proposal to JSON minified format for the BTV kernel.

        Produces compact JSON with all relevant fields. Text fields are passed
        as-is in the applicant's language — do NOT use English prefixes like
        'Title:', 'Description:', 'Budget:' as they bias the language detector
        for pt-BR, es, and sw proposals.

        Returns:
            JSON minified string (no extra whitespace) with proposal fields.
        """
        payload: Dict[str, Any] = {
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "stage": self.stage.value,
            "budget_usd": self.budget_usd,
            "team_size": self.team_size,
            "linguistic_group": self.linguistic_group.value,
            "action_impact": self.action_impact.value,
        }
        if self.country_code:
            payload["country_code"] = self.country_code
        if self.tags:
            payload["tags"] = self.tags
        if self.metadata:
            payload["metadata"] = self.metadata
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Grant Verdict
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GrantVerdict:
    """Enriched result from the BTV governance pipeline for a grant proposal.

    Wraps the raw BTV Verdict with grant-specific derived fields, making it
    easier for downstream consumers to render actionable information without
    re-querying the BTV kernel.

    Attributes:
        verdict_id: BTV verdict ULID (VRD-...).
        action: The governance action (ALLOW, BLOCK, EDUCATE, INSPECT, REDACT).
        hard_blocked: True if the block is final and non-contestable.
        contestable: Whether the applicant can appeal via /v1/appeals.
        appeal_deadline_hours: Hours remaining to file an appeal (0 if not contestable).
        composite_risk: Aggregate risk score (0.0-1.0).
        trust_score: Post-pipeline trust score.
        mercy_applied: Whether the Gilligan mercy algorithm intervened.
        rationale: Human-readable rationale from the BTV explain module.
        rawls_rationale: Distributive justice assessment.
        levinas_rationale: SLA + appeal rights assessment.
        jonas_rationale: Responsibility calibration assessment.
        gilligan_rationale: Mercy + care ethics assessment.
    """
    verdict_id: str
    action: str
    hard_blocked: bool
    contestable: bool
    appeal_deadline_hours: int
    composite_risk: float
    trust_score: float
    mercy_applied: bool
    rationale: str
    rawls_rationale: str = ""
    levinas_rationale: str = ""
    jonas_rationale: str = ""
    gilligan_rationale: str = ""

    @property
    def can_appeal(self) -> bool:
        """True if the applicant can file an appeal (contestable + window open)."""
        return self.contestable and self.appeal_deadline_hours > 0

    @property
    def is_hard_block(self) -> bool:
        """True if this verdict represents a hard (non-contestable) block."""
        return self.hard_blocked

    @property
    def explanation(self) -> str:
        """Single-sentence explanation for the applicant UI."""
        if self.action == "ALLOW":
            return "Your grant proposal has been approved for processing."
        if self.is_hard_block:
            return (
                "Your proposal has been permanently blocked due to policy violations "
                "that do not allow appeal."
            )
        if self.can_appeal:
            return (
                f"Your proposal has been blocked. You may appeal within "
                f"{self.appeal_deadline_hours} hours."
            )
        if self.action == "EDUCATE":
            return (
                "Your proposal needs revisions before it can be approved. "
                "Please review the guidance below."
            )
        if self.action == "INSPECT":
            return "Your proposal is under manual review. You will be notified of the outcome."
        return f"Your proposal received action '{self.action}'. Rationale: {self.rationale}"
