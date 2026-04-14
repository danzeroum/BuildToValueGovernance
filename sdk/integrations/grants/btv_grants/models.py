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
        fpr: False Positive Rate (0.0–1.0) or None if uncalibrated.
        fnr: False Negative Rate (0.0–1.0) or None if uncalibrated.
        sample_size: Number of real-world samples used for calibration.
                     0 means no calibration data (synthetic-only).
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
        if self.group == LinguisticGroup.SW and (
            self.fpr is not None or self.fnr is not None
        ):
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


# Default bias declarations per linguistic group
DEFAULT_BIAS_DECLARATIONS: Dict[str, BiasDeclaration] = {
    LinguisticGroup.EN_US.value: BiasDeclaration(
        group=LinguisticGroup.EN_US,
        fpr=0.032,
        fnr=0.018,
        sample_size=15_420,
        calibration_date="2024-11-01",
        notes="Calibrated on Gitcoin GR15-GR21 historical data",
    ),
    LinguisticGroup.PT_BR.value: BiasDeclaration(
        group=LinguisticGroup.PT_BR,
        fpr=0.041,
        fnr=0.023,
        sample_size=3_280,
        calibration_date="2024-10-15",
        notes="Calibrated on BrazilDAO + Gitcoin BR rounds",
    ),
    LinguisticGroup.ES.value: BiasDeclaration(
        group=LinguisticGroup.ES,
        fpr=0.038,
        fnr=0.021,
        sample_size=2_940,
        calibration_date="2024-10-15",
        notes="Calibrated on LatAm Web3 grant data (es-MX, es-AR, es-CO)",
    ),
    LinguisticGroup.SW.value: BiasDeclaration(
        group=LinguisticGroup.SW,
        fpr=None,  # MUST be null — uncalibrated (Jonas principle)
        fnr=None,  # MUST be null — uncalibrated (Jonas principle)
        sample_size=0,
        calibration_date=None,
        notes="UNCALIBRATED: No production data for Swahili proposals. "
              "FPR/FNR fabrication forbidden. INSPECT path forced until calibrated.",
    ),
}


# ---------------------------------------------------------------------------
# Grant Proposal
# ---------------------------------------------------------------------------

@dataclass
class GrantProposal:
    """Core data model for a grant proposal entering the BTV governance pipeline.

    Serialized via to_btv_input() into JSON minified format before being sent
    to the BTV kernel. JSON format preserves the original language of all text
    fields, critical for the BTV language detector and multilingual governance.

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
        action_impact: Impact classification. Defaults to IRREVERSIBLE (fail-secure).
        country_code: ISO 3166-1 alpha-2 country code of the applicant/team.
        wallet_address: Ethereum wallet address for fund disbursement.
        deliverables: List of expected deliverables / milestones.
        tags: Free-form tags for additional categorization.
        extra: Arbitrary additional fields passed through to BTV metadata.
    """
    applicant_id: str
    title: str
    description: str
    category: str = GrantCategory.OTHER.value
    stage: str = GrantStage.SUBMITTED.value
    budget_usd: float = 0.0
    team_size: int = 1
    linguistic_group: str = LinguisticGroup.EN_US.value
    action_impact: str = ActionImpact.IRREVERSIBLE.value
    country_code: Optional[str] = None
    wallet_address: Optional[str] = None
    deliverables: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_btv_input(self) -> str:
        """Serialize proposal to JSON minified string for BTV kernel input.

        CRITICAL: Uses JSON format, NOT English text prefixes like "Title: ..."
        Text prefixes would confuse the BTV LanguageDetector for non-English
        proposals. JSON keys are language-neutral identifiers.

        Returns:
            Minified JSON string ready for /v1/decide content field.
        """
        payload: Dict[str, Any] = {
            "t": self.title,
            "d": self.description,
            "cat": self.category,
            "budget": self.budget_usd,
            "team": self.team_size,
            "lang": self.linguistic_group,
            "impact": self.action_impact,
        }
        if self.country_code:
            payload["cc"] = self.country_code
        if self.deliverables:
            payload["deliv"] = self.deliverables
        if self.tags:
            payload["tags"] = self.tags
        if self.extra:
            payload["extra"] = self.extra
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def to_session_id(self, secret_key: bytes) -> str:
        """Derive a deterministic session ID via HMAC-SHA256.

        Uses HMAC-SHA256, NOT hashlib.blake3. The Rust kernel handles BLAKE3
        internally for evidence hashing. Adapters must not double-hash or
        duplicate the Rust kernel's cryptographic responsibilities.

        Args:
            secret_key: Secret bytes for HMAC derivation. Must be >= 32 bytes.

        Returns:
            Hex-encoded HMAC-SHA256 digest (64 hex chars).
        """
        msg = f"{self.applicant_id}:{self.title}:{self.budget_usd}".encode("utf-8")
        return hmac_lib.new(secret_key, msg, hashlib.sha256).hexdigest()

    def to_metadata(self, secret_key: bytes) -> Dict[str, Any]:
        """Build the BTV metadata dict for the /v1/decide request."""
        bias = DEFAULT_BIAS_DECLARATIONS.get(
            self.linguistic_group,
            DEFAULT_BIAS_DECLARATIONS[LinguisticGroup.SW.value],
        )
        return {
            "session_id": self.to_session_id(secret_key),
            "source": "grant-decision-adapter",
            "version": "1.0.0",
            "linguistic_group": self.linguistic_group,
            "bias_declaration": bias.to_dict(),
            "action_impact": self.action_impact,
            "category": self.category,
            "budget_usd": self.budget_usd,
            "team_size": self.team_size,
            "country_code": self.country_code,
            "wallet_address": self.wallet_address,
        }


# ---------------------------------------------------------------------------
# Grant Verdict
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GrantVerdict:
    """Enriched verdict returned to callers after BTV pipeline evaluation.

    Wraps the raw BTV Verdict with grant-domain semantics, adding
    can_appeal, is_hard_block, and explanation fields for applicant UX.
    """
    verdict_id: str
    action: str
    composite_risk: float
    rationale: str
    trust_score: float
    contestable: bool
    appeal_deadline_hours: int
    mercy_applied: bool = False
    hard_blocked: bool = False
    rawls_rationale: str = ""
    levinas_rationale: str = ""
    jonas_rationale: str = ""
    gilligan_rationale: str = ""

    @property
    def can_appeal(self) -> bool:
        """True if applicant can file an appeal via /v1/appeals."""
        return self.contestable and not self.hard_blocked

    @property
    def is_hard_block(self) -> bool:
        """True if this is a hard block (sanctioned entity, scam pattern, etc.)."""
        return self.hard_blocked

    @property
    def explanation(self) -> str:
        """Multi-stage philosophical explanation for the governance decision."""
        parts = [self.rationale]
        if self.rawls_rationale:
            parts.append(f"[Rawls] {self.rawls_rationale}")
        if self.levinas_rationale:
            parts.append(f"[Levinas] {self.levinas_rationale}")
        if self.jonas_rationale:
            parts.append(f"[Jonas] {self.jonas_rationale}")
        if self.gilligan_rationale:
            parts.append(f"[Gilligan] {self.gilligan_rationale}")
        return " | ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict for API response or audit log."""
        return {
            "verdict_id": self.verdict_id,
            "action": self.action,
            "composite_risk": self.composite_risk,
            "rationale": self.rationale,
            "trust_score": self.trust_score,
            "contestable": self.contestable,
            "can_appeal": self.can_appeal,
            "appeal_deadline_hours": self.appeal_deadline_hours,
            "is_hard_block": self.is_hard_block,
            "mercy_applied": self.mercy_applied,
            "explanation": self.explanation,
        }
