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
import hmac
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

@dataclass
class GrantProposal:
    """Core data model for a grant proposal entering the BTV governance pipeline.

    This is the adapter's internal representation. It gets serialized via
    to_btv_input() into JSON minified format before being sent to the BTV
    kernel. The JSON format preserves the original language of all text fields,
    which is critical for the BTV language detector and multilingual governance.

    Attributes:
        applicant_id: Unique identifier for the grant applicant.
        title: Grant proposal title in the applicant's own language.
        description: Full proposal description in the applicant's own language.
        category: Grant category for sector-specific policy routing.
        stage: Current lifecycle stage of the proposal.
        budget_usd: Requested funding amount in USD.
        team_size: Number of team members involved.
        linguistic_group: Primary language of the proposal content.
        action_impact: Impact classification. Defaults to IRREVERSIBLE (fail-secure).
        country_code: ISO 3166-1 alpha-2 country code.
        wallet_address: Ethereum wallet address for fund disbursement.
        deliverables: List of expected deliverables / milestones.
        tags: Free-form tags for additional categorization.
        extra: Arbitrary additional fields passed through to BTV.
    """

    # Required fields
    applicant_id: str
    title: str
    description: str
    category: GrantCategory = GrantCategory.OTHER

    # Core fields with sensible defaults
    stage: GrantStage = GrantStage.SUBMITTED
    budget_usd: float = 0.0
    team_size: int = 1
    linguistic_group: LinguisticGroup = LinguisticGroup.EN_US
    action_impact: ActionImpact = ActionImpact.IRREVERSIBLE

    # Optional fields
    country_code: Optional[str] = None
    wallet_address: Optional[str] = None
    deliverables: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate proposal structural integrity."""
        if not self.applicant_id or not self.applicant_id.strip():
            raise ValueError("applicant_id is required")
        if not self.title or not self.title.strip():
            raise ValueError("title is required")
        if not self.description or not self.description.strip():
            raise ValueError("description is required")
        if self.budget_usd < 0:
            raise ValueError(f"budget_usd must be >= 0, got {self.budget_usd}")
        if self.team_size < 1:
            raise ValueError(f"team_size must be >= 1, got {self.team_size}")
        if self.wallet_address is not None and not self.wallet_address.startswith("0x"):
            raise ValueError(
                f"wallet_address must start with '0x', got '{self.wallet_address}'"
            )

    # ------------------------------------------------------------------
    # BTV Integration Methods
    # ------------------------------------------------------------------

    def to_btv_input(self) -> str:
        """Serialize the proposal for the BTV kernel.

        Uses JSON minified format (not text with English prefixes).

        DESIGN DECISION (ADR-043 §3):
        Previous adapter drafts used text serialization like:
            "Title: ...\nDescription: ...\nBudget: ..."
        This is FRAGILE for non-English proposals because English prefixes
        ("Title:", "Description:") pollute the language detector, causing
        the BTV pipeline to misidentify the proposal's language and apply
        wrong governance profiles.

        JSON minified avoids this entirely — the BTV kernel's Rust
        gatekeeper can parse JSON natively and extract text fields for
        language detection independently of structural keys.
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
        if self.wallet_address:
            payload["wallet_address"] = self.wallet_address
        if self.deliverables:
            payload["deliverables"] = self.deliverables
        if self.tags:
            payload["tags"] = self.tags
        if self.extra:
            payload.update(self.extra)

        # Compact JSON — no whitespace, preserving all original-language text
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def to_session_id(self, secret: bytes = b"btv-grant-salt") -> str:
        """Derive a deterministic session ID for the BTV governance session.

        DESIGN DECISION (ADR-043 §2):
        Uses HMAC-SHA256, NOT hashlib.blake3. The Rust kernel already applies
        BLAKE3 internally for integrity verification. Adapters must NOT
        double-hash — the BTL (BLAKE3 Throughput Layer) in the Executive
        branch handles all BLAKE3 operations.

        HMAC-SHA256 provides:
          - Deterministic session IDs per applicant
          - Resistance to length-extension attacks (vs plain SHA-256)
          - A distinct salt domain from the kernel's BLAKE3 operations
        """
        if not self.applicant_id or not self.applicant_id.strip():
            return str(uuid.uuid4())
        return hmac.new(
            secret,
            self.applicant_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to plain dict for logging / debugging."""
        return {
            "applicant_id": self.applicant_id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "stage": self.stage.value,
            "budget_usd": self.budget_usd,
            "team_size": self.team_size,
            "linguistic_group": self.linguistic_group.value,
            "action_impact": self.action_impact.value,
            "country_code": self.country_code,
            "wallet_address": self.wallet_address,
            "deliverables": self.deliverables,
            "tags": self.tags,
            "extra": self.extra,
        }


# ---------------------------------------------------------------------------
# Default Bias Declarations
# ---------------------------------------------------------------------------

DEFAULT_BIAS_DECLARATIONS: Dict[LinguisticGroup, BiasDeclaration] = {
    LinguisticGroup.EN_US: BiasDeclaration(
        group=LinguisticGroup.EN_US,
        fpr=0.03,
        fnr=0.05,
        sample_size=2400,
        calibration_date="2025-11-01",
        notes="Calibrated against 2,400 Gitcoin Grants Round 18 proposals. "
              "FPR measured as ALLOW->should-BLOCK rate; FNR as BLOCK->should-ALLOW.",
    ),
    LinguisticGroup.PT_BR: BiasDeclaration(
        group=LinguisticGroup.PT_BR,
        fpr=0.07,
        fnr=0.09,
        sample_size=800,
        calibration_date="2025-11-01",
        notes="Calibrated against 800 Web3 Comunidade proposals + 200 synthetic edge cases. "
              "Higher FPR/FNR than en-US due to informal register patterns in Portuguese.",
    ),
    LinguisticGroup.ES: BiasDeclaration(
        group=LinguisticGroup.ES,
        fpr=0.06,
        fnr=0.08,
        sample_size=600,
        calibration_date="2025-11-01",
        notes="Calibrated against 600 Spanish-speaking DAO proposals. "
              "FNR slightly elevated due to code-switching patterns.",
    ),
    # Swahili — UNCALIBRATED. FPR/FNR MUST remain None.
    # The Jonas integrity principle forbids fabricating bias data.
    LinguisticGroup.SW: BiasDeclaration(
        group=LinguisticGroup.SW,
        fpr=None,
        fnr=None,
        sample_size=0,
        calibration_date=None,
        notes="UNCALIBRATED — no real Swahili grant proposals available yet. "
              "DO NOT fabricate FPR/FNR values. Target: 500+ proposals from "
              "East African Web3 community (Kenya, Tanzania, Uganda, Rwanda).",
    ),
}
