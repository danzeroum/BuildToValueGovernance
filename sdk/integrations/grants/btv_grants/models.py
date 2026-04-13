"""
BuildToValue Grant Decision Adapter — Domain Models

CRITICAL DESIGN DECISIONS (see ADR-043):
  1. to_btv_input() uses JSON minified — NOT text with English prefixes.
  2. to_session_id() uses HMAC-SHA256 — NOT hashlib.blake3.
  3. BiasDeclaration uses null for uncalibrated linguistic groups (sw).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class GrantCategory(str, Enum):
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
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    FUNDED = "funded"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class LinguisticGroup(str, Enum):
    EN_US = "en-US"
    PT_BR = "pt-BR"
    ES = "es"
    SW = "sw"  # Swahili — uncalibrated, BiasDeclaration FPR/FNR must be null


class ActionImpact(str, Enum):
    """Impact classification for the BTV fail-secure pipeline.

    If a proposal does not declare an ActionImpact, the BTV Rust gatekeeper
    defaults to IRREVERSIBLE (fail-secure by default).
    """
    REVERSIBLE = "reversible"
    CONDITIONALLY_REVERSIBLE = "conditionally_reversible"
    IRREVERSIBLE = "irreversible"


@dataclass(frozen=True)
class BiasDeclaration:
    """Explicit bias calibration data for a linguistic group.

    For uncalibrated groups (e.g. Swahili), FPR and FNR MUST be None —
    the Jonas integrity principle forbids fabricating calibration data.
    """
    group: LinguisticGroup
    fpr: Optional[float] = None
    fnr: Optional[float] = None
    sample_size: int = 0
    calibration_date: Optional[str] = None
    notes: str = ""

    def __post_init__(self) -> None:
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
        return {
            "group": self.group.value,
            "fpr": self.fpr,
            "fnr": self.fnr,
            "sample_size": self.sample_size,
            "calibration_date": self.calibration_date,
            "notes": self.notes,
        }


@dataclass
class GrantProposal:
    """Core data model for a grant proposal entering the BTV governance pipeline."""

    # Required fields
    applicant_id: str
    title: str
    description: str
    category: GrantCategory

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

    def to_btv_input(self) -> str:
        """Serialize the proposal for the BTV kernel using JSON minified format.

        DESIGN DECISION (ADR-043 §3): JSON minified avoids English-prefix
        pollution of the BTV language detector for non-English proposals.
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
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def to_session_id(self, secret: bytes = b"btv-grant-salt") -> str:
        """Derive a deterministic session ID using HMAC-SHA256.

        DESIGN DECISION (ADR-043 §2): Uses HMAC-SHA256, NOT hashlib.blake3.
        The Rust kernel owns BLAKE3; adapters must not double-hash.
        """
        if not self.applicant_id or not self.applicant_id.strip():
            return str(uuid.uuid4())
        return hmac.new(
            secret,
            self.applicant_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
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


DEFAULT_BIAS_DECLARATIONS: Dict[LinguisticGroup, BiasDeclaration] = {
    LinguisticGroup.EN_US: BiasDeclaration(
        group=LinguisticGroup.EN_US,
        fpr=0.03,
        fnr=0.05,
        sample_size=2400,
        calibration_date="2025-11-01",
        notes="Calibrated against 2,400 Gitcoin Grants Round 18 proposals.",
    ),
    LinguisticGroup.PT_BR: BiasDeclaration(
        group=LinguisticGroup.PT_BR,
        fpr=0.07,
        fnr=0.09,
        sample_size=800,
        calibration_date="2025-11-01",
        notes="Calibrated against 800 Web3 Comunidade proposals + 200 synthetic edge cases.",
    ),
    LinguisticGroup.ES: BiasDeclaration(
        group=LinguisticGroup.ES,
        fpr=0.06,
        fnr=0.08,
        sample_size=600,
        calibration_date="2025-11-01",
        notes="Calibrated against 600 Spanish-speaking DAO proposals.",
    ),
    LinguisticGroup.SW: BiasDeclaration(
        group=LinguisticGroup.SW,
        fpr=None,
        fnr=None,
        sample_size=0,
        calibration_date=None,
        notes=(
            "UNCALIBRATED — no real Swahili grant proposals available yet. "
            "DO NOT fabricate FPR/FNR values. Target: 500+ proposals from "
            "East African Web3 community (Kenya, Tanzania, Uganda, Rwanda)."
        ),
    ),
}
