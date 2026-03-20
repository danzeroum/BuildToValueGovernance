"""
Domain models for the BuildToValue governance API.
Maps directly to gateway response schemas (rust/gateway/src/routes/).
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class VerdictAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    INSPECT = "INSPECT"
    REDACT = "REDACT"
    EDUCATE = "EDUCATE"
    LOG = "LOG"


class DriftLevel(str, Enum):
    NONE = "None"
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


class AppealStatus(str, Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"


class AppealGrounds(str, Enum):
    RAWLS_EQUITY = "rawls_equity"
    LEVINAS_PROTECTION = "levinas_protection"
    GILLIGAN_MERCY = "gilligan_mercy"
    JONAS_RESPONSIBILITY = "jonas_responsibility"
    TECHNICAL_ERROR = "technical_error"
    SCOPE_MISMATCH = "scope_mismatch"
    FALSE_POSITIVE = "false_positive"


class ExplainDecision(BaseModel):
    """Philosophical rationale from the Rawls→Levinas→Jonas→Gilligan pipeline."""
    summary: str
    rawls_rationale: str
    levinas_rationale: str
    jonas_rationale: str
    gilligan_rationale: str
    trust_score: float = Field(ge=0.0, le=1.0)
    mercy_score: float = Field(ge=0.0, le=1.0)
    pipeline_stages: list[str]


class Verdict(BaseModel):
    """Full governance verdict from /v1/decide (with ethical pipeline)."""
    verdict_id: str
    action: VerdictAction
    original_action: VerdictAction
    mercy_applied: bool
    finding_count: int
    critical_count: int
    composite_risk: float = Field(ge=0.0, le=1.0)
    hard_blocked: bool
    contestable: bool
    appeal_deadline_hours: int
    signature: str
    rationale: str
    explain: ExplainDecision
    jurisdiction_bitmask: int
    latency_ms: float

    @property
    def is_blocked(self) -> bool:
        return self.action == VerdictAction.BLOCK

    @property
    def is_allowed(self) -> bool:
        return self.action == VerdictAction.ALLOW

    @property
    def explanation(self) -> str:
        """Human-readable explanation combining rationale and philosophical summary."""
        return f"{self.rationale}\n\n{self.explain.summary}"


class ValidateVerdict(BaseModel):
    """Verdict from /v1/validate (Rust-only scan, no ethical pipeline)."""
    verdict_id: str
    action: VerdictAction
    original_action: VerdictAction
    mercy_applied: bool
    finding_count: int
    critical_count: int
    composite_risk: float
    hard_blocked: bool
    hard_block_term: Optional[str] = None
    contestable: bool
    appeal_deadline_hours: int
    message: str
    matched_policies: list[str]
    max_finding_confidence: float = 0.0
    entropy: float = 0.0
    total_chars: int = 0
    blake3_hash: str = ""
    drift_level: str = "None"
    signature: str
    latency_ms: float

    @property
    def is_blocked(self) -> bool:
        return self.action == VerdictAction.BLOCK

    @property
    def is_allowed(self) -> bool:
        return self.action == VerdictAction.ALLOW


class Appeal(BaseModel):
    """Appeal record with status and resolution."""
    appeal_id: str
    verdict_id: str = ""
    user_id: str = ""
    reason: str
    grounds: list[str] = []
    status: AppealStatus
    submitted_at: Optional[str] = None
    resolved_at: Optional[str] = None
    resolution: Optional[str] = None
    mediator_recommendation: Optional[str] = None
    sla_deadline: Optional[str] = None
    evidence_hash: Optional[str] = None

    @property
    def is_pending(self) -> bool:
        return self.status == AppealStatus.PENDING

    @property
    def is_accepted(self) -> bool:
        return self.status == AppealStatus.ACCEPTED


class TrustScore(BaseModel):
    """Session trust score from /v1/trust/{session_id}."""
    session_id: str
    trust_score: float = Field(ge=0.0, le=1.0)
    total_requests: int = 0
    offenses: int = 0
    calculated_at: Optional[str] = None

    @property
    def level(self) -> str:
        """Qualitative trust level."""
        if self.trust_score >= 0.8:
            return "high"
        elif self.trust_score >= 0.5:
            return "medium"
        else:
            return "low"


class SanitizeResult(BaseModel):
    """Result from /v1/sanitize."""
    sanitized: str
    redactions: int
    latency_ms: float = 0.0
