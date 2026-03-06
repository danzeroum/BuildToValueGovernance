"""
ece_types.py — Dataclasses locais do EthicalContextEngine (T1.3 / v1.6.0)

Extraído de ethical_context_engine.py para respeitar o limite de 200 linhas.
Importado exclusivamente por ethical_context_engine.py — nao e API publica.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .mercy_factor import MercyFactor
from .types import ActionType, EthicalContext


@dataclass
class Rule:
    """Policy rule for technical evaluation."""
    id: str
    action: str
    priority: int
    domain: Optional[str] = None
    min_risk_level: Optional[str] = None
    required_findings: Optional[List[str]] = None
    min_trust_score: Optional[float] = None
    max_trust_score: Optional[float] = None
    condition: Optional[str] = None


@dataclass
class TechnicalVerdict:
    """Technical layer verdict."""
    action: ActionType
    confidence: float
    rule_id: Optional[str]
    rationale: str
    mercy_score: float = 0.0
    trust_score: float = 0.0
    signature: Optional[bytes] = None
    context_factors: Dict[str, Any] = field(default_factory=dict)
    security_evaluation_time_ms: float = 0.0
    expression_nodes_evaluated: int = 0


@dataclass
class EthicalDecision:
    """Governance layer decision."""
    verdict: ActionType
    adjusted_severity: float
    confidence: float
    context: EthicalContext
    mercy_applied: bool
    mercy_factor: Optional[MercyFactor]
    rationale: str
    contributing_factors: List[str]
    contestable: bool = True
    appeal_deadline: Optional[datetime] = None
    signature: Optional[str] = None
    signed_at: Optional[int] = None
    bias_declaration: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        from dataclasses import asdict
        result = asdict(self)
        result["verdict"] = self.verdict.value
        if self.appeal_deadline:
            result["appeal_deadline"] = self.appeal_deadline.isoformat()
        return result


@dataclass
class UnifiedDecision:
    """Combined technical + governance decision."""
    decision_id: str
    timestamp: int
    technical_verdict: TechnicalVerdict
    ethical_decision: EthicalDecision
    evidence_hash: str
    request_metadata: Any   # RequestMetadata — Any evita import circular
    ethical_context: EthicalContext
    profile_name: str
    total_processing_time_ms: float
    technical_time_ms: float
    governance_time_ms: float

    def to_v2_verdict(self) -> TechnicalVerdict:
        return self.technical_verdict

    def to_v3_decision(self) -> EthicalDecision:
        return self.ethical_decision

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "action": self.technical_verdict.action.value,
            "confidence": self.technical_verdict.confidence,
            "trust_score": self.technical_verdict.trust_score,
            "mercy_applied": self.ethical_decision.mercy_applied,
            "contestable": self.ethical_decision.contestable,
            "evidence_hash": self.evidence_hash,
            "processing_time_ms": self.total_processing_time_ms,
            "signature": self.ethical_decision.signature,
            "bias_declaration": self.ethical_decision.bias_declaration,
        }
