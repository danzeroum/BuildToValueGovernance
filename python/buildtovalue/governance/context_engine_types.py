"""
context_engine_types.py — Dataclasses para EthicalContextEngine v1.9.1.
Extraído de context_engine.py (T1.3 — DT-005).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class RequestContext:
    """Context provided by the caller for ethical evaluation."""
    agent_id: str
    session_id: str
    domain: str = "general"
    user_role: str = "anonymous"
    ip_jurisdiction: str = "XX"
    ip_risk: str = "Low"
    drift_level: str = "None"
    timestamp: int = 0
    prior_sensitivity_tags: list = field(default_factory=list)
    cumulative_risk: float = 0.0
    active_combinations: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.timestamp == 0:
            self.timestamp = int(time.time())


@dataclass
class RustEvidence:
    """Simplified view of TechnicalEvidence for governance layer."""
    composite_risk: float
    finding_count: int
    critical_count: int
    entropy: float
    total_chars: int
    policy_action: str  # ALLOW/LOG/EDUCATE/REDACT/BLOCK/REPORT
    blake3_hash: str
    findings_summary: list = field(default_factory=list)


@dataclass
class EthicalVerdict:
    """Signed, explainable, contestable verdict."""
    verdict_id: str
    timestamp: int
    original_action: str
    final_action: str
    mercy_applied: bool
    mercy_scenario: str
    mercy_score: float
    trust_score: float
    explanation: str
    hmac_signature: str
    contestable: bool = True
    appeal_deadline: int = 0
    # ADR-043: True quando veredicto REPORT emitido por threshold
    report_triggered: bool = False

    def __post_init__(self) -> None:
        if self.appeal_deadline == 0:
            self.appeal_deadline = self.timestamp + (24 * 3600)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict_id": self.verdict_id,
            "timestamp": self.timestamp,
            "original_action": self.original_action,
            "final_action": self.final_action,
            "mercy_applied": self.mercy_applied,
            "mercy_scenario": self.mercy_scenario,
            "mercy_score": round(self.mercy_score, 4),
            "trust_score": round(self.trust_score, 4),
            "explanation": self.explanation,
            "hmac_signature": self.hmac_signature,
            "contestable": self.contestable,
            "appeal_deadline": self.appeal_deadline,
            "report_triggered": self.report_triggered,
        }
