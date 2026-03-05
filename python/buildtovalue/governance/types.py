"""
Governance shared types v1.0.0
Canonical type definitions for the Judiciary branch.

Used by: context_engine.py, ethical_context_engine.py, all test files.
DO NOT redefine these types elsewhere — import from here.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import time


class ActionType(Enum):
    """
    Proportional response actions (Levinas: educate before punish).

    Severity order: ALLOW < LOG < EDUCATE < REDACT < BLOCK < ESCALATE_HUMAN
    """
    ALLOW          = "ALLOW"
    LOG            = "LOG"
    EDUCATE        = "EDUCATE"
    REDACT         = "REDACT"
    BLOCK          = "BLOCK"
    ESCALATE_HUMAN = "escalate_human"


ACTION_SEVERITY: Dict[ActionType, int] = {
    ActionType.ALLOW: 0,
    ActionType.LOG: 1,
    ActionType.EDUCATE: 2,
    ActionType.REDACT: 3,
    ActionType.BLOCK: 4,
    ActionType.ESCALATE_HUMAN: 5,
}


@dataclass
class RequestMetadata:
    """
    Technical request context.

    All fields have defaults to allow flexible construction
    from both Gateway (partial data) and tests.
    """
    agent_id: str = "unknown"
    session_id: str = "unknown"
    user_role: str = "anonymous"
    domain: str = "general"
    timestamp: int = field(default_factory=lambda: int(time.time()))
    is_first_offense: bool = True
    has_prior_violations: bool = False
    trust_score: float = 0.5
    educational_mode: bool = False
    operation_type: Optional[str] = None
    criticality: str = "MEDIUM"
    user_history: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None


@dataclass
class EthicalContext:
    """
    Context for ethical evaluation (Gilligan: care factors).

    Used by EthicalContextEngineV3.decide() and all governance tests.
    """
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: int = field(default_factory=lambda: int(time.time()))
    user_history: Dict[str, Any] = field(default_factory=dict)
    trust_score: float = 0.5
    operation_type: Optional[str] = None
    criticality: str = "MEDIUM"
    is_first_offense: bool = True
    has_prior_violations: bool = False
    educational_mode: bool = False
    domain: str = "general"
    user_role: str = "anonymous"


@dataclass
class SimpleFinding:
    """Minimal finding for governance layer (duck-types Rust Finding)."""
    rule_id: str = ""
    confidence: float = 0.5
    severity: float = 0.5
    module: str = ""


class _Stats:
    """Mimics TechnicalEvidence.stats interface for MercyCalculator."""
    def __init__(
        self,
        entropy: float = 0.0,
        total_chars: int = 0,
        has_pii: bool = False,
    ):
        self.entropy = entropy
        self.total_chars = total_chars
        self.has_pii = has_pii


@dataclass
class SimpleTechnicalEvidence:
    """
    Lightweight adapter matching Rust TechnicalEvidence interface
    for MercyCalculator compatibility.

    Duck-types: .findings, .critical, .critical_count,
    .composite_risk, .stats.has_pii, .stats.entropy
    """
    composite_risk: float = 0.0
    finding_count: int = 0
    critical_count: int = 0
    entropy: float = 0.0
    total_chars: int = 0
    findings: List[SimpleFinding] = field(default_factory=list)
    _has_pii: bool = False

    @property
    def stats(self) -> _Stats:
        return _Stats(
            entropy=self.entropy,
            total_chars=self.total_chars,
            has_pii=self._has_pii or self.finding_count > 0,
        )

    @property
    def critical(self) -> List[SimpleFinding]:
        return [f for f in self.findings if f.severity >= 0.8]
