"""
Agent PDP contracts — ADR-029 v1.0.

Tipos canônicos para agentes externos consumirem o BTV como PDP.
Invariantes:
- ActionImpact ausente → Irreversible (fail-secure)
- HMAC inválido → BLOCK imediato
- TTL zero para Irreversible (cache proibido)
≤ 200 linhas
"""
from __future__ import annotations
import hashlib
import hmac as hmac_lib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionImpact(str, Enum):
    SAFE         = "Safe"
    DESTRUCTIVE  = "Destructive"
    IRREVERSIBLE = "Irreversible"


class AgentVerdict(str, Enum):
    ALLOW            = "ALLOW"
    EDUCATE          = "EDUCATE"
    PENDING_APPROVAL = "PENDING_APPROVAL"  # Gap F: awaiting HITL
    BLOCK            = "BLOCK"


@dataclass
class AgentAction:
    name:         str
    impact:       ActionImpact = ActionImpact.IRREVERSIBLE  # fail-secure default
    capabilities: List[str]    = field(default_factory=list)


@dataclass
class AgentContext:
    profile_id:          str   = "default"
    sector_id:           str   = "general"
    session_trust_score: float = 0.5
    agent_metadata:      Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentDecisionRequest:
    """Contrato canônico ADR-029 §4.1."""
    agent_id:           str
    session_id:         str
    action:             AgentAction
    parameters_hash:    str                   # BLAKE3-hex dos parâmetros completos
    schema_version:     str                   = "1.0"
    request_id:         str                   = field(default_factory=lambda: str(uuid.uuid4()))
    parameters_preview: Dict[str, Any]       = field(default_factory=dict)
    context:            AgentContext          = field(default_factory=AgentContext)
    timestamp_utc:      str                   = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    parent_verdict_id:  Optional[str]        = None   # Gap B: delegation chain
    delegation_depth:   int                  = 0      # Gap B: chain depth counter

    def __post_init__(self) -> None:
        if len(self.parameters_hash) != 64:
            raise ValueError("parameters_hash must be 64-char hex (BLAKE3)")
        if self.action.impact == ActionImpact.IRREVERSIBLE:
            # TTL zero enforced by caller — document invariant
            self.parameters_preview = {}  # proibido expor preview em Irreversible


@dataclass
class BiasSummary:
    false_positive_rate_pct: float
    false_negative_rate_pct: float
    calibration_date:        str
    known_limitations:       str = ""


@dataclass
class VerdictEnvelope:
    """Contrato canônico ADR-029 §4.2."""
    request_id:              str
    verdict:                 AgentVerdict
    verdict_code:            int
    explain_decision:        str
    bias_declaration:        BiasSummary
    contestable:             bool
    appeal_deadline_utc:     str
    policy_version_applied:  str
    evidence_id:             str
    hmac_sha256:             str
    timestamp_utc:           str
    approval_id:             Optional[str] = None  # Gap F: HITL ticket ID

    def verify_hmac(self, shared_key: bytes) -> bool:
        """Verificação constant-time obrigatória — ADR-029 §4.3."""
        payload = (
            f"{self.request_id}|{self.verdict}|"
            f"{self.evidence_id}|{self.timestamp_utc}"
        ).encode()
        expected = hmac_lib.new(shared_key, payload, hashlib.sha256).hexdigest()
        return hmac_lib.compare_digest(expected, self.hmac_sha256)

    @property
    def is_blocked(self) -> bool:
        return self.verdict == AgentVerdict.BLOCK
