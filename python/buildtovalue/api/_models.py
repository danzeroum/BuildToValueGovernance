"""Modelos Pydantic da API de governança (ADR-0093).

Extraídos de ``app.py`` para isolar contratos de dados da lógica de
orquestração/decisão. Sem dependências de regras de negócio — modelos não
conhecem regras (apenas regras consomem modelos).
"""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class DecideRequest(BaseModel):
    """Request from Rust Gateway (or direct call)."""
    # HIGH-03: cap payload size to prevent unbounded-memory DoS.
    input_text: str = Field(default="", max_length=50000)
    finding_count: int = 0
    critical_count: int = 0
    composite_risk: float = 0.0
    action: str = "ALLOW"
    hard_blocked: bool = False
    matched_policies: List[str] = []
    session_id: Optional[str] = None
    trust_score: Optional[float] = None
    is_first_offense: Optional[bool] = None
    profile: Optional[str] = None
    # Evidence metadata
    entropy: float = 0.0
    total_chars: int = 0
    blake3_hash: str = ""
    max_finding_confidence: float = 0.0
    # Context (from Rust Network/Session modules)
    ip_risk: str = "Low"
    ip_jurisdiction: str = "XX"
    drift_level: str = "None"
    llm_output: Optional[str] = None  # LLM response text for schema validation
    # ADR-043: ID gerado pelo Rust; None = modo legado (deprecado)
    verdict_id: Optional[str] = None
    # Guard activation fields (forwarded from Rust gateway — policy-activation layer)
    source: Optional[str] = None
    channel: Optional[str] = None
    agent_policies: Optional[List[str]] = None


class BiasDeclaration(BaseModel):
    """Quatro pilares filosóficos da decisão (ADR Lab v3.0).

    Derivada de sinais reais do veredicto — não há precisão fabricada:
      equity_score    Rawls    — proxy de equidade = trust da sessão/papel
      pii_redacted    Levinas  — PII detectada e tratada de forma protetiva
      long_term_impact Jonas   — rótulo qualitativo do risco ajustado
      mercy_applied   Gilligan — downgrade de misericórdia aplicado (S1-S6)
      explain         output de explain_decision() (Levinas, obrigatório)
    """
    equity_score: float = 0.0
    pii_redacted: bool = False
    long_term_impact: str = "low"
    mercy_applied: bool = False
    explain: str = ""


class DecideResponse(BaseModel):
    verdict_id: str
    action: str
    original_action: str
    mercy_applied: bool
    mercy_scenario: str = ""
    mercy_score: float = 0.0
    trust_score: float
    adjusted_risk: float
    rationale: str
    contestable: bool
    appeal_deadline_hours: int
    signature: str
    latency_ms: float
    # Lab v3.0: declaração de viés sempre presente no envelope de decisão.
    bias_declaration: BiasDeclaration = Field(default_factory=BiasDeclaration)
    slm_used: bool = False
    slm_intent: Optional[str] = None
    slm_risk: Optional[float] = None
    risk_classification: Optional[str] = None
    compliance_violations: Optional[List[dict[str, object]]] = None
    compliance_rate: Optional[float] = None
    schema_violations: Optional[list[object]] = None


class MultiDecideRequest(BaseModel):
    """Lab v3.0 — avalia o mesmo prompt contra vários agentes (multi-agente)."""
    prompt: str
    agent_ids: List[str] = Field(default_factory=list)
    session_id: Optional[str] = None


class MultiDecideResponse(BaseModel):
    verdicts: List[DecideResponse]


# ═══════════════════════════════════════════════════════════════
# MODELS — Appeals (ADR-017)
# ═══════════════════════════════════════════════════════════════

class AppealStatusEnum(str, Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"


class AppealSubmitRequest(BaseModel):
    audit_trail_id: int = Field(..., description="ID da decisão contestada")
    user_id: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=20)
    evidence: Optional[str] = None
    evidence_hash: Optional[str] = None
    grounds: List[str] = []


class AppealResponse(BaseModel):
    appeal_id: str
    audit_trail_id: int
    user_id: str
    timestamp: int
    reason: str
    evidence_provided: Optional[str] = None
    status: AppealStatusEnum
    reviewer_notes: Optional[str] = None
    resolution_timestamp: Optional[int] = None
    sla_deadline: int
    is_overdue: bool
    evidence_hash: Optional[str] = None
    grounds: List[str] = []
    mediator_recommendation: Optional[str] = None


class AppealListResponse(BaseModel):
    appeals: List[AppealResponse]
    total: int


class AppealResolveRequest(BaseModel):
    accepted: bool
    reviewer_notes: str = Field(..., min_length=10)
    reviewer_id: str = Field(..., min_length=1)
    mediator_recommendation: Optional[str] = None


class AppealMetricsResponse(BaseModel):
    appeals_submitted: int
    appeals_accepted: int
    appeals_rejected: int
    sla_violations: int
    pending_appeals: int
    sla_compliance_rate: float
    appeal_success_rate: float


class RiskClassifyRequest(BaseModel):
    agent_id: str
    sector: str
    capabilities: List[str] = []
    deployment_context: dict[str, object] = {}


# ═══════════════════════════════════════════════════════════════
# MODELS — Compliance & Intelligence
# ═══════════════════════════════════════════════════════════════

class ComplianceRequest(BaseModel):
    framework: str
    evidence: dict[str, object] = {}
    verdict: dict[str, object] = {}


class ThreatIngestRequest(BaseModel):
    id: str
    threat_type: str
    severity: int
    source: str = "manual"
    indicators: List[str] = []
    description: str = ""
    mitre_id: str = ""


class ThreatQueryRequest(BaseModel):
    threat_type: Optional[str] = None
    min_severity: int = 0
    source: Optional[str] = None
    limit: int = 50


class FRIARequest(BaseModel):
    agent_id: str
    sector: str
    capabilities: List[str] = []
    deployment_context: dict[str, object] = {}


# ═══════════════════════════════════════════════════════════════
# MODELS — Compliance-as-Code (ADR-048: ROPA, Art.20, Export)
# ═══════════════════════════════════════════════════════════════

class ROPARequest(BaseModel):
    controller: str = "Not specified"
    dpo_name: str = "Not specified"
    dpo_contact: str = "Not specified"
    start_ts: Optional[int] = None
    end_ts: Optional[int] = None


class Art20Request(BaseModel):
    start_ts: Optional[int] = None
    end_ts: Optional[int] = None
    include_decisions: bool = True
    max_decisions: int = 500


class DocumentExportRequest(BaseModel):
    type: str = ""           # ropa | fria | art20
    data: dict[str, object] = {}
    format: str = "json"     # json | pdf
