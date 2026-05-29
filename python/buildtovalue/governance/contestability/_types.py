"""Tipos do Contestability Loop (ADR-0095) — verdict, appeal e vocabulários.

EthicalVerdict (ADR-0028/0005), Appeal (ADR-017/047) e os vocabulários
controlados de grounds/recomendações. ``Appeal.is_overdue`` é a fonte do
predicado de SLA 24h consumido pelo loop.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Optional

from buildtovalue.security import get_hmac_key

# ─────────────────────────────────────────────────────────────────────────────
# ADR-047: VOCABULÁRIO CONTROLADO DE GROUNDS (frozenset = imutável em runtime)
# ─────────────────────────────────────────────────────────────────────────────
VALID_GROUNDS: frozenset[str] = frozenset({
    "rawls_equity",         # decisão não passaria pelo véu de ignorância
    "levinas_protection",   # falha em proteger o vulnerável
    "gilligan_mercy",       # rigidez sem contexto de cuidado
    "jonas_responsibility", # impacto de longo prazo ignorado
    "technical_error",      # evidência forense incorreta (BLAKE3)
    "scope_mismatch",       # policy aplicada fora do trust_boundary (ADR-045)
    "false_positive",       # validator disparou incorretamente
})

VALID_MEDIATOR_RECOMMENDATIONS: frozenset[str] = frozenset({
    "accept_appeal",
    "reject_appeal",
    "escalate",
    "educate",
})

_HMAC_KEY: bytes = get_hmac_key()


@dataclass
class EthicalVerdict:
    """Verdict final do pipeline de governança.

    ADR-0028: explain_decision() obrigatório — toda decisão deve ser explicável.
    ADR-0005: hmac_signature garante integridade do veredicto.
    CONTEST: enfileira em appeals.db para revisão humana ≤24h SLA (Jonas).
    """
    decision: Literal["ALLOW", "BLOCK", "EDUCATE", "CONTEST"]
    explanation: str
    bias_declaration: str
    finding_count: int = 0
    critical_count: int = 0
    hmac_signature: bytes = field(default_factory=bytes)

    def __post_init__(self) -> None:
        if not self.hmac_signature:
            self.hmac_signature = self._compute_hmac()

    def _compute_hmac(self) -> bytes:
        payload = f"{self.decision}|{self.explanation}|{self.bias_declaration}".encode()
        return hmac.new(_HMAC_KEY, payload, hashlib.sha256).digest()

    def verify(self) -> bool:
        return hmac.compare_digest(self.hmac_signature, self._compute_hmac())

    def explain_decision(self) -> str:
        """Return human-readable explanation (ADR-0028 mandatory)."""
        return (
            f"Decision: {self.decision}\n"
            f"Findings: {self.finding_count} total, {self.critical_count} critical\n"
            f"Bias: {self.bias_declaration}\n"
            f"Reason: {self.explanation}"
        )


def _derive_decision(
    finding_count: int, critical_count: int
) -> Literal["ALLOW", "BLOCK", "EDUCATE", "CONTEST"]:
    if critical_count > 0:
        return "BLOCK"
    if finding_count > 0:
        return "EDUCATE"
    return "ALLOW"


def _summarize_bias(fpr: float, fnr: float) -> str:
    return f"FPR={fpr:.1%} FNR={fnr:.1%}"


def _build_explanation(decision: str, finding_count: int, critical_count: int) -> str:
    if decision == "BLOCK":
        return f"Blocked: {critical_count} critical finding(s) detected"
    if decision == "EDUCATE":
        return f"Flagged: {finding_count} finding(s) requiring review"
    return "No policy violations detected"


def build_verdict(
    finding_count: int,
    critical_count: int,
    fpr: float = 0.0,
    fnr: float = 0.0,
) -> EthicalVerdict:
    """Build and sign an EthicalVerdict from scan results (ADR-0028/ADR-0005)."""
    decision = _derive_decision(finding_count, critical_count)
    explanation = _build_explanation(decision, finding_count, critical_count)
    bias_declaration = _summarize_bias(fpr, fnr)
    return EthicalVerdict(
        decision=decision,
        explanation=explanation,
        bias_declaration=bias_declaration,
        finding_count=finding_count,
        critical_count=critical_count,
    )


# ─────────────────────────────────────────────────────────────────────────────
# APPEAL TYPES
# ─────────────────────────────────────────────────────────────────────────────

class AppealStatus(Enum):
    """Status de recurso."""
    PENDING      = "pending"
    UNDER_REVIEW = "under_review"
    ACCEPTED     = "accepted"
    REJECTED     = "rejected"
    EXPIRED      = "expired"


@dataclass
class Appeal:
    """Recurso de usuário — imutável após criação exceto campos de resolução.

    Invariante: reason >= 20 chars (Levinas — contestação pressupõe
    articulação mínima). ADR-047: campos opcionais para mediação estruturada.
    """
    appeal_id: str
    audit_trail_id: int
    user_id: str
    timestamp: int
    reason: str
    evidence_provided: Optional[str] = None

    # Resolução
    status: AppealStatus = AppealStatus.PENDING
    reviewer_notes: Optional[str] = None
    resolution_timestamp: Optional[int] = None

    # SLA
    sla_deadline: int = 0

    # ADR-047: Structured Mediation fields (opcionais, retrocompatível)
    evidence_hash: Optional[str] = None
    grounds: list[str] = field(default_factory=list)
    mediator_recommendation: Optional[str] = None

    def __post_init__(self) -> None:
        if self.sla_deadline == 0:
            self.sla_deadline = self.timestamp + (24 * 3600)

    def is_overdue(self) -> bool:
        return (
            int(time.time()) > self.sla_deadline
            and self.status == AppealStatus.PENDING
        )

    def validated_grounds(self) -> list[str]:
        """Retorna apenas grounds do vocabulário controlado (VALID_GROUNDS).
        Não lança exceção para grounds inválidos — os ignora silenciosamente.
        """
        return [g for g in self.grounds if g in VALID_GROUNDS]
