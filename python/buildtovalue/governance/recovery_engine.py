"""
RecoveryEngine — PROP-030 (Python Governance / Judiciário).

Determina estratégia de recuperação após BLOCK emitido pelo Rust Kernel.
Integra MercyCalculator + contestabilidade SLA-24h.

Fundamentos: Gilligan (cuidado), Jonas (responsabilidade), Rawls (equidade).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional

from .ffi_client import TechnicalEvidence
from .mercy_algorithm import MercyCalculator
from .types import RequestMetadata

# ─────────────────────────────────────────────────────────────────────────────
# THRESHOLDS
# ─────────────────────────────────────────────────────────────────────────────

_MERCY_ALLOW_THRESHOLD    = 0.75
_MERCY_DEGRADE_THRESHOLD  = 0.45
_MERCY_REDIRECT_THRESHOLD = 0.25
_QUARANTINE_VIOLATIONS    = 3
_SLA_HOURS                = 24


# ─────────────────────────────────────────────────────────────────────────────
# STRATEGY ENUM
# ─────────────────────────────────────────────────────────────────────────────

class RecoveryStrategy(str, Enum):
    """Estratégias pós-BLOCK ordenadas por severidade crescente."""
    ALLOW_WITH_AUDIT   = "ALLOW_WITH_AUDIT"
    DEGRADE_GRACEFUL   = "DEGRADE_GRACEFUL"
    REDIRECT_HUMAN     = "REDIRECT_HUMAN"
    QUARANTINE_SESSION = "QUARANTINE_SESSION"
    MAINTAIN_BLOCK     = "MAINTAIN_BLOCK"


# ─────────────────────────────────────────────────────────────────────────────
# OUTCOME
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RecoveryOutcome:
    """
    Resultado imutável do RecoveryEngine.

    explain_decision é OBRIGATÓRIO (invariante arquitetural).
    signature é HMAC-SHA256 sobre payload canônico.
    contestable + sla_deadline_iso: suporte SLA-24h (Rawls).
    """
    strategy: RecoveryStrategy
    explain_decision: str
    mercy_score: float
    contestable: bool
    sla_deadline_iso: str
    session_id: str
    request_id: str
    decided_at_iso: str
    signature: str
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "strategy":        self.strategy.value,
            "explain_decision": self.explain_decision,
            "mercy_score":     round(self.mercy_score, 4),
            "contestable":     self.contestable,
            "sla_deadline_iso": self.sla_deadline_iso,
            "session_id":      self.session_id,
            "request_id":      self.request_id,
            "decided_at_iso":  self.decided_at_iso,
            "signature":       self.signature,
            "metadata":        self.metadata,
        }


# ─────────────────────────────────────────────────────────────────────────────
# ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class RecoveryEngine:
    """
    Determina estratégia de recuperação pós-BLOCK.

    Fail-secure: qualquer exceção interna → MAINTAIN_BLOCK assinado.
    """

    def __init__(self, hmac_secret: bytes) -> None:
        if not hmac_secret:
            raise ValueError("hmac_secret não pode ser vazio")
        self._secret: bytes = hmac_secret
        self._mercy = MercyCalculator()
        self._violation_counts: dict[str, int] = {}

    # ── Public ──────────────────────────────────────────────────────────────

    def evaluate(
        self,
        evidence: TechnicalEvidence,
        metadata: RequestMetadata,
        trust_score: float,
        context: dict[str, str],
    ) -> RecoveryOutcome:
        """Avalia evidência pós-BLOCK. Fail-secure: erro → MAINTAIN_BLOCK."""
        try:
            return self._evaluate_internal(evidence, metadata, trust_score, context)
        except Exception as exc:  # noqa: BLE001 — fail-secure intencionais
            return self._fail_secure(metadata, str(exc))

    # ── Internal ─────────────────────────────────────────────────────────────

    def _evaluate_internal(
        self,
        evidence: TechnicalEvidence,
        metadata: RequestMetadata,
        trust_score: float,
        context: dict[str, str],
    ) -> RecoveryOutcome:
        ctx = {**context, "session_id": metadata.session_id}
        mercy_score = self._mercy.calculate(evidence, ctx, trust_score)
        strategy    = self._select_strategy(evidence, mercy_score, metadata.session_id)
        explain     = self._build_explain(strategy, mercy_score, evidence, ctx)
        now         = datetime.now(timezone.utc)
        sla         = (now + timedelta(hours=_SLA_HOURS)).isoformat()
        contestable = (strategy != RecoveryStrategy.MAINTAIN_BLOCK)
        payload     = self._canonical_payload(
            strategy, mercy_score,
            metadata.session_id, metadata.request_id, now.isoformat(),
        )
        return RecoveryOutcome(
            strategy=strategy,
            explain_decision=explain,
            mercy_score=mercy_score,
            contestable=contestable,
            sla_deadline_iso=sla,
            session_id=metadata.session_id,
            request_id=metadata.request_id,
            decided_at_iso=now.isoformat(),
            signature=self._sign(payload),
            metadata={"domain": ctx.get("domain", "general")},
        )

    def _select_strategy(
        self,
        evidence: TechnicalEvidence,
        mercy_score: float,
        session_id: str,
    ) -> RecoveryStrategy:
        violations = self._increment_violations(session_id)

        if evidence.critical_count > 0 and evidence.composite_risk >= 80:
            return RecoveryStrategy.MAINTAIN_BLOCK

        if violations >= _QUARANTINE_VIOLATIONS:
            return RecoveryStrategy.QUARANTINE_SESSION

        if mercy_score >= _MERCY_ALLOW_THRESHOLD:
            return RecoveryStrategy.ALLOW_WITH_AUDIT

        if mercy_score >= _MERCY_DEGRADE_THRESHOLD:
            return RecoveryStrategy.DEGRADE_GRACEFUL

        if mercy_score >= _MERCY_REDIRECT_THRESHOLD:
            return RecoveryStrategy.REDIRECT_HUMAN

        return RecoveryStrategy.MAINTAIN_BLOCK

    def _increment_violations(self, session_id: str) -> int:
        count = self._violation_counts.get(session_id, 0) + 1
        self._violation_counts[session_id] = count
        return count

    def _build_explain(
        self,
        strategy: RecoveryStrategy,
        mercy_score: float,
        evidence: TechnicalEvidence,
        context: dict[str, str],
    ) -> str:
        domain     = context.get("domain", "general")
        violations = self._violation_counts.get(context.get("session_id", ""), 0)
        lines = [
            f"[RecoveryEngine] estratégia={strategy.value}",
            f"  mercy_score={mercy_score:.3f}  risk={evidence.composite_risk}"
            f"  criticals={evidence.critical_count}  pii={evidence.stats.has_pii}",
            f"  domain={domain}  violations_session={violations}",
            "",
            _RATIONALE[strategy].format(
                mercy_score=mercy_score,
                violations=violations,
            ),
            "",
            f"Contestação: /api/v1/contestation  (SLA {_SLA_HOURS}h — Rawls).",
        ]
        return "\n".join(lines)

    def _canonical_payload(
        self,
        strategy: RecoveryStrategy,
        mercy_score: float,
        session_id: str,
        request_id: str,
        decided_at: str,
    ) -> bytes:
        obj = {
            "decided_at":  decided_at,
            "mercy_score": round(mercy_score, 4),
            "request_id":  request_id,
            "session_id":  session_id,
            "strategy":    strategy.value,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    def _sign(self, payload: bytes) -> str:
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def _fail_secure(
        self, metadata: RequestMetadata, error: str
    ) -> RecoveryOutcome:
        now = datetime.now(timezone.utc)
        sla = (now + timedelta(hours=_SLA_HOURS)).isoformat()
        explain = (
            "[RecoveryEngine] FAIL-SECURE ativado.\n"
            f"  erro interno: {error}\n"
            "  estratégia padrão: MAINTAIN_BLOCK (Jonas: responsabilidade).\n"
            f"  Contestação disponível (SLA {_SLA_HOURS}h)."
        )
        payload = self._canonical_payload(
            RecoveryStrategy.MAINTAIN_BLOCK, 0.0,
            metadata.session_id, metadata.request_id, now.isoformat(),
        )
        return RecoveryOutcome(
            strategy=RecoveryStrategy.MAINTAIN_BLOCK,
            explain_decision=explain,
            mercy_score=0.0,
            contestable=True,   # erro do sistema → sempre contestável (Rawls)
            sla_deadline_iso=sla,
            session_id=metadata.session_id,
            request_id=metadata.request_id,
            decided_at_iso=now.isoformat(),
            signature=self._sign(payload),
        )


# ─────────────────────────────────────────────────────────────────────────────
# RATIONALE STRINGS (separados para manter funções ≤50 linhas)
# ─────────────────────────────────────────────────────────────────────────────

_RATIONALE: dict[RecoveryStrategy, str] = {
    RecoveryStrategy.ALLOW_WITH_AUDIT: (
        "Mercy alta ({mercy_score:.2f} ≥ "
        f"{_MERCY_ALLOW_THRESHOLD}). "
        "Dano potencial baixo. Permitido com auditoria completa."
    ),
    RecoveryStrategy.DEGRADE_GRACEFUL: (
        "Mercy moderada ({mercy_score:.2f}). "
        "Resposta degradada: dados sensíveis removidos, operação parcial."
    ),
    RecoveryStrategy.REDIRECT_HUMAN: (
        "Mercy insuficiente ({mercy_score:.2f} < "
        f"{_MERCY_DEGRADE_THRESHOLD}). "
        "Complexidade requer supervisão humana."
    ),
    RecoveryStrategy.QUARANTINE_SESSION: (
        "Sessão com {{violations}} violações (limite={lim}). "
        "Quarentena ativada (Jonas: responsabilidade).".format(
            lim=_QUARANTINE_VIOLATIONS
        )
    ),
    RecoveryStrategy.MAINTAIN_BLOCK: (
        "Risco crítico confirmado ou mercy insuficiente. "
        "BLOCK mantido (Jonas: responsabilidade > eficiência)."
    ),
}
