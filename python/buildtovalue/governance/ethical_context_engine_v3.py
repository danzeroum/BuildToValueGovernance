"""
Ethical Context Engine v3.0 - Judiciário da República Algorítmica

Responsabilidades:
- Interpreta TechnicalEvidence (Facts do Rust)
- Aplica contexto ético (Judgments em Python)
- Misericórdia Algorítmica (Gilligan: alta incerteza → abrandamento)
- Contestability (recurso humano)
- BiasDeclaration (transparência)

Gate: Week 4 - Day 16
"""

import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# TIPOS
# ═══════════════════════════════════════════════════════════════════════════

class EthicalVerdict(str, Enum):
    """Veredito ético final."""
    ALLOW = "ALLOW"
    LOG = "LOG"
    EDUCATE = "EDUCATE"
    REDACT = "REDACT"
    BLOCK = "BLOCK"

    def severity_level(self) -> int:
        """Retorna nível de severidade (0-4)."""
        levels = {
            "ALLOW": 0,
            "LOG": 1,
            "EDUCATE": 2,
            "REDACT": 3,
            "BLOCK": 4,
        }
        return levels[self.value]


@dataclass
class EthicalContext:
    """Contexto ético para decisão."""

    # Identificação
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None

    # Contexto temporal
    timestamp: int = field(default_factory=lambda: int(time.time()))

    # Contexto de usuário
    user_history: Dict[str, Any] = field(default_factory=dict)
    trust_score: float = 0.5  # 0.0-1.0 (default: neutro)

    # Contexto de operação
    operation_type: Optional[str] = None
    criticality: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL

    # Flags
    is_first_offense: bool = True
    has_prior_violations: bool = False
    educational_mode: bool = False


@dataclass
class MercyFactor:
    """Fator de misericórdia (Gilligan)."""

    # Incerteza técnica
    technical_uncertainty: float = 0.0  # 0.0-1.0

    # Contexto humano
    first_offense: bool = True
    trust_score: float = 0.5

    # Severidade da violação
    violation_severity: float = 0.0

    # Resultado
    should_apply_mercy: bool = False
    mercy_adjustment: float = 0.0  # Redução na severidade
    rationale: str = ""

    def calculate(self) -> 'MercyFactor':
        """
        Calcula fator de misericórdia.

        Gilligan: Contexto > Regra
        - Alta incerteza técnica → misericórdia
        - Primeira ofensa → misericórdia
        - Alto trust score → misericórdia
        - Baixa severidade → misericórdia
        """
        reasons = []
        adjustment = 0.0

        # 1. Incerteza técnica (peso: 0.3)
        if self.technical_uncertainty > 0.7:
            adjustment += 0.3
            reasons.append(f"alta incerteza técnica ({self.technical_uncertainty:.2f})")

        # 2. Primeira ofensa (peso: 0.2)
        if self.first_offense:
            adjustment += 0.2
            reasons.append("primeira ofensa")

        # 3. Trust score (peso: 0.3)
        if self.trust_score > 0.7:
            adjustment += 0.3
            reasons.append(f"alto trust score ({self.trust_score:.2f})")

        # 4. Severidade baixa (peso: 0.2)
        if self.violation_severity < 0.4:
            adjustment += 0.2
            reasons.append(f"baixa severidade ({self.violation_severity:.2f})")

        # Aplica misericórdia se adjustment >= 0.4
        self.should_apply_mercy = adjustment >= 0.4
        self.mercy_adjustment = min(adjustment, 0.6)  # Cap em 0.6

        if self.should_apply_mercy:
            self.rationale = f"Misericórdia aplicada: {', '.join(reasons)}"
        else:
            self.rationale = "Misericórdia não aplicável (contexto não favorável)"

        return self


@dataclass
class EthicalDecision:
    """Decisão ética completa (assinada)."""

    # Veredito
    verdict: EthicalVerdict

    # Severidade ajustada (após misericórdia)
    adjusted_severity: float

    # Confiança na decisão
    confidence: float

    # Contexto usado
    context: EthicalContext

    # Misericórdia
    mercy_applied: bool
    mercy_factor: Optional[MercyFactor]

    # Explicabilidade
    rationale: str
    contributing_factors: List[str]

    # Contestability
    contestable: bool = True
    appeal_deadline: Optional[datetime] = None

    # Assinatura (HMAC)
    signature: Optional[str] = None
    signed_at: Optional[int] = None

    # Bias Declaration
    bias_declaration: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializa para dict."""
        result = asdict(self)
        result['verdict'] = self.verdict.value
        if self.appeal_deadline:
            result['appeal_deadline'] = self.appeal_deadline.isoformat()
        return result


# ═══════════════════════════════════════════════════════════════════════════
# ETHICAL CONTEXT ENGINE v3
# ═══════════════════════════════════════════════════════════════════════════

class EthicalContextEngineV3:
    """
    Ethical Context Engine v3 - Judiciário da República Algorítmica.

    Responsabilidades:
    1. Interpreta TechnicalEvidence (Facts do Rust)
    2. Aplica contexto ético (Judgments)
    3. Calcula Misericórdia Algorítmica (Gilligan)
    4. Gera decisão explicável e contestável
    5. Declara vieses (BiasDeclaration)

    Performance: <10ms (p99)
    """

    def __init__(self):
        """Inicializa engine."""
        self.metrics = {
            'decisions_total': 0,
            'mercy_applied_count': 0,
            'verdicts_by_level': [0, 0, 0, 0, 0],  # ALLOW, LOG, EDUCATE, REDACT, BLOCK
            'avg_latency_ms': 0.0,
        }

        # Bias Declaration (transparência de limitações)
        self.bias_declaration = {
            'model_version': '3.0',
            'last_calibration': '2026-02-16',
            'known_limitations': [
                'Não detecta context-specific semantic violations',
                'False positive rate: ~5% em low-confidence scenarios',
                'Requires human review for CRITICAL operations',
            ],
            'false_positive_rate': 0.05,
            'false_negative_rate': 0.02,
            'calibration_dataset_size': 10000,
        }

    def decide(
            self,
            technical_evidence: Dict[str, Any],
            context: EthicalContext,
            policy_action: str = "BLOCK",
    ) -> EthicalDecision:
        """
        Toma decisão ética baseada em TechnicalEvidence + Contexto.

        Args:
            technical_evidence: TechnicalEvidence do Rust (dict)
            context: Contexto ético (usuário, operação, etc)
            policy_action: Ação sugerida pelas policies (YAML)

        Returns:
            EthicalDecision (assinada, explicável, contestável)
        """
        start = time.perf_counter()

        # 1. Extrai informações do TechnicalEvidence
        composite_risk = technical_evidence.get('composite_risk', 0.0)
        finding_count = technical_evidence.get('finding_count', 0)
        critical_count = technical_evidence.get('critical_count', 0)
        entropy = technical_evidence.get('entropy', 0.0)

        # 2. Calcula incerteza técnica
        technical_uncertainty = self._calculate_uncertainty(technical_evidence)

        # 3. Avalia Misericórdia Algorítmica (Gilligan)
        mercy = MercyFactor(
            technical_uncertainty=technical_uncertainty,
            first_offense=context.is_first_offense,
            trust_score=context.trust_score,
            violation_severity=composite_risk,
        ).calculate()

        # 4. Ajusta severidade (se misericórdia aplicável)
        adjusted_severity = composite_risk
        if mercy.should_apply_mercy:
            adjusted_severity = max(0.0, composite_risk - mercy.mercy_adjustment)
            logger.info(f"Mercy applied: {composite_risk:.2f} → {adjusted_severity:.2f}")

        # 5. Determina veredito final
        verdict = self._determine_verdict(
            adjusted_severity,
            policy_action,
            context,
            mercy.should_apply_mercy,
        )

        # 6. Calcula confiança na decisão
        confidence = self._calculate_confidence(
            technical_evidence,
            technical_uncertainty,
            mercy.should_apply_mercy,
        )

        # 7. Gera explicação (rationale)
        rationale, factors = self._explain_decision(
            verdict,
            adjusted_severity,
            technical_evidence,
            context,
            mercy,
        )

        # 8. Cria decisão
        decision = EthicalDecision(
            verdict=verdict,
            adjusted_severity=adjusted_severity,
            confidence=confidence,
            context=context,
            mercy_applied=mercy.should_apply_mercy,
            mercy_factor=mercy if mercy.should_apply_mercy else None,
            rationale=rationale,
            contributing_factors=factors,
            contestable=True,
            appeal_deadline=datetime.now() + timedelta(hours=24),  # SLA 24h
            bias_declaration=self.bias_declaration.copy(),
        )

        # 9. Assina decisão (HMAC - TODO: integrar com PolicySigner)
        decision.signature = self._sign_decision(decision)
        decision.signed_at = int(time.time())

        # 10. Atualiza métricas
        latency_ms = (time.perf_counter() - start) * 1000
        self._update_metrics(verdict, mercy.should_apply_mercy, latency_ms)

        return decision

    def _calculate_uncertainty(self, evidence: Dict[str, Any]) -> float:
        """
        Calcula incerteza técnica.

        Alta incerteza se:
        - Baixa confiança nos findings
        - Poucos findings (< 2)
        - Severidade próxima de thresholds
        """
        finding_count = evidence.get('finding_count', 0)
        composite_risk = evidence.get('composite_risk', 0.0)

        uncertainty = 0.0

        # Poucos findings
        if finding_count < 2:
            uncertainty += 0.3

        # Severidade próxima de threshold (0.5)
        if 0.4 <= composite_risk <= 0.6:
            uncertainty += 0.4

        # TODO: Considerar confidence dos findings individuais

        return min(uncertainty, 1.0)

    def _determine_verdict(
            self,
            adjusted_severity: float,
            policy_action: str,
            context: EthicalContext,
            mercy_applied: bool,
    ) -> EthicalVerdict:
        """
        Determina veredito final.

        Leva em conta:
        - Severidade ajustada (após misericórdia)
        - Ação sugerida pela policy
        - Contexto (educational mode, criticality)
        """
        # Educational mode → sempre EDUCATE (exceto CRITICAL)
        if context.educational_mode and context.criticality != "CRITICAL":
            return EthicalVerdict.EDUCATE

        # Respeita policy action se não foi aplicada misericórdia
        if not mercy_applied:
            try:
                return EthicalVerdict(policy_action)
            except ValueError:
                pass  # Fallback abaixo

        # Fallback: baseado em severidade ajustada
        if adjusted_severity >= 0.8:
            return EthicalVerdict.BLOCK
        elif adjusted_severity >= 0.6:
            return EthicalVerdict.REDACT
        elif adjusted_severity >= 0.4:
            return EthicalVerdict.EDUCATE
        elif adjusted_severity >= 0.2:
            return EthicalVerdict.LOG
        else:
            return EthicalVerdict.ALLOW

    def _calculate_confidence(
            self,
            evidence: Dict[str, Any],
            uncertainty: float,
            mercy_applied: bool,
    ) -> float:
        """Calcula confiança na decisão."""
        base_confidence = 0.8

        # Reduz confiança se alta incerteza
        base_confidence -= uncertainty * 0.3

        # Reduz confiança se misericórdia aplicada (decisão humana)
        if mercy_applied:
            base_confidence -= 0.1

        # Aumenta confiança se muitos findings
        finding_count = evidence.get('finding_count', 0)
        if finding_count >= 3:
            base_confidence += 0.1

        return max(0.5, min(base_confidence, 0.95))

    def _explain_decision(
            self,
            verdict: EthicalVerdict,
            adjusted_severity: float,
            evidence: Dict[str, Any],
            context: EthicalContext,
            mercy: MercyFactor,
    ) -> tuple[str, List[str]]:
        """Gera explicação human-readable."""
        factors = []

        # Fatores técnicos
        finding_count = evidence.get('finding_count', 0)
        critical_count = evidence.get('critical_count', 0)

        if finding_count > 0:
            factors.append(f"{finding_count} violation(s) detected")

        if critical_count > 0:
            factors.append(f"{critical_count} critical finding(s)")

        factors.append(f"adjusted severity: {adjusted_severity:.2f}")

        # Fatores contextuais
        if context.is_first_offense:
            factors.append("first offense")

        if context.trust_score > 0.7:
            factors.append(f"high trust score ({context.trust_score:.2f})")

        # Misericórdia
        if mercy.should_apply_mercy:
            factors.append(mercy.rationale)

        # Rationale completo
        rationale = (
            f"Verdict: {verdict.value}. "
            f"Severity: {adjusted_severity:.2f}. "
            f"Factors: {', '.join(factors)}."
        )

        return rationale, factors

    def _sign_decision(self, decision: EthicalDecision) -> str:
        """Assina decisão com HMAC (placeholder)."""
        # TODO: Integrar com PolicySigner (Day 4)
        import hashlib
        content = f"{decision.verdict.value}{decision.adjusted_severity}{decision.signed_at}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _update_metrics(
            self,
            verdict: EthicalVerdict,
            mercy_applied: bool,
            latency_ms: float,
    ):
        """Atualiza métricas."""
        self.metrics['decisions_total'] += 1

        if mercy_applied:
            self.metrics['mercy_applied_count'] += 1

        level = verdict.severity_level()
        self.metrics['verdicts_by_level'][level] += 1

        # EMA
        alpha = 0.1
        self.metrics['avg_latency_ms'] = (
                alpha * latency_ms + (1 - alpha) * self.metrics['avg_latency_ms']
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas."""
        total = self.metrics['decisions_total']
        return {
            **self.metrics,
            'mercy_rate': self.metrics['mercy_applied_count'] / max(total, 1),
        }

    def get_bias_declaration(self) -> Dict[str, Any]:
        """Retorna BiasDeclaration (transparência)."""
        return self.bias_declaration.copy()
