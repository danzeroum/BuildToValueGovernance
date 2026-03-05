"""
Gilligan Ethics Stage v1.0.0 — PROP-030 (Care/Focus).

Nó explícito do Judiciary pipeline para ética do cuidado (Carol Gilligan).
Posição: após Jonas, antes de Verdict.

Princípios implementados:
- Contexto > Regra: circunstâncias específicas importam mais que regras abstratas
- Care/Focus: weighted recovery para decisões de bloqueio
- Relacionamento: histórico do usuário (first_offense) é fator de mercy
- Fail-secure: qualquer exceção → bloquear + logar

Obrigatório: explain_decision() em GilliganStageResult.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import logging

from .mercy_algorithm import MercyCalculator, MercyFactors

logger = logging.getLogger(__name__)


@dataclass
class GilliganStageResult:
    """Resultado do estágio Gilligan no pipeline ético."""
    mercy_score: float
    care_focus: str        # "soften" | "maintain" | "block"
    factors: Optional[MercyFactors]
    explanation: str
    passed: bool
    error: Optional[str] = None

    def explain_decision(self) -> str:
        """Obrigatório: explicação auditável da decisão. Conforme ADR-Python."""
        return (
            f"[Gilligan/Care P-030] care_focus={self.care_focus} "
            f"mercy_score={self.mercy_score:.3f} "
            f"passed={self.passed} | {self.explanation}"
        )


class GilliganStage:
    """
    Estágio Gilligan do Judiciary pipeline (PROP-030).

    Integra MercyCalculator como nó formal explícito, expondo
    care_focus e explain_decision() para o Verdict downstream.
    """

    SOFTEN_THRESHOLD: float = 0.65
    MAINTAIN_THRESHOLD: float = 0.35

    def __init__(self, mercy_calculator: Optional[MercyCalculator] = None) -> None:
        self._calc = mercy_calculator or MercyCalculator()

    def evaluate(
        self,
        evidence,  # TechnicalEvidence (evita import circular com ffi_client)
        context: dict,
        trust_score: float = 0.5,
    ) -> GilliganStageResult:
        """
        Avalia evidência com ética do cuidado.

        Args:
            evidence: TechnicalEvidence do kernel Rust
            context:  dict com domain, session_id, etc.
            trust_score: 0.0–1.0 (confiança do solicitante)

        Returns:
            GilliganStageResult com explain_decision() obrigatório.
        """
        try:
            mercy_score = self._calc.calculate(evidence, context, trust_score)
            # _extract_factors é semi-privado por convenção; acesso interno justificado.
            factors = self._calc._extract_factors(evidence, context, trust_score)
            care_focus = self._resolve_care_focus(mercy_score, evidence)
            explanation = self._build_explanation(mercy_score, factors, care_focus)
            return GilliganStageResult(
                mercy_score=mercy_score,
                care_focus=care_focus,
                factors=factors,
                explanation=explanation,
                passed=True,
            )
        except Exception as exc:  # noqa: BLE001 — fail-secure intencional
            logger.error("GilliganStage error — fail-secure BLOCK: %s", exc)
            return GilliganStageResult(
                mercy_score=0.0,
                care_focus="block",
                factors=None,
                explanation="Internal error — fail-secure applied",
                passed=False,
                error=str(exc),
            )

    def _resolve_care_focus(self, mercy_score: float, evidence) -> str:
        """Resolve care_focus baseado em mercy score e critical findings."""
        if getattr(evidence, "critical_count", 0) > 0 and mercy_score < self.SOFTEN_THRESHOLD:
            return "block"
        if mercy_score >= self.SOFTEN_THRESHOLD:
            return "soften"
        if mercy_score >= self.MAINTAIN_THRESHOLD:
            return "maintain"
        return "block"

    def _build_explanation(self, mercy_score: float, factors: MercyFactors, care_focus: str) -> str:
        return " | ".join([
            f"Mercy: {mercy_score:.3f}",
            f"Care Focus: {care_focus}",
            f"Uncertainty: {factors.uncertainty_score:.2f}",
            f"Justifiability: {factors.context_justifiability:.2f}",
            f"Trust: {factors.trust_score:.2f}",
            f"Harm Potential: {factors.harm_potential:.2f}",
            f"First Offense: {factors.first_offense}",
        ])
