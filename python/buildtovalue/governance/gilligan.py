"""
Gilligan Ethics Stage v1.1.0 — PROP-030 (Care/Focus).

Changelog:
  v1.0.0: implementacao inicial
  v1.1.0 (Sprint 5): corrige double-call de _extract_factors().
    evaluate() usava calculate() + _extract_factors() separadamente,
    incrementando _violation_history 2x por request.
    Fix: usa calculate_with_factors() (unica passagem, sem efeito colateral duplo).

No explicito do Judiciary pipeline para etica do cuidado (Carol Gilligan).
Posicao: apos Jonas, antes de Verdict.

Principios implementados:
- Contexto > Regra: circunstancias especificas importam mais que regras abstratas
- Care/Focus: weighted recovery para decisoes de bloqueio
- Relacionamento: historico do usuario (first_offense) e fator de mercy
- Fail-secure: qualquer excecao -> bloquear + logar

Obrigatorio: explain_decision() em GilliganStageResult.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import logging

from .mercy_algorithm import MercyCalculator, MercyFactors

logger = logging.getLogger(__name__)


@dataclass
class GilliganStageResult:
    """Resultado do estagio Gilligan no pipeline etico."""
    mercy_score: float
    care_focus: str
    factors: Optional[MercyFactors]
    explanation: str
    passed: bool
    error: Optional[str] = None

    def explain_decision(self) -> str:
        """Obrigatorio: explicacao auditavel da decisao. Conforme ADR-Python."""
        return (
            f"[Gilligan/Care P-030] care_focus={self.care_focus} "
            f"mercy_score={self.mercy_score:.3f} "
            f"passed={self.passed} | {self.explanation}"
        )


class GilliganStage:
    """
    Estagio Gilligan do Judiciary pipeline (PROP-030).

    Integra MercyCalculator como no formal explicito, expondo
    care_focus e explain_decision() para o Verdict downstream.
    """

    SOFTEN_THRESHOLD: float = 0.65
    MAINTAIN_THRESHOLD: float = 0.35

    def __init__(self, mercy_calculator: Optional[MercyCalculator] = None) -> None:
        self._calc = mercy_calculator or MercyCalculator()

    def evaluate(
        self,
        evidence,
        context: dict,
        trust_score: float = 0.5,
    ) -> GilliganStageResult:
        """
        Avalia evidencia com etica do cuidado.

        Usa calculate_with_factors() para obter (score, factors) em
        uma unica passagem — evita o bug de double-call onde
        _is_first_offense() incrementava _violation_history 2x.
        """
        try:
            mercy_score, factors = self._calc.calculate_with_factors(
                evidence, context, trust_score
            )
            care_focus = self._resolve_care_focus(mercy_score, evidence)
            explanation = self._build_explanation(mercy_score, factors, care_focus)
            return GilliganStageResult(
                mercy_score=mercy_score,
                care_focus=care_focus,
                factors=factors,
                explanation=explanation,
                passed=True,
            )
        except Exception as exc:
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
