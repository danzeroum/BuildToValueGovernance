"""
Mercy Algorithm - Misericordia Algoritmica (Carol Gilligan).
Implementa abrandamento contextual de decisoes.
"""
from dataclasses import dataclass
from typing import Optional
import math

from .ffi_client import TechnicalEvidence
from .types import RequestMetadata


@dataclass
class MercyFactors:
    """
    Fatores que contribuem para misericordia.
    """
    uncertainty_score: float
    context_justifiability: float
    trust_score: float
    harm_potential: float
    first_offense: bool

    def __repr__(self):
        return (
            f"MercyFactors("
            f"uncertainty={self.uncertainty_score:.2f}, "
            f"justifiability={self.context_justifiability:.2f}, "
            f"trust={self.trust_score:.2f}, "
            f"harm={self.harm_potential:.2f}, "
            f"first_offense={self.first_offense})"
        )


class MercyCalculator:
    """
    Implementa Misericordia Algoritmica baseada em Carol Gilligan.

    Principios:
    1. Contexto > Regra: Decisoes devem considerar circunstancias especificas
    2. Cuidado: Priorizar continuidade do servico quando possivel
    3. Relacionamento: Historico do usuario importa
    4. Incerteza: Quando nao temos certeza, erramos para o lado da permissividade

    Formula de Misericordia:
    mercy_score = w1*uncertainty + w2*justifiability + w3*trust + w4*(1-harm) + w5*first_offense
    """

    def __init__(self):
        self.weights = {
            'uncertainty': 0.30,
            'justifiability': 0.25,
            'trust': 0.20,
            'harm': 0.15,
            'first_offense': 0.10
        }
        self._violation_history = {}

    def calculate(
            self,
            evidence: TechnicalEvidence,
            context: dict,
            trust_score: float
    ) -> float:
        """
        Calcula mercy score (0.0 a 1.0).
        Chama _extract_factors() + _calculate_score() em uma unica passagem.
        """
        factors = self._extract_factors(evidence, context, trust_score)
        return self._calculate_score(factors)

    def calculate_with_factors(
            self,
            evidence: TechnicalEvidence,
            context: dict,
            trust_score: float
    ) -> tuple:
        """
        Retorna (mercy_score, MercyFactors) em uma unica passagem.

        Invariante critico: _extract_factors() e chamado APENAS UMA VEZ.
        _is_first_offense() incrementa _violation_history por chamada;
        chamar _extract_factors() duas vezes resultaria em first_offense=False
        na segunda chamada — bug de double-call corrigido aqui.

        Uso obrigatorio em GilliganStage.evaluate() e qualquer codigo
        que precise de (score, factors) simultaneamente.
        """
        factors = self._extract_factors(evidence, context, trust_score)
        score = self._calculate_score(factors)
        return score, factors

    def _calculate_score(self, factors: MercyFactors) -> float:
        """
        Formula ponderada isolada. Sem efeitos colaterais.
        Permite reutilizacao sem re-executar _extract_factors.
        """
        mercy_score = (
            self.weights['uncertainty'] * factors.uncertainty_score
            + self.weights['justifiability'] * factors.context_justifiability
            + self.weights['trust'] * factors.trust_score
            + self.weights['harm'] * (1.0 - factors.harm_potential)
            + self.weights['first_offense'] * (1.0 if factors.first_offense else 0.0)
        )
        return max(0.0, min(1.0, mercy_score))

    def _extract_factors(
            self,
            evidence: TechnicalEvidence,
            context: dict,
            trust_score: float
    ) -> MercyFactors:
        """
        Extrai fatores de misericordia da evidencia + contexto.
        ATENCAO: tem efeito colateral em _violation_history via _is_first_offense.
        Chamar apenas uma vez por request.
        """
        avg_confidence = self._calculate_avg_confidence(evidence)
        uncertainty_score = 1.0 - avg_confidence
        domain = context.get('domain', 'general')
        justifiability = self._get_domain_justifiability(domain)
        trust = trust_score
        harm_potential = self._calculate_harm_potential(evidence)
        session_id = context.get('session_id', 'unknown')
        first_offense = self._is_first_offense(session_id)

        return MercyFactors(
            uncertainty_score=uncertainty_score,
            context_justifiability=justifiability,
            trust_score=trust,
            harm_potential=harm_potential,
            first_offense=first_offense
        )

    def _calculate_avg_confidence(self, evidence: TechnicalEvidence) -> float:
        all_findings = evidence.findings + evidence.critical
        if not all_findings:
            return 0.5
        total_confidence = sum(f.confidence for f in all_findings)
        return total_confidence / len(all_findings)

    def _get_domain_justifiability(self, domain: str) -> float:
        domain_scores = {
            'development': 0.9,
            'testing': 0.8,
            'general': 0.6,
            'education': 0.5,
            'healthcare': 0.3,
            'finance': 0.2,
            'legal': 0.2
        }
        return domain_scores.get(domain, 0.5)

    def _calculate_harm_potential(self, evidence: TechnicalEvidence) -> float:
        harm = 0.0
        if evidence.critical_count > 0:
            harm += 0.4
        if evidence.stats.has_pii:
            harm += 0.3
        if evidence.composite_risk >= 80:
            harm += 0.3
        elif evidence.composite_risk >= 60:
            harm += 0.2
        elif evidence.composite_risk >= 30:
            harm += 0.1
        return min(1.0, harm)

    def _is_first_offense(self, session_id: str) -> bool:
        """
        Verifica se e primeira violacao da sessao.
        Efeito colateral: incrementa _violation_history[session_id].
        Chamar apenas uma vez por request via calculate_with_factors().
        """
        count = self._violation_history.get(session_id, 0)
        self._violation_history[session_id] = count + 1
        return count == 0

    def explain(self, mercy_score: float, factors: MercyFactors) -> str:
        lines = [
            f"Mercy Score: {mercy_score:.2f}",
            "",
            "Fatores considerados:",
            f"  * Incerteza: {factors.uncertainty_score:.2f} (peso: {self.weights['uncertainty']:.0%})",
            f"  * Justificabilidade: {factors.context_justifiability:.2f} (peso: {self.weights['justifiability']:.0%})",
            f"  * Confianca: {factors.trust_score:.2f} (peso: {self.weights['trust']:.0%})",
            f"  * Dano potencial: {factors.harm_potential:.2f} (peso: {self.weights['harm']:.0%})",
            f"  * Primeira violacao: {'Sim' if factors.first_offense else 'Nao'} (peso: {self.weights['first_offense']:.0%})",
        ]
        if mercy_score >= 0.8:
            lines.append("\n-> FORTE CANDIDATO A MISERICORDIA (abrandar acao)")
        elif mercy_score >= 0.5:
            lines.append("\n-> Considerar abrandamento contextual")
        else:
            lines.append("\n-> Aplicar acao conforme regra")
        return "\n".join(lines)
