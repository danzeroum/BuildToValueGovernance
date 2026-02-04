"""
Mercy Algorithm - Misericórdia Algorítmica (Carol Gilligan).
Implementa abrandamento contextual de decisões.
"""
from dataclasses import dataclass
from typing import Optional
import math

from .ffi_client import TechnicalEvidence
from .ethical_context_engine import RequestMetadata


@dataclass
class MercyFactors:
    """
    Fatores que contribuem para misericórdia.
    """
    uncertainty_score: float  # 0.0-1.0 (alta incerteza = mais mercy)
    context_justifiability: float  # 0.0-1.0 (contexto justifica = mais mercy)
    trust_score: float  # 0.0-1.0 (alta confiança = mais mercy)
    harm_potential: float  # 0.0-1.0 (baixo potencial de dano = mais mercy)
    first_offense: bool  # True se primeira violação = mais mercy

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
    Implementa Misericórdia Algorítmica baseada em Carol Gilligan.

    Princípios:
    1. Contexto > Regra: Decisões devem considerar circunstâncias específicas
    2. Cuidado: Priorizar continuidade do serviço quando possível
    3. Relacionamento: Histórico do usuário importa
    4. Incerteza: Quando não temos certeza, erramos para o lado da permissividade

    Fórmula de Misericórdia:
    mercy_score = w1*uncertainty + w2*justifiability + w3*trust + w4*(1-harm) + w5*first_offense

    onde:
    - w1, w2, w3, w4, w5 são pesos (soma = 1.0)
    - mercy_score ≥ 0.5: Considera abrandar ação
    - mercy_score ≥ 0.8: Forte candidato a misericórdia
    """

    def __init__(self):
        """
        Inicializa calculador com pesos padrão.

        Pesos calibrados empiricamente:
        - uncertainty: 0.30 (mais importante)
        - justifiability: 0.25
        - trust: 0.20
        - harm: 0.15
        - first_offense: 0.10
        """
        self.weights = {
            'uncertainty': 0.30,
            'justifiability': 0.25,
            'trust': 0.20,
            'harm': 0.15,
            'first_offense': 0.10
        }

        # Histórico de violações (session_id -> count)
        # Em prod: usar Redis/DB
        self._violation_history = {}

    def calculate(
            self,
            evidence: TechnicalEvidence,
            context: dict,
            trust_score: float
    ) -> float:
        """
        Calcula mercy score (0.0 a 1.0).

        Args:
            evidence: Evidências técnicas do Rust
            context: Contexto da requisição (dict com domain, session_id, etc.)
            trust_score: Trust score do usuário (0.0-1.0)

        Returns:
            Mercy score (0.0 = sem misericórdia, 1.0 = máxima misericórdia)
        """
        factors = self._extract_factors(evidence, context, trust_score)

        # Aplica fórmula ponderada
        mercy_score = (
                self.weights['uncertainty'] * factors.uncertainty_score +
                self.weights['justifiability'] * factors.context_justifiability +
                self.weights['trust'] * factors.trust_score +
                self.weights['harm'] * (1.0 - factors.harm_potential) +
                self.weights['first_offense'] * (1.0 if factors.first_offense else 0.0)
        )

        # Clamp [0.0, 1.0]
        return max(0.0, min(1.0, mercy_score))

    def _extract_factors(
            self,
            evidence: TechnicalEvidence,
            context: dict,
            trust_score: float
    ) -> MercyFactors:
        """
        Extrai fatores de misericórdia da evidência + contexto.
        """
        # 1. Uncertainty Score
        # Alta quando findings têm baixa confidence
        avg_confidence = self._calculate_avg_confidence(evidence)
        uncertainty_score = 1.0 - avg_confidence

        # 2. Context Justifiability
        # Alta quando domínio permite mais flexibilidade
        domain = context.get('domain', 'general')
        justifiability = self._get_domain_justifiability(domain)

        # 3. Trust Score (já fornecido)
        trust = trust_score

        # 4. Harm Potential
        # Alta quando há findings críticos ou PII exposto
        harm_potential = self._calculate_harm_potential(evidence)

        # 5. First Offense
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
        """
        Calcula confiança média dos findings.

        Returns:
            0.0-1.0 (média de confidence dos findings)
        """
        all_findings = evidence.findings + evidence.critical
        if not all_findings:
            return 0.5  # Neutro se sem findings

        total_confidence = sum(f.confidence for f in all_findings)
        return total_confidence / len(all_findings)

    def _get_domain_justifiability(self, domain: str) -> float:
        """
        Retorna justifiability do domínio.

        Domínios mais flexíveis têm maior justifiability:
        - development: 0.9 (alta)
        - general: 0.6 (média)
        - healthcare: 0.3 (baixa - mais restritivo)
        - finance: 0.2 (muito baixa - mais restritivo)
        """
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
        """
        Calcula potencial de dano baseado em evidências.

        Alto harm potential se:
        - Findings críticos presentes
        - PII detectado
        - Risk score alto

        Returns:
            0.0-1.0 (0 = sem dano, 1 = alto dano)
        """
        harm = 0.0

        # Findings críticos
        if evidence.critical_count > 0:
            harm += 0.4

        # PII detectado
        if evidence.stats.has_pii:
            harm += 0.3

        # Risk score alto
        if evidence.composite_risk >= 80:
            harm += 0.3
        elif evidence.composite_risk >= 60:
            harm += 0.2
        elif evidence.composite_risk >= 30:
            harm += 0.1

        return min(1.0, harm)

    def _is_first_offense(self, session_id: str) -> bool:
        """
        Verifica se é primeira violação da sessão.

        Em prod: consultar Redis/DB
        """
        count = self._violation_history.get(session_id, 0)
        self._violation_history[session_id] = count + 1
        return count == 0

    def explain(self, mercy_score: float, factors: MercyFactors) -> str:
        """
        Gera explicação human-readable do mercy score.

        Args:
            mercy_score: Score calculado
            factors: Fatores usados no cálculo

        Returns:
            String explicativa
        """
        lines = [
            f"Mercy Score: {mercy_score:.2f}",
            "",
            "Fatores considerados:",
            f"  • Incerteza: {factors.uncertainty_score:.2f} (peso: {self.weights['uncertainty']:.0%})",
            f"  • Justificabilidade: {factors.context_justifiability:.2f} (peso: {self.weights['justifiability']:.0%})",
            f"  • Confiança: {factors.trust_score:.2f} (peso: {self.weights['trust']:.0%})",
            f"  • Dano potencial: {factors.harm_potential:.2f} (peso: {self.weights['harm']:.0%})",
            f"  • Primeira violação: {'Sim' if factors.first_offense else 'Não'} (peso: {self.weights['first_offense']:.0%})",
        ]

        if mercy_score >= 0.8:
            lines.append("\n→ FORTE CANDIDATO A MISERICÓRDIA (abrandar ação)")
        elif mercy_score >= 0.5:
            lines.append("\n→ Considerar abrandamento contextual")
        else:
            lines.append("\n→ Aplicar ação conforme regra")

        return "\n".join(lines)
