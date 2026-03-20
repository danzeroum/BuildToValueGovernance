# python/tests/unit/governance/test_mercy_edge_cases.py
"""
Testes de edge cases do MercyAlgorithm (Gilligan stage).
Cobre trust=0.0 e trust=0.95 documentados em FASE 0 item 0.5.

Filosofia (Gilligan): contexto > regra. Trust score alto com primeira infração
deve sempre resultar em downgrade de severidade.
"""

import pytest
from unittest.mock import MagicMock
from buildtovalue.governance.mercy_algorithm import MercyCalculator, MercyFactors


@pytest.fixture
def calculator():
    return MercyCalculator()


class TestMercyEdgeCaseTrustZero:
    """trust_score=0.0 com alto potencial de dano: mercy_score deve ser mínimo."""

    def test_mercy_zero_trust_high_harm_near_zero(self, calculator: MercyCalculator) -> None:
        factors = MercyFactors(
            uncertainty_score=0.0,
            context_justifiability=0.0,
            trust_score=0.0,
            harm_potential=1.0,
            first_offense=False,
        )
        score = calculator._calculate_score(factors)
        # Com trust=0, harm=1.0, não-primeira-infração: mercy deve ser próximo de 0
        assert score < 0.20, f"Mercy com trust=0.0 e harm=1.0 deveria ser < 0.20, got {score:.3f}"

    def test_mercy_zero_trust_first_offense_still_low(self, calculator: MercyCalculator) -> None:
        factors = MercyFactors(
            uncertainty_score=0.0,
            context_justifiability=0.0,
            trust_score=0.0,
            harm_potential=1.0,
            first_offense=True,
        )
        score = calculator._calculate_score(factors)
        # Primeira infração ajuda, mas trust=0 com harm=1.0 ainda é perigoso
        assert score < 0.40, f"Mercy com trust=0.0, harm=1.0, first_offense=True deveria ser < 0.40, got {score:.3f}"

    def test_mercy_zero_trust_range_valid(self, calculator: MercyCalculator) -> None:
        factors = MercyFactors(
            uncertainty_score=0.5,
            context_justifiability=0.5,
            trust_score=0.0,
            harm_potential=0.5,
            first_offense=True,
        )
        score = calculator._calculate_score(factors)
        assert 0.0 <= score <= 1.0, "Mercy score deve estar no intervalo [0.0, 1.0]"


class TestMercyEdgeCaseTrustMax:
    """trust_score=0.95 com baixo harm e primeira infração: mercy_score deve ser alto."""

    def test_mercy_high_trust_low_harm_first_offense_high(self, calculator: MercyCalculator) -> None:
        factors = MercyFactors(
            uncertainty_score=0.8,
            context_justifiability=0.9,
            trust_score=0.95,
            harm_potential=0.1,
            first_offense=True,
        )
        score = calculator._calculate_score(factors)
        # Veterano de alta confiança, primeira infração, baixo dano → mercy alto
        assert score > 0.70, f"Mercy com trust=0.95, harm=0.1, first_offense=True deveria ser > 0.70, got {score:.3f}"

    def test_mercy_high_trust_high_harm_bounded(self, calculator: MercyCalculator) -> None:
        factors = MercyFactors(
            uncertainty_score=0.0,
            context_justifiability=0.0,
            trust_score=0.95,
            harm_potential=1.0,
            first_offense=False,
        )
        score = calculator._calculate_score(factors)
        # Mesmo trust alto, harm crítico deve limitar mercy
        assert score <= 0.60, f"Mercy com harm=1.0 não deve ultrapassar 0.60 mesmo com trust=0.95, got {score:.3f}"

    def test_mercy_score_always_bounded(self, calculator: MercyCalculator) -> None:
        """Invariante: mercy_score ∈ [0.0, 1.0] independente dos inputs."""
        for trust in [0.0, 0.5, 0.95, 1.0]:
            for harm in [0.0, 0.5, 1.0]:
                factors = MercyFactors(
                    uncertainty_score=trust,
                    context_justifiability=trust,
                    trust_score=trust,
                    harm_potential=harm,
                    first_offense=True,
                )
                score = calculator._calculate_score(factors)
                assert 0.0 <= score <= 1.0, (
                    f"Mercy score fora dos bounds para trust={trust}, harm={harm}: {score}"
                )
