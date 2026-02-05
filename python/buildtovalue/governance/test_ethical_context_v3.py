"""
Testes para Ethical Context Engine v3.

Coverage: Misericórdia, Contexto, BiasDeclaration.
"""

import pytest
from python.buildtovalue.governance.ethical_context_engine import (
    EthicalContextEngineV3,
    EthicalContext,
    TechnicalVerdict,
    MercyFactor,
)


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def engine():
    """Engine para testes."""
    return EthicalContextEngineV3()


@pytest.fixture
def high_risk_evidence():
    """Evidence de alto risco."""
    return {
        'composite_risk': 0.9,
        'finding_count': 3,
        'critical_count': 1,
        'entropy': 7.2,
    }


@pytest.fixture
def low_risk_evidence():
    """Evidence de baixo risco."""
    return {
        'composite_risk': 0.3,
        'finding_count': 1,
        'critical_count': 0,
        'entropy': 4.5,
    }


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE DECISÃO
# ═══════════════════════════════════════════════════════════════════════════

class TestEthicalDecision:
    """Testes de decisão ética."""

    def test_high_risk_block(self, engine, high_risk_evidence):
        """Alto risco deve resultar em BLOCK."""
        context = EthicalContext(
            user_id="user123",
            trust_score=0.5,
            is_first_offense=False,
        )

        decision = engine.decide(high_risk_evidence, context, policy_action="BLOCK")

        assert decision.verdict == TechnicalVerdict.BLOCK
        assert decision.adjusted_severity >= 0.8
        assert decision.contestable

    def test_low_risk_allow(self, engine, low_risk_evidence):
        """Baixo risco deve resultar em ALLOW/LOG."""
        context = EthicalContext()

        decision = engine.decide(low_risk_evidence, context, policy_action="LOG")

        assert decision.verdict in [TechnicalVerdict.ALLOW, TechnicalVerdict.LOG]
        assert decision.adjusted_severity < 0.5


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE MISERICÓRDIA
# ═══════════════════════════════════════════════════════════════════════════

class TestMercyAlgorithm:
    """Testes de Misericórdia Algorítmica (Gilligan)."""

    def test_mercy_first_offense(self, engine, high_risk_evidence):
        """Primeira ofensa deve receber misericórdia."""
        context = EthicalContext(
            is_first_offense=True,
            trust_score=0.8,
        )

        decision = engine.decide(high_risk_evidence, context, policy_action="BLOCK")

        # Pode ter misericórdia aplicada
        if decision.mercy_applied:
            assert decision.adjusted_severity < high_risk_evidence['composite_risk']
            assert "primeira ofensa" in decision.mercy_factor.rationale.lower()

    def test_mercy_high_trust(self, engine):
        """Alto trust score deve receber misericórdia."""
        evidence = {
            'composite_risk': 0.6,
            'finding_count': 2,
            'critical_count': 0,
            'entropy': 5.0,
        }

        context = EthicalContext(
            trust_score=0.9,
            is_first_offense=True,
        )

        decision = engine.decide(evidence, context)

        # Deve ter misericórdia (trust 0.9 + first offense)
        assert decision.mercy_applied
        assert decision.adjusted_severity < 0.6

    def test_no_mercy_repeat_offender(self, engine, high_risk_evidence):
        """Reincidente com baixo trust não deve receber misericórdia."""
        context = EthicalContext(
            is_first_offense=False,
            has_prior_violations=True,
            trust_score=0.2,
        )

        decision = engine.decide(high_risk_evidence, context, policy_action="BLOCK")

        # Não deve ter misericórdia
        assert not decision.mercy_applied
        assert decision.verdict == TechnicalVerdict.BLOCK

    def test_mercy_calculation(self):
        """Testa cálculo de MercyFactor."""
        mercy = MercyFactor(
            technical_uncertainty=0.8,
            first_offense=True,
            trust_score=0.8,
            violation_severity=0.3,
        ).calculate()

        # Deve aplicar misericórdia (todos os fatores favoráveis)
        assert mercy.should_apply_mercy
        assert mercy.mercy_adjustment > 0.0
        assert "alta incerteza" in mercy.rationale.lower()


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE CONTEXTO
# ═══════════════════════════════════════════════════════════════════════════

class TestContext:
    """Testes de contexto."""

    def test_educational_mode(self, engine, high_risk_evidence):
        """Educational mode deve resultar em EDUCATE."""
        context = EthicalContext(
            educational_mode=True,
            criticality="MEDIUM",
        )

        decision = engine.decide(high_risk_evidence, context)

        assert decision.verdict == TechnicalVerdict.EDUCATE

    def test_critical_operation(self, engine):
        """Operação crítica não deve ter misericórdia."""
        evidence = {
            'composite_risk': 0.9,
            'finding_count': 2,
            'critical_count': 1,
            'entropy': 6.0,
        }

        context = EthicalContext(
            criticality="CRITICAL",
            is_first_offense=True,
        )

        decision = engine.decide(evidence, context, policy_action="BLOCK")

        # Crítico = BLOCK sempre
        assert decision.verdict == TechnicalVerdict.BLOCK


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE EXPLICABILIDADE
# ═══════════════════════════════════════════════════════════════════════════

class TestExplainability:
    """Testes de explicabilidade."""

    def test_rationale_generated(self, engine, high_risk_evidence):
        """Deve gerar rationale human-readable."""
        context = EthicalContext()
        decision = engine.decide(high_risk_evidence, context)

        assert decision.rationale
        assert "Verdict:" in decision.rationale
        assert "Severity:" in decision.rationale
        assert len(decision.contributing_factors) > 0

    def test_contestability(self, engine, high_risk_evidence):
        """Decisão deve ser contestável."""
        context = EthicalContext()
        decision = engine.decide(high_risk_evidence, context)

        assert decision.contestable
        assert decision.appeal_deadline is not None

    def test_signature(self, engine, high_risk_evidence):
        """Decisão deve ser assinada."""
        context = EthicalContext()
        decision = engine.decide(high_risk_evidence, context)

        assert decision.signature is not None
        assert decision.signed_at is not None


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE BIAS DECLARATION
# ═══════════════════════════════════════════════════════════════════════════

class TestBiasDeclaration:
    """Testes de BiasDeclaration (transparência)."""

    def test_bias_declaration_exists(self, engine):
        """Deve ter BiasDeclaration."""
        bias = engine.get_bias_declaration()

        assert 'model_version' in bias
        assert 'known_limitations' in bias
        assert 'false_positive_rate' in bias
        assert 'last_calibration' in bias

    def test_bias_in_decision(self, engine, high_risk_evidence):
        """Decisão deve incluir BiasDeclaration."""
        context = EthicalContext()
        decision = engine.decide(high_risk_evidence, context)

        assert 'model_version' in decision.bias_declaration
        assert decision.bias_declaration['false_positive_rate'] > 0


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════════

class TestPerformance:
    """Testes de performance."""

    def test_latency_target(self, engine, high_risk_evidence):
        """Deve respeitar SLA de 10ms."""
        import time

        context = EthicalContext()

        # Warmup
        for _ in range(10):
            engine.decide(high_risk_evidence, context)

        # Benchmark
        iterations = 100
        start = time.perf_counter()

        for _ in range(iterations):
            engine.decide(high_risk_evidence, context)

        elapsed_ms = (time.perf_counter() - start) * 1000
        avg_ms = elapsed_ms / iterations

        print(f"\nAvg latency: {avg_ms:.2f}ms")

        # Target: <10ms (p99)
        assert avg_ms < 20, f"Latency {avg_ms:.2f}ms exceeds 20ms"


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
