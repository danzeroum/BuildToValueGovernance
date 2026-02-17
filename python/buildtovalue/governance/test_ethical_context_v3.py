"""
Testes para Ethical Context Engine v3.
Coverage: Misericórdia, Contexto, BiasDeclaration, Performance.
"""

import pytest
import time
from buildtovalue.governance.ethical_context_engine import (
    EthicalContextEngineV3,
    MercyFactor,
)
from buildtovalue.governance.types import (
    EthicalContext,
    ActionType,
)


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def engine():
    return EthicalContextEngineV3()


@pytest.fixture
def high_risk_evidence():
    return {
        'composite_risk': 0.9,
        'finding_count': 3,
        'critical_count': 1,
        'entropy': 7.2,
    }


@pytest.fixture
def low_risk_evidence():
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

    def test_high_risk_block(self, engine, high_risk_evidence):
        context = EthicalContext(
            user_id="user123",
            trust_score=0.5,
            is_first_offense=False,
        )
        decision = engine.decide(high_risk_evidence, context, policy_action="BLOCK")
        assert decision.verdict == ActionType.BLOCK
        assert decision.adjusted_severity >= 0.8
        assert decision.contestable

    def test_low_risk_allow(self, engine, low_risk_evidence):
        context = EthicalContext()
        decision = engine.decide(low_risk_evidence, context, policy_action="LOG")
        assert decision.verdict in [ActionType.ALLOW, ActionType.LOG]
        assert decision.adjusted_severity < 0.5


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE MISERICÓRDIA
# ═══════════════════════════════════════════════════════════════════════════

class TestMercyAlgorithm:

    def test_mercy_first_offense(self, engine, high_risk_evidence):
        context = EthicalContext(
            is_first_offense=True,
            trust_score=0.8,
        )
        decision = engine.decide(high_risk_evidence, context, policy_action="BLOCK")
        if decision.mercy_applied:
            assert decision.adjusted_severity < high_risk_evidence['composite_risk']

    def test_mercy_high_trust(self, engine):
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
        assert decision.mercy_applied
        assert decision.adjusted_severity < 0.6

    def test_no_mercy_repeat_offender(self, engine, high_risk_evidence):
        context = EthicalContext(
            is_first_offense=False,
            has_prior_violations=True,
            trust_score=0.2,
        )
        decision = engine.decide(high_risk_evidence, context, policy_action="BLOCK")
        assert not decision.mercy_applied
        assert decision.verdict == ActionType.BLOCK

    def test_mercy_calculation(self):
        mercy = MercyFactor(
            technical_uncertainty=0.8,
            first_offense=True,
            trust_score=0.8,
            violation_severity=0.3,
        ).calculate()
        assert mercy.should_apply_mercy
        assert mercy.mercy_adjustment > 0.0


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE CONTEXTO
# ═══════════════════════════════════════════════════════════════════════════

class TestContext:

    def test_educational_mode(self, engine, high_risk_evidence):
        context = EthicalContext(
            educational_mode=True,
            criticality="MEDIUM",
        )
        decision = engine.decide(high_risk_evidence, context)
        # Educational mode should soften to EDUCATE or lower
        assert decision.verdict in [ActionType.EDUCATE, ActionType.LOG, ActionType.ALLOW]

    def test_critical_operation(self, engine):
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
        assert decision.verdict == ActionType.BLOCK


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE EXPLICABILIDADE
# ═══════════════════════════════════════════════════════════════════════════

class TestExplainability:

    def test_rationale_generated(self, engine, high_risk_evidence):
        context = EthicalContext()
        decision = engine.decide(high_risk_evidence, context)
        assert decision.rationale
        assert "Veredito:" in decision.rationale or "BLOCK" in decision.rationale
        assert len(decision.contributing_factors) > 0

    def test_contestability(self, engine, high_risk_evidence):
        context = EthicalContext()
        decision = engine.decide(high_risk_evidence, context)
        assert decision.contestable
        assert decision.appeal_deadline is not None

    def test_signature(self, engine, high_risk_evidence):
        context = EthicalContext()
        decision = engine.decide(high_risk_evidence, context)
        assert decision.signature is not None
        assert decision.signed_at is not None


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE BIAS DECLARATION
# ═══════════════════════════════════════════════════════════════════════════

class TestBiasDeclaration:

    def test_bias_declaration_exists(self, engine):
        bias = engine.get_bias_declaration()
        assert 'model_version' in bias
        assert 'known_limitations' in bias
        assert 'false_positive_rate' in bias
        assert 'last_calibration' in bias

    def test_bias_in_decision(self, engine, high_risk_evidence):
        context = EthicalContext()
        decision = engine.decide(high_risk_evidence, context)
        assert 'model_version' in decision.bias_declaration
        assert decision.bias_declaration['false_positive_rate'] > 0


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════════

class TestPerformance:

    def test_latency_target(self, engine, high_risk_evidence):
        context = EthicalContext()

        for _ in range(10):
            engine.decide(high_risk_evidence, context)

        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            engine.decide(high_risk_evidence, context)
        elapsed_ms = (time.perf_counter() - start) * 1000
        avg_ms = elapsed_ms / iterations

        print(f"\nAvg latency: {avg_ms:.2f}ms")
        assert avg_ms < 20, f"Latency {avg_ms:.2f}ms exceeds 20ms"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])