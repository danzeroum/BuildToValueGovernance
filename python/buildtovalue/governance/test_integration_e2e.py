"""
Integration Test E2E - Python Governance Complete Flow

Gate: Week 4 - Day 19
"""

import pytest
import time
from .ethical_context_engine_v3 import EthicalContextEngineV3, EthicalContext
from .contestability_loop import ContestabilityLoop, AppealStatus

@pytest.fixture
def engine():
    return EthicalContextEngineV3()

@pytest.fixture
def contestability():
    return ContestabilityLoop(sla_hours=24)

class TestE2EIntegration:

    def test_e2e_governance_and_appeal_accepted(self, engine, contestability):
        """E2E: Governance → Appeal → Accepted"""

        context = EthicalContext(
            session_id="session-123",
            user_history={'violations': 0, 'appeals_successful': 0, 'trust_score': 0.5},
        )

        technical_evidence = {
            'composite_risk': 192,
            'findings': [{'validator': 'cpf', 'severity': 192, 'confidence': 0.95, 'title': 'CPF_DETECTED'}],
            'finding_count': 1,
            'critical_count': 0,
            'entropy': 3.2,
            'uncertainty_score': 0.3,
        }

        # STEP 1: Decisão
        verdict = engine.decide(technical_evidence, context)

        # Verifica que verdict existe e tem confiança
        assert verdict is not None
        assert hasattr(verdict, 'confidence')
        assert verdict.confidence > 0

        print(f"\n✅ STEP 1: Decision made, confidence = {verdict.confidence:.2f}")

        # STEP 2: User contesta (simula que foi bloqueado)
        appeal = contestability.submit_appeal(
            audit_trail_id=12345,
            user_id="user-123",
            reason="This was a test CPF from ABNT standards (111.444.777-35), not real data.",
            evidence="https://www.abnt.org.br/standards/cpf-format",
        )
        assert appeal.status == AppealStatus.PENDING
        print(f"✅ STEP 2: Appeal submitted = {appeal.appeal_id}")

        # STEP 3: Human aceita
        time.sleep(0.001)
        resolved = contestability.resolve_appeal(
            appeal_id=appeal.appeal_id,
            accepted=True,
            reviewer_notes="Confirmed: Test CPF. Appeal approved.",
            reviewer_id="reviewer@buildtovalue.com",
        )
        assert resolved.status == AppealStatus.ACCEPTED
        print(f"✅ STEP 3: Appeal resolved = ACCEPTED")

        # STEP 4: Métricas
        metrics = contestability.get_metrics()
        assert metrics['appeals_submitted'] == 1
        assert metrics['appeals_accepted'] == 1
        print(f"✅ STEP 4: Success rate = {metrics['appeal_success_rate']:.0%}")

    def test_e2e_governance_and_appeal_rejected(self, engine, contestability):
        """E2E: Governance → Appeal → Rejected"""

        context = EthicalContext(
            session_id="session-456",
            user_history={'violations': 1, 'appeals_successful': 0, 'trust_score': 0.3},
        )

        technical_evidence = {
            'composite_risk': 220,
            'findings': [{'validator': 'cpf', 'severity': 220, 'confidence': 0.99, 'title': 'CPF_DETECTED'}],
            'finding_count': 1,
            'critical_count': 1,
            'entropy': 2.5,
            'uncertainty_score': 0.1,
        }

        # STEP 1: Decisão
        verdict = engine.decide(technical_evidence, context)
        assert verdict is not None
        assert verdict.confidence > 0

        print(f"\n✅ STEP 1: Decision made, confidence = {verdict.confidence:.2f}")

        # STEP 2: User contesta (weak reason)
        appeal = contestability.submit_appeal(
            audit_trail_id=67890,
            user_id="user-456",
            reason="I don't think this is a problem. Please unblock me.",
        )
        print(f"✅ STEP 2: Appeal submitted (weak reason)")

        # STEP 3: Human rejeita
        time.sleep(0.001)
        resolved = contestability.resolve_appeal(
            appeal_id=appeal.appeal_id,
            accepted=False,
            reviewer_notes="Evidence confirms real CPF. Appeal denied.",
            reviewer_id="reviewer@buildtovalue.com",
        )
        assert resolved.status == AppealStatus.REJECTED
        print(f"✅ STEP 3: Appeal resolved = REJECTED")

class TestE2EPerformance:

    def test_e2e_latency_target(self, engine, contestability):
        """E2E deve ser <50ms."""

        context = EthicalContext(
            session_id="session-perf",
            user_history={'violations': 0, 'appeals_successful': 0, 'trust_score': 0.5},
        )

        technical_evidence = {
            'composite_risk': 100,
            'findings': [],
            'finding_count': 0,
            'critical_count': 0,
            'entropy': 3.0,
            'uncertainty_score': 0.5,
        }

        start = time.perf_counter()

        # Decide
        verdict = engine.decide(technical_evidence, context)

        # Submete appeal (independente da decisão)
        contestability.submit_appeal(
            audit_trail_id=99999,
            user_id="user-perf",
            reason="Performance test appeal reason here for testing.",
        )

        elapsed_ms = (time.perf_counter() - start) * 1000
        print(f"\nE2E latency: {elapsed_ms:.2f}ms")

        assert elapsed_ms < 50, f"E2E latency {elapsed_ms:.2f}ms > 50ms"

    def test_multiple_appeals_performance(self, contestability):
        """10 appeals devem manter performance."""

        start = time.perf_counter()

        for i in range(10):
            contestability.submit_appeal(
                audit_trail_id=1000 + i,
                user_id=f"user-{i}",
                reason=f"Performance test appeal number {i} with sufficient reason length.",
            )

        elapsed_ms = (time.perf_counter() - start) * 1000
        avg_ms = elapsed_ms / 10

        print(f"\n10 appeals: {elapsed_ms:.2f}ms total, {avg_ms:.2f}ms avg")
        assert avg_ms < 5, f"Avg appeal latency {avg_ms:.2f}ms > 5ms"

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
