"""
Testes para ContestabilityLoop v2.0.

Coverage: SLA, Appeals, Metrics.
"""

import pytest
import time
from buildtovalue.governance.contestability_loop import ContestabilityLoop, Appeal, AppealStatus


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def loop():
    """ContestabilityLoop para testes."""
    return ContestabilityLoop(sla_hours=24)


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE SUBMIT
# ═══════════════════════════════════════════════════════════════════════════

class TestSubmitAppeal:
    """Testes de submissão de appeals."""

    def test_submit_appeal_success(self, loop):
        """Deve submeter appeal com sucesso."""
        appeal = loop.submit_appeal(
            audit_trail_id=12345,
            user_id="user123",
            reason="This was a test CPF from ABNT standards, not real data.",
        )

        assert appeal.appeal_id.startswith("APL-12345-")
        assert appeal.status == AppealStatus.PENDING
        assert appeal.user_id == "user123"
        assert appeal.sla_deadline > time.time()

    def test_submit_appeal_with_evidence(self, loop):
        """Deve aceitar evidências adicionais."""
        appeal = loop.submit_appeal(
            audit_trail_id=12345,
            user_id="user123",
            reason="This was a test CPF from ABNT standards.",
            evidence="https://example.com/training-materials",
        )

        assert appeal.evidence_provided == "https://example.com/training-materials"

    def test_submit_appeal_reason_too_short(self, loop):
        """Deve rejeitar reason muito curto."""
        with pytest.raises(ValueError, match="at least 20 characters"):
            loop.submit_appeal(
                audit_trail_id=12345,
                user_id="user123",
                reason="Too short",  # <20 chars
            )

    def test_metrics_increment(self, loop):
        """Deve incrementar métricas."""
        loop.submit_appeal(
            audit_trail_id=12345,
            user_id="user123",
            reason="This was a test CPF from ABNT standards.",
        )

        metrics = loop.get_metrics()
        assert metrics['appeals_submitted'] == 1
        assert metrics['pending_appeals'] == 1


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE RESOLVE
# ═══════════════════════════════════════════════════════════════════════════

class TestResolveAppeal:
    """Testes de resolução de appeals."""

    def test_resolve_appeal_accepted(self, loop):
        """Deve aceitar appeal."""
        # Submit
        appeal = loop.submit_appeal(
            audit_trail_id=12345,
            user_id="user123",
            reason="This was a test CPF from ABNT standards.",
        )

        time.sleep(0.001)  # FIX: Garante timestamp diferente

        # Resolve (accepted)
        resolved = loop.resolve_appeal(
            appeal_id=appeal.appeal_id,
            accepted=True,
            reviewer_notes="Confirmed: Test CPF. Appeal approved.",
            reviewer_id="reviewer@example.com",
        )

        assert resolved.status == AppealStatus.ACCEPTED
        assert resolved.reviewer_notes == "Confirmed: Test CPF. Appeal approved."
        assert resolved.resolution_timestamp >= appeal.timestamp  # FIX: >= em vez de >

        # Metrics
        metrics = loop.get_metrics()
        assert metrics['appeals_accepted'] == 1
        assert metrics['appeal_success_rate'] == 1.0

    def test_resolve_appeal_rejected(self, loop):
        """Deve rejeitar appeal."""
        # Submit
        appeal = loop.submit_appeal(
            audit_trail_id=12345,
            user_id="user123",
            reason="I think this was a mistake.",
        )

        time.sleep(0.001)  # FIX: Garante timestamp diferente

        # Resolve (rejected)
        resolved = loop.resolve_appeal(
            appeal_id=appeal.appeal_id,
            accepted=False,
            reviewer_notes="Evidence confirms real CPF was shared. Appeal denied.",
            reviewer_id="reviewer@example.com",
        )

        assert resolved.status == AppealStatus.REJECTED
        assert resolved.resolution_timestamp >= appeal.timestamp  # FIX: >= em vez de >

        # Metrics
        metrics = loop.get_metrics()
        assert metrics['appeals_rejected'] == 1
        assert metrics['appeal_success_rate'] == 0.0

    def test_resolve_nonexistent_appeal(self, loop):
        """Deve falhar se appeal não existe."""
        with pytest.raises(ValueError, match="Appeal not found"):
            loop.resolve_appeal(
                appeal_id="APL-99999-999999",
                accepted=True,
                reviewer_notes="N/A",
                reviewer_id="reviewer@example.com",
            )


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE SLA
# ═══════════════════════════════════════════════════════════════════════════

class TestSLA:
    """Testes de SLA."""

    def test_sla_deadline_calculated(self, loop):
        """Deve calcular deadline SLA."""
        appeal = loop.submit_appeal(
            audit_trail_id=12345,
            user_id="user123",
            reason="This was a test CPF from ABNT standards.",
        )

        # SLA = 24h após timestamp
        expected_deadline = appeal.timestamp + (24 * 3600)
        assert appeal.sla_deadline == expected_deadline

    def test_sla_compliance_100_percent(self, loop):
        """SLA compliance = 100% se nenhum appeal."""
        assert loop.get_sla_compliance_rate() == 1.0

    def test_sla_compliance_within_sla(self, loop):
        """SLA compliance = 100% se resolvido dentro do prazo."""
        # Submit
        appeal = loop.submit_appeal(
            audit_trail_id=12345,
            user_id="user123",
            reason="This was a test CPF from ABNT standards.",
        )

        # Resolve imediatamente (dentro do SLA)
        loop.resolve_appeal(
            appeal_id=appeal.appeal_id,
            accepted=True,
            reviewer_notes="OK",
            reviewer_id="reviewer@example.com",
        )

        assert loop.get_sla_compliance_rate() == 1.0


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE MÉTRICAS
# ═══════════════════════════════════════════════════════════════════════════

class TestMetrics:
    """Testes de métricas."""

    def test_appeal_success_rate_50_percent(self, loop):
        """Success rate = 50% se 1 aceito, 1 rejeitado."""
        # Appeal 1 (accepted)
        appeal1 = loop.submit_appeal(
            audit_trail_id=1,
            user_id="user1",
            reason="This was a test CPF from ABNT standards.",
        )
        loop.resolve_appeal(
            appeal_id=appeal1.appeal_id,
            accepted=True,
            reviewer_notes="OK",
            reviewer_id="reviewer",
        )

        # Appeal 2 (rejected)
        appeal2 = loop.submit_appeal(
            audit_trail_id=2,
            user_id="user2",
            reason="I don't agree with this decision.",
        )
        loop.resolve_appeal(
            appeal_id=appeal2.appeal_id,
            accepted=False,
            reviewer_notes="Denied",
            reviewer_id="reviewer",
        )

        assert loop.get_appeal_success_rate() == 0.5

    def test_get_metrics_complete(self, loop):
        """Deve retornar métricas completas."""
        # Submit 2 appeals
        loop.submit_appeal(12345, "user1", "Reason 1" * 5)
        loop.submit_appeal(67890, "user2", "Reason 2" * 5)

        metrics = loop.get_metrics()

        assert 'appeals_submitted' in metrics
        assert 'pending_appeals' in metrics
        assert 'sla_compliance_rate' in metrics
        assert 'appeal_success_rate' in metrics

        assert metrics['appeals_submitted'] == 2
        assert metrics['pending_appeals'] == 2


# ═══════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
