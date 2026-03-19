# python/tests/integration/test_appeals_expired.py
"""
Testes de appeals expirados (FASE 0 item 0.5).

SLA = 24h. Appeals não resolvidos dentro do SLA devem ser marcados como EXPIRED.
Princípio Jonas: responsabilidade ativa — o sistema deve detectar e registrar expiração.
"""

import time
import pytest
from buildtovalue.governance.contestability_loop import ContestabilityLoop, AppealStatus


@pytest.fixture
def loop(tmp_path):
    """ContestabilityLoop com banco SQLite em tmp_path para isolamento dos testes."""
    db_path = str(tmp_path / "appeals_test.db")
    return ContestabilityLoop(db_path=db_path, sla_hours=24)


def _make_appeal(loop: ContestabilityLoop, audit_id: int = 1001) -> str:
    """Helper: cria appeal válido e retorna appeal_id."""
    appeal = loop.submit_appeal(
        audit_trail_id=audit_id,
        user_id="user-test-001",
        reason="Recurso legítimo com justificativa de pelo menos vinte caracteres.",
    )
    return appeal.appeal_id


def _expire_appeal(loop: ContestabilityLoop, appeal_id: str) -> None:
    """Helper: manipula o appeal em memória para colocar deadline 25h no passado."""
    appeal = loop.appeals[appeal_id]
    appeal.sla_deadline = int(time.time()) - (25 * 3600)


class TestExpiredAppeals:
    """Appeals não resolvidos dentro do SLA devem ser detectados como EXPIRED."""

    def test_expired_appeal_detected(self, loop: ContestabilityLoop) -> None:
        """Appeal com deadline no passado deve aparecer na lista de expirados."""
        appeal_id = _make_appeal(loop, audit_id=1001)
        _expire_appeal(loop, appeal_id)

        expired = loop.list_expired_appeals()
        expired_ids = [a.appeal_id for a in expired]
        assert appeal_id in expired_ids, (
            f"Appeal {appeal_id} com deadline expirado deve aparecer em list_expired_appeals()"
        )

    def test_active_appeal_not_expired(self, loop: ContestabilityLoop) -> None:
        """Appeal dentro do SLA não deve ser marcado como expirado."""
        appeal_id = _make_appeal(loop, audit_id=1002)

        expired = loop.list_expired_appeals()
        expired_ids = [a.appeal_id for a in expired]
        assert appeal_id not in expired_ids, (
            "Appeal recém-criado não deve estar na lista de expirados"
        )

    def test_expired_appeal_metrics_increment(self, loop: ContestabilityLoop) -> None:
        """Chamada a list_expired_appeals() deve incrementar métrica appeals_expired."""
        appeal_id = _make_appeal(loop, audit_id=1003)
        _expire_appeal(loop, appeal_id)

        initial_expired = loop.metrics.get("appeals_expired", 0)
        loop.list_expired_appeals()
        assert loop.metrics.get("appeals_expired", 0) >= initial_expired + 1, (
            "Métrica appeals_expired deve ser incrementada ao detectar appeal expirado"
        )

    def test_resolved_appeal_not_in_expired(self, loop: ContestabilityLoop) -> None:
        """Appeal resolvido não deve aparecer como expirado mesmo com deadline passado."""
        appeal_id = _make_appeal(loop, audit_id=1004)

        # Resolver o appeal antes de expirar
        loop.resolve_appeal(
            appeal_id=appeal_id,
            accepted=True,
            reviewer_notes="Contexto médico verificado pelo revisor humano.",
            reviewer_id="reviewer-001",
        )

        # Mesmo forçando deadline expirado, appeal RESOLVIDO não deve aparecer como expirado
        _expire_appeal(loop, appeal_id)

        # list_expired_appeals() itera sobre appeals cujo status é PENDING e is_overdue() == True
        # Appeals ACCEPTED não devem ser marcados como EXPIRED
        expired = loop.list_expired_appeals()
        expired_ids = [a.appeal_id for a in expired]
        assert appeal_id not in expired_ids, (
            "Appeal já resolvido (ACCEPTED) não deve aparecer na lista de expirados"
        )
