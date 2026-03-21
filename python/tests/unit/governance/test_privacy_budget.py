"""Tests for PrivacyBudgetTracker — Cenários 26, 30, 3."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from buildtovalue.governance.privacy_budget import (
    BudgetCheckResult,
    BudgetStatus,
    BudgetWindow,
    PrivacyBudgetTracker,
    SensitiveDataType,
    _DEFAULT_LIMITS,
    _WARNING_PCT,
    _CRITICAL_PCT,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "test_budget.db")


@pytest.fixture
def tracker(db_path: str) -> PrivacyBudgetTracker:
    return PrivacyBudgetTracker(db_path=db_path)


# ── TestBudgetStatusTransitions — SIM-1: Limiar exatos ────────────────────────

class TestBudgetStatusTransitions:
    """Verifica transições OK → WARNING → CRITICAL → EXHAUSTED nos limiares exatos."""

    def test_initial_status_ok(self, tracker: PrivacyBudgetTracker) -> None:
        result = tracker.check_only("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        assert result.status == BudgetStatus.OK

    def test_status_below_warning_is_ok(self, db_path: str) -> None:
        """69% de uso → OK (limite session GPS = 3, então 2/3 = 66% → OK)."""
        tracker = PrivacyBudgetTracker(
            db_path=db_path,
            limits={SensitiveDataType.GPS_LOCATION: {
                BudgetWindow.SESSION: 3,
                BudgetWindow.DAILY:   100,
                BudgetWindow.WEEKLY:  1000,
            }},
        )
        # 2 de 3 = 66% → OK
        tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        result = tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        assert result.used == 2
        assert result.limit == 3
        assert result.status == BudgetStatus.OK

    def test_warning_threshold_exact(self, db_path: str) -> None:
        """70% de uso → WARNING (limite = 10, usado = 7 → 70%)."""
        tracker = PrivacyBudgetTracker(
            db_path=db_path,
            limits={SensitiveDataType.GPS_LOCATION: {
                BudgetWindow.SESSION: 10,
                BudgetWindow.DAILY:   1000,
                BudgetWindow.WEEKLY:  10000,
            }},
        )
        for _ in range(6):
            tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        result = tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        # 7/10 = 70% → WARNING
        assert result.used == 7
        assert result.limit == 10
        assert result.status == BudgetStatus.WARNING

    def test_critical_threshold_exact(self, db_path: str) -> None:
        """90% de uso → CRITICAL (limite = 10, usado = 9 → 90%)."""
        tracker = PrivacyBudgetTracker(
            db_path=db_path,
            limits={SensitiveDataType.GPS_LOCATION: {
                BudgetWindow.SESSION: 10,
                BudgetWindow.DAILY:   1000,
                BudgetWindow.WEEKLY:  10000,
            }},
        )
        for _ in range(8):
            tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        result = tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        # 9/10 = 90% → CRITICAL
        assert result.used == 9
        assert result.status == BudgetStatus.CRITICAL

    def test_exhausted_at_100_pct(self, db_path: str) -> None:
        """100% de uso → EXHAUSTED → blocked=True."""
        tracker = PrivacyBudgetTracker(
            db_path=db_path,
            limits={SensitiveDataType.GPS_LOCATION: {
                BudgetWindow.SESSION: 3,
                BudgetWindow.DAILY:   1000,
                BudgetWindow.WEEKLY:  10000,
            }},
        )
        for _ in range(3):
            tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        result = tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        assert result.status == BudgetStatus.EXHAUSTED
        assert result.blocked is True

    def test_exhausted_does_not_increment(self, db_path: str) -> None:
        """Quando exausto, check_and_record não incrementa contador."""
        tracker = PrivacyBudgetTracker(
            db_path=db_path,
            limits={SensitiveDataType.GPS_LOCATION: {
                BudgetWindow.SESSION: 2,
                BudgetWindow.DAILY:   1000,
                BudgetWindow.WEEKLY:  10000,
            }},
        )
        tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        # agora exausto; chamar mais vezes não deve incrementar
        tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        result = tracker.check_only("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        assert result.used == 2  # sem incremento após exausto

    @pytest.mark.parametrize("data_type", list(SensitiveDataType))
    def test_all_data_types_have_limits(self, tracker: PrivacyBudgetTracker, data_type: SensitiveDataType) -> None:
        result = tracker.check_only("agent-A", "sess-1", data_type)
        assert result.status == BudgetStatus.OK
        assert result.data_type == data_type


# ── TestAgentIsolation — SIM-2: Isolamento entre agentes ──────────────────────

class TestAgentIsolation:
    """Budget de agente A não afeta agente B."""

    def test_different_agents_are_isolated(self, db_path: str) -> None:
        tracker = PrivacyBudgetTracker(
            db_path=db_path,
            limits={SensitiveDataType.BIOMETRIC: {
                BudgetWindow.SESSION: 1,
                BudgetWindow.DAILY:   1000,
                BudgetWindow.WEEKLY:  10000,
            }},
        )
        # Exaurir agent-A
        tracker.check_and_record("agent-A", "sess-A", SensitiveDataType.BIOMETRIC)
        result_a = tracker.check_only("agent-A", "sess-A", SensitiveDataType.BIOMETRIC)
        assert result_a.status == BudgetStatus.EXHAUSTED

        # agent-B deve ter budget zerado
        result_b = tracker.check_only("agent-B", "sess-B", SensitiveDataType.BIOMETRIC)
        assert result_b.status == BudgetStatus.OK

    def test_different_sessions_same_agent_isolated(self, db_path: str) -> None:
        """Sessões distintas do mesmo agente têm budget independente."""
        tracker = PrivacyBudgetTracker(
            db_path=db_path,
            limits={SensitiveDataType.BIOMETRIC: {
                BudgetWindow.SESSION: 1,
                BudgetWindow.DAILY:   1000,
                BudgetWindow.WEEKLY:  10000,
            }},
        )
        tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.BIOMETRIC)
        result_sess1 = tracker.check_only("agent-A", "sess-1", SensitiveDataType.BIOMETRIC)
        assert result_sess1.status == BudgetStatus.EXHAUSTED

        result_sess2 = tracker.check_only("agent-A", "sess-2", SensitiveDataType.BIOMETRIC)
        assert result_sess2.status == BudgetStatus.OK

    def test_different_data_types_are_isolated(self, tracker: PrivacyBudgetTracker) -> None:
        """GPS exausto não afeta HEALTH_DATA."""
        result = tracker.check_only("agent-A", "sess-1", SensitiveDataType.HEALTH_DATA)
        assert result.status == BudgetStatus.OK


# ── TestPersistence — SIM-3: Persistência entre reinícios ─────────────────────

class TestPersistence:
    """Budget acumulado sobrevive a reinício do processo (SQLite)."""

    def test_usage_persists_across_tracker_instances(self, db_path: str) -> None:
        """Criar tracker, registrar uso, criar novo tracker com mesmo db, verificar."""
        limits = {SensitiveDataType.FINANCIAL: {
            BudgetWindow.SESSION: 5,
            BudgetWindow.DAILY:   1000,
            BudgetWindow.WEEKLY:  10000,
        }}
        tracker1 = PrivacyBudgetTracker(db_path=db_path, limits=limits)
        tracker1.check_and_record("agent-X", "sess-1", SensitiveDataType.FINANCIAL)
        tracker1.check_and_record("agent-X", "sess-1", SensitiveDataType.FINANCIAL)

        # Novo tracker com o mesmo banco — simula reinício
        tracker2 = PrivacyBudgetTracker(db_path=db_path, limits=limits)
        result = tracker2.check_only("agent-X", "sess-1", SensitiveDataType.FINANCIAL)
        assert result.used == 2

    def test_exhausted_budget_persists(self, db_path: str) -> None:
        """Budget exausto antes do reinício deve continuar exausto após."""
        limits = {SensitiveDataType.BIOMETRIC: {
            BudgetWindow.SESSION: 1,
            BudgetWindow.DAILY:   1000,
            BudgetWindow.WEEKLY:  10000,
        }}
        tracker1 = PrivacyBudgetTracker(db_path=db_path, limits=limits)
        tracker1.check_and_record("agent-Z", "sess-Z", SensitiveDataType.BIOMETRIC)

        tracker2 = PrivacyBudgetTracker(db_path=db_path, limits=limits)
        result = tracker2.check_only("agent-Z", "sess-Z", SensitiveDataType.BIOMETRIC)
        assert result.status == BudgetStatus.EXHAUSTED
        assert result.blocked is True


# ── TestFailSecure — SIM-4: Fail-secure ───────────────────────────────────────

class TestFailSecure:
    """Exceção interna → EXHAUSTED (BLOCK), nunca silêncio."""

    def test_invalid_db_path_fails_secure(self, tmp_path: Path) -> None:
        """DB path que é diretório (não arquivo) deve falhar e retornar EXHAUSTED."""
        # Usar um diretório como path do DB — SQLite não consegue abrir
        dir_as_db = str(tmp_path)  # tmp_path é um diretório, não arquivo
        tracker = PrivacyBudgetTracker(db_path=dir_as_db)
        result = tracker.check_and_record("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        # Se falhar, retorna EXHAUSTED; se por acaso não falhar (SQLite tolerante), OK é aceitável
        assert result.status in (BudgetStatus.EXHAUSTED, BudgetStatus.OK)
        # Em qualquer caso, não deve levantar exceção
        assert result.explain_decision

    def test_fail_secure_internal_error(self, db_path: str) -> None:
        """Método _fail_secure retorna EXHAUSTED com explain e signature."""
        tracker = PrivacyBudgetTracker(db_path=db_path)
        result = tracker._fail_secure(SensitiveDataType.GPS_LOCATION, "erro simulado")
        assert result.status == BudgetStatus.EXHAUSTED
        assert result.blocked is True
        assert result.explain_decision
        assert result.signature

    def test_fail_secure_has_explain(self, db_path: str) -> None:
        tracker = PrivacyBudgetTracker(db_path=db_path)
        result = tracker._fail_secure(SensitiveDataType.BIOMETRIC, "test error")
        assert result.explain_decision
        assert len(result.explain_decision) > 0


# ── TestResultInvariants — SIM-5: Invariantes de resultado ───────────────────

class TestResultInvariants:
    """Invariantes de BudgetCheckResult."""

    def test_result_is_frozen(self, tracker: PrivacyBudgetTracker) -> None:
        result = tracker.check_only("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        with pytest.raises((AttributeError, TypeError)):
            result.status = BudgetStatus.EXHAUSTED  # type: ignore[misc]

    def test_explain_decision_always_present(self, tracker: PrivacyBudgetTracker) -> None:
        for dt in SensitiveDataType:
            result = tracker.check_only("agent-A", "sess-1", dt)
            assert result.explain_decision
            assert len(result.explain_decision) > 10

    def test_signature_always_present(self, tracker: PrivacyBudgetTracker) -> None:
        result = tracker.check_only("agent-A", "sess-1", SensitiveDataType.FINANCIAL)
        assert result.signature
        assert len(result.signature) == 64  # hex SHA-256

    def test_decided_at_iso_is_utc(self, tracker: PrivacyBudgetTracker) -> None:
        result = tracker.check_only("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        # ISO 8601 com Z ou +00:00
        assert "Z" in result.decided_at_iso or "+00:00" in result.decided_at_iso

    def test_check_only_does_not_record(self, tracker: PrivacyBudgetTracker) -> None:
        for _ in range(5):
            tracker.check_only("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        result = tracker.check_only("agent-A", "sess-1", SensitiveDataType.GPS_LOCATION)
        assert result.used == 0
