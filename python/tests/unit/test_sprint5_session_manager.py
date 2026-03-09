"""
Testes Sprint 5 — SessionManager (Gaps 1, 5, 9, 17)

Cobre:
  - SessionManager puro: LRU cap, TTL amortizado, evict explícito
  - Integração GoalDriftSentinel: sessão expirada reinicia ring buffer
  - Integração SensitivityAccumulator: SessionManager substitui evictions O(n)
"""
from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from buildtovalue.governance.session_manager import SessionManager
from buildtovalue.governance.goal_drift_sentinel import (
    GoalDriftSentinel, DriftAction,
)
from buildtovalue.governance.sensitivity_accumulator import (
    SessionSensitivityAccumulator,
)

HMAC = b"test-secret-sprint5"


# ──────────────────────────────────────────────────────────────────────────────
# SessionManager — Unit
# ──────────────────────────────────────────────────────────────────────────────

class TestSessionManagerLRU:
    def test_touch_new_session_returns_empty(self):
        mgr = SessionManager(max_sessions=10, ttl_s=3600)
        assert mgr.touch("s1") == []
        assert mgr.size() == 1

    def test_touch_existing_refreshes_without_eviction(self):
        mgr = SessionManager(max_sessions=10, ttl_s=3600)
        mgr.touch("s1")
        evicted = mgr.touch("s1")
        assert evicted == []
        assert mgr.size() == 1

    def test_lru_cap_evicts_oldest_when_full(self):
        mgr = SessionManager(max_sessions=3, ttl_s=3600)
        mgr.touch("a")
        mgr.touch("b")
        mgr.touch("c")
        evicted = mgr.touch("d")  # cap=3 → evicta "a" (mais antigo)
        assert "a" in evicted
        assert mgr.size() == 3
        assert mgr.evictions >= 1

    def test_lru_recent_access_protects_from_eviction(self):
        mgr = SessionManager(max_sessions=3, ttl_s=3600)
        mgr.touch("a")
        mgr.touch("b")
        mgr.touch("c")
        mgr.touch("a")  # a fica recente
        evicted = mgr.touch("d")  # b deve ser evictado (mais antigo)
        assert "b" in evicted
        assert "a" not in evicted

    def test_evict_explicit_removes_session(self):
        mgr = SessionManager(max_sessions=10, ttl_s=3600)
        mgr.touch("s1")
        mgr.evict("s1")
        assert mgr.is_expired("s1") is True
        assert mgr.size() == 0

    def test_is_expired_returns_true_for_unknown(self):
        mgr = SessionManager(max_sessions=10, ttl_s=3600)
        assert mgr.is_expired("never-seen") is True

    def test_invalid_params_raise(self):
        with pytest.raises(ValueError):
            SessionManager(max_sessions=0)
        with pytest.raises(ValueError):
            SessionManager(ttl_s=0)


class TestSessionManagerTTL:
    def test_ttl_eviction_amortized_at_100_ops(self):
        """
        Após 100 toques, sessões expiradas são varridas.
        Usa monkeypatch para controlar time.time.
        """
        import buildtovalue.governance.session_manager as sm_module

        _t = [1000.0]

        def fake_time():
            return _t[0]

        with patch.object(sm_module, "time") as mock_time:
            mock_time.time = fake_time
            mgr = SessionManager(max_sessions=1000, ttl_s=300)

            # Cria 5 sessões "antigas"
            for i in range(5):
                mgr.touch(f"old-{i}")

            # Avança 400s (acima do TTL=300)
            _t[0] = 1400.0

            # Cria 100 sessões novas para disparar varredura amortizada
            all_evicted = []
            for i in range(100):
                all_evicted.extend(mgr.touch(f"new-{i}"))

        # Pelo menos algumas das sessões antigas devem ter sido evictadas
        evicted_old = [e for e in all_evicted if e.startswith("old-")]
        assert len(evicted_old) >= 1, (
            f"Esperado evicção de sessões expiradas, got: {all_evicted}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# GoalDriftSentinel — Integração SessionManager
# ──────────────────────────────────────────────────────────────────────────────

class TestGoalDriftSentinelSessionManager:
    def test_cap_evicts_oldest_session_data(self):
        """Com max_sessions=2, a 3ª sessão evicta a 1ª e limpa o ring buffer."""
        s = GoalDriftSentinel(hmac_secret=HMAC, max_sessions=2, ttl_s=3600)
        s.record_and_analyze("s1", "High", "ALLOW")
        s.record_and_analyze("s2", "High", "ALLOW")
        # s3 dispara evicção de s1
        s.record_and_analyze("s3", "Low", "ALLOW")

        assert len(s.window_snapshot("s1")) == 0, "s1 deve ter sido evictada"
        assert len(s.window_snapshot("s2")) == 1
        assert len(s.window_snapshot("s3")) == 1

    def test_reset_session_clears_both_data_and_manager(self):
        """reset_session remove do dict E do SessionManager."""
        s = GoalDriftSentinel(hmac_secret=HMAC, max_sessions=10, ttl_s=3600)
        for _ in range(5):
            s.record_and_analyze("s1", "High", "ALLOW")
        s.reset_session("s1")
        assert s.window_snapshot("s1") == []
        # Após reset, nova análise começa do zero
        r = s.record_and_analyze("s1", "Low", "ALLOW")
        assert r.drift_action == DriftAction.ALLOW
        assert len(s.window_snapshot("s1")) == 1


# ──────────────────────────────────────────────────────────────────────────────
# SensitivityAccumulator — Integração SessionManager
# ──────────────────────────────────────────────────────────────────────────────

class TestSensitivityAccumulatorSessionManager:
    def test_cap_evicts_oldest_session(self):
        """Com max_sessions=2, a 3ª sessão evicta a 1ª via SessionManager LRU."""
        acc = SessionSensitivityAccumulator(max_sessions=2)
        acc.accumulate("s1", ["cpf", "credit_card"])
        acc.accumulate("s2", ["email"])
        acc.accumulate("s3", ["ssn"])  # evicta s1

        assert acc.get_state("s1") is None, "s1 deve ter sido evictada"
        assert acc.get_state("s2") is not None
        assert acc.get_state("s3") is not None
        assert acc.metrics["evictions"] >= 1

    def test_accumulation_still_works_after_eviction(self):
        """Funcionalidade core (combinações, risco) preservada após refator."""
        acc = SessionSensitivityAccumulator(max_sessions=100)
        acc.accumulate("x", ["cpf"])
        state = acc.accumulate("x", ["credit_card"])
        assert state.cumulative_risk > 0.0
        assert any("PII_BRAZILIAN" in c and "FINANCIAL" in c
                   for c in state.active_combinations)

    def test_no_eviction_method_present(self):
        """_evict_expired e _evict_oldest devem ter sido removidos (Gap 17)."""
        acc = SessionSensitivityAccumulator()
        assert not hasattr(acc, "_evict_expired"), "_evict_expired deve estar removido"
        assert not hasattr(acc, "_evict_oldest"), "_evict_oldest deve estar removido"
