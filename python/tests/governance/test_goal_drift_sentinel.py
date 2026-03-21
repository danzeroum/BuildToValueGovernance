"""
Tests: GoalDriftSentinel - PROP-038
pytest python/tests/governance/test_goal_drift_sentinel.py -v
"""
import pytest
from buildtovalue.governance.goal_drift_sentinel import (
    GoalDriftSentinel, DriftAction, DriftReport, ModelPerformanceReport,
    DRIFT_SCORE, _compute_trend_pct, _detect_asymmetric_pressure,
)

SECRET = b"btv-test-prop038-drift"

def _sentinel(**kw) -> GoalDriftSentinel:
    return GoalDriftSentinel(hmac_secret=SECRET, **kw)


# ─── Init ──────────────────────────────────────────────────────────────────────────

class TestInit:
    def test_rejects_empty_secret(self):
        with pytest.raises(ValueError):
            GoalDriftSentinel(hmac_secret=b"")


# ─── No drift (sessao saudavel) ────────────────────────────────────────────────────────────

class TestNoDrift:
    def test_single_record_no_drift(self):
        r = _sentinel().record_and_analyze("s1", "Low", "ALLOW")
        assert r.drift_action == DriftAction.ALLOW
        assert not r.policy_drift_detected

    def test_stable_medium_no_drift(self):
        s = _sentinel()
        for _ in range(8):
            r = s.record_and_analyze("s1", "Medium", "ALLOW")
        assert r.drift_action == DriftAction.ALLOW

    def test_decreasing_trend_no_drift(self):
        s = _sentinel()
        for level in ["Critical", "High", "Medium", "Low", "None"]:
            r = s.record_and_analyze("s1", level, "BLOCK")
        assert r.drift_action == DriftAction.ALLOW


# ─── Drift detectado ───────────────────────────────────────────────────────────────

class TestDriftDetected:
    def test_critical_triggers_block(self):
        r = _sentinel().record_and_analyze("s1", "Critical", "ALLOW")
        assert r.policy_drift_detected
        assert r.drift_action == DriftAction.BLOCK

    def test_ascending_with_asymmetric_pressure_escalates(self):
        """
        Sprint 3 (trend ponderado): sequencia (0,1,2,3,3,3) com K=6
        produzia trend=60% uniforme mas 40% ponderado (abaixo do threshold).
        Sequencia corrigida: ultimo step High->Critical — escalada real
        para nivel critico + pressao assimetrica = BLOCK imediato.
        Invariante: escalada crescente com pressao -> drift detectado.
        """
        s = _sentinel(window_k=6, threshold_pct=60)
        levels = ["None", "Low", "Medium", "High", "High", "Critical"]
        for lv in levels:
            r = s.record_and_analyze("s1", lv, "ALLOW")  # ALLOW = pressao eficiencia
        assert r.policy_drift_detected
        assert r.drift_action in {DriftAction.ESCALATE_HUMAN, DriftAction.BLOCK}

    def test_high_trend_without_asymmetry_escalates(self):
        s = _sentinel(window_k=5, threshold_pct=60)
        # Trend 100% crescente, ultimo=High, acoes BLOCK (sem pressao assimetrica)
        for lv in ["None", "Low", "Medium", "High", "High"]:
            r = s.record_and_analyze("s1", lv, "BLOCK")
        # trend >= 80% e last >= High -> deve detectar
        assert r.policy_drift_detected


# ─── Invariantes ───────────────────────────────────────────────────────────────────────

class TestInvariants:
    def test_explain_always_present(self):
        r = _sentinel().record_and_analyze("s1", "None", "ALLOW")
        assert len(r.explain_decision) > 30
        assert "GoalDriftSentinel" in r.explain_decision

    def test_signature_64_hex(self):
        r = _sentinel().record_and_analyze("s1", "Low", "ALLOW")
        assert len(r.signature) == 64
        int(r.signature, 16)

    def test_report_is_frozen(self):
        r = _sentinel().record_and_analyze("s1", "Low", "ALLOW")
        with pytest.raises((AttributeError, TypeError)):
            r.drift_action = DriftAction.BLOCK  # type: ignore

    def test_to_dict_keys(self):
        r = _sentinel().record_and_analyze("s1", "Low", "ALLOW")
        d = r.to_dict()
        for k in ("session_id", "policy_drift_detected", "drift_action",
                  "trend_pct", "explain_decision", "signature"):
            assert k in d

    def test_sequence_recorded_in_report(self):
        s = _sentinel()
        s.record_and_analyze("s1", "Low",    "ALLOW")
        s.record_and_analyze("s1", "Medium", "ALLOW")
        r = s.record_and_analyze("s1", "High", "ALLOW")
        assert DRIFT_SCORE["Low"]    in r.drift_score_sequence
        assert DRIFT_SCORE["High"]   in r.drift_score_sequence


# ─── Ring buffer e sessoes ──────────────────────────────────────────────────────────────

class TestWindowBehavior:
    def test_window_bounded_by_k(self):
        s = _sentinel(window_k=5)
        for i in range(10):
            s.record_and_analyze("s1", "Low", "ALLOW")
        assert len(s.window_snapshot("s1")) == 5

    def test_different_sessions_isolated(self):
        s = _sentinel()
        for _ in range(5):
            s.record_and_analyze("sA", "None", "ALLOW")
        s.record_and_analyze("sB", "Critical", "ALLOW")
        rA = s.record_and_analyze("sA", "None", "ALLOW")
        assert rA.drift_action == DriftAction.ALLOW  # sA nao afetada pela sB

    def test_reset_session_clears_window(self):
        s = _sentinel()
        for _ in range(5):
            s.record_and_analyze("s1", "High", "ALLOW")
        s.reset_session("s1")
        assert s.window_snapshot("s1") == []
        r = s.record_and_analyze("s1", "Low", "ALLOW")
        assert r.drift_action == DriftAction.ALLOW


# ─── Fail-Secure ──────────────────────────────────────────────────────────────────────

class TestFailSecure:
    def test_fail_secure_on_internal_exception(self, monkeypatch):
        s = _sentinel()
        monkeypatch.setattr(s, "_analyze", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
        r = s.record_and_analyze("s1", "Low", "ALLOW")
        assert r.drift_action == DriftAction.ESCALATE_HUMAN
        assert r.policy_drift_detected is True
        assert "FAIL-SECURE" in r.explain_decision
        assert len(r.signature) == 64


# ─── Helpers ─────────────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_trend_pct_ascending(self):
        assert _compute_trend_pct([0, 1, 2, 3, 4]) == 100

    def test_trend_pct_flat(self):
        assert _compute_trend_pct([2, 2, 2, 2]) == 0

    def test_trend_pct_single(self):
        assert _compute_trend_pct([3]) == 0

    def test_asymmetric_pressure_majority_allow(self):
        assert _detect_asymmetric_pressure(["ALLOW", "ALLOW", "ALLOW", "BLOCK", "ALLOW"])

    def test_no_asymmetric_pressure_majority_block(self):
        assert not _detect_asymmetric_pressure(["BLOCK", "BLOCK", "BLOCK", "ALLOW", "BLOCK"])

    def test_asymmetric_too_short(self):
        assert not _detect_asymmetric_pressure(["ALLOW", "ALLOW"])


# ── C14: ModelPerformanceSentinel ─────────────────────────────────────────────

class TestModelPerformanceSentinel:
    def _sentinel(self) -> GoalDriftSentinel:
        return GoalDriftSentinel(hmac_secret=SECRET)

    def test_no_degradation_stable(self):
        s = self._sentinel()
        for _ in range(5):
            r = s.monitor_model_performance("model-a", 0.95)
        assert isinstance(r, ModelPerformanceReport)
        assert r.degradation_detected is False
        assert r.model_id == "model-a"

    def test_degradation_25pct_detected(self):
        s = self._sentinel()
        # Build baseline with high metrics
        for _ in range(6):
            s.monitor_model_performance("model-b", 1.0)
        # Sudden drop to 0.70 — ~30% below baseline
        r = s.monitor_model_performance("model-b", 0.70)
        assert r.degradation_detected is True
        assert r.degradation_pct > 20.0

    def test_below_threshold_not_detected(self):
        s = self._sentinel()
        for _ in range(6):
            s.monitor_model_performance("model-c", 1.0)
        # 8% drop — below default 20% threshold
        r = s.monitor_model_performance("model-c", 0.92)
        assert r.degradation_detected is False

    def test_insufficient_samples_no_baseline(self):
        s = self._sentinel()
        # Only 2 samples — not enough for baseline detection
        s.monitor_model_performance("model-d", 0.95)
        r = s.monitor_model_performance("model-d", 0.50)
        assert r.degradation_detected is False

    def test_report_signed(self):
        s = self._sentinel()
        r = s.monitor_model_performance("model-e", 0.90)
        assert len(r.signature) == 64
        assert all(c in "0123456789abcdef" for c in r.signature)

    def test_explain_decision_mandatory(self):
        s = self._sentinel()
        r = s.monitor_model_performance("model-f", 0.85)
        assert r.explain_decision  # non-empty (Levinas)
        assert "model-f" in r.explain_decision

    def test_degradation_explain_includes_alert(self):
        s = self._sentinel()
        for _ in range(6):
            s.monitor_model_performance("model-g", 1.0)
        r = s.monitor_model_performance("model-g", 0.50)
        assert r.degradation_detected is True
        assert "backdoor" in r.explain_decision.lower() or "degradação" in r.explain_decision

    def test_custom_threshold(self):
        s = self._sentinel()
        for _ in range(6):
            s.monitor_model_performance("model-h", 1.0)
        # 15% drop — below default 20% but above custom 10%
        r = s.monitor_model_performance("model-h", 0.85, threshold=0.10)
        assert r.degradation_detected is True
