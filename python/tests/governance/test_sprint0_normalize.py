"""
Testes Sprint 0 — Gaps 2, 4, 15
12 passed em 09/03/2026 (Python 3.11.9, pytest 7.4.4)
"""
import pytest
from buildtovalue.governance._normalize import normalize_drift_level, normalize_action
from buildtovalue.governance.goal_drift_sentinel import GoalDriftSentinel, DRIFT_SCORE


# ── _normalize: normalize_drift_level ────────────────────────────────────────

def test_drift_uppercase_rust():
    """Gap 15: Rust envia 'LOW' → deve mapear para 'Low' (score 1, não 0)."""
    assert normalize_drift_level("LOW")      == "Low"
    assert normalize_drift_level("MEDIUM")   == "Medium"
    assert normalize_drift_level("HIGH")     == "High"
    assert normalize_drift_level("CRITICAL") == "Critical"
    assert normalize_drift_level("NONE")     == "None"


def test_drift_titlecase_passthrough():
    """Callers Python existentes não quebram."""
    for k in ("None", "Low", "Medium", "High", "Critical"):
        assert normalize_drift_level(k) == k


def test_drift_invalid_failsecure():
    """Gap 2: valor inválido → 'High' (score 3), nunca silêncio 0."""
    result = normalize_drift_level("UNKNOWN_LEVEL")
    assert result == "High"
    assert DRIFT_SCORE[result] == 3


def test_drift_invalid_non_string():
    """Tipo errado → fail-secure High."""
    assert normalize_drift_level(None) == "High"   # type: ignore
    assert normalize_drift_level(42)   == "High"   # type: ignore


# ── _normalize: normalize_action ─────────────────────────────────────────

def test_action_lowercase_fixed():
    """Gap 4: 'allow' não era detectado como pressão — agora é canonicalizado."""
    assert normalize_action("allow")      == "ALLOW"
    assert normalize_action("log")        == "LOG"
    assert normalize_action("block")      == "BLOCK"
    assert normalize_action("  Redact  ") == "REDACT"


def test_action_invalid_failsecure():
    assert normalize_action("PERMIT") == "BLOCK"
    assert normalize_action("")       == "BLOCK"
    assert normalize_action(None)     == "BLOCK"  # type: ignore


# ── GoalDriftSentinel: comportamento de ponta a ponta ─────────────────────

SECRET = b"test-secret-sprint0"


def test_sentinel_was_blind_before_fix():
    """Documenta o bug histórico: DRIFT_SCORE.get('HIGH', 0) retornava 0."""
    assert DRIFT_SCORE.get("HIGH", 0) == 0


def test_sentinel_sees_rust_critical_after_fix():
    """Rust envia 'CRITICAL' uppercase → normalizado → disparo imediato."""
    s = GoalDriftSentinel(SECRET)
    report = s.record_and_analyze("sess-critical", "CRITICAL", "ALLOW")
    assert report.policy_drift_detected is True
    assert report.drift_action.value == "BLOCK"
    assert 4 in report.drift_score_sequence


def test_sentinel_sees_rust_escalation_trend_after_fix():
    """Escalada contínua uppercase: trend >= 60% + High → drift detectado."""
    s = GoalDriftSentinel(SECRET)
    sid = "sess-trend"
    for lvl in ["NONE", "LOW", "LOW", "MEDIUM", "HIGH", "HIGH"]:
        s.record_and_analyze(sid, lvl, "ALLOW")
    for lvl in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        report = s.record_and_analyze(sid, lvl, "ALLOW")
    assert report.policy_drift_detected is True


def test_sentinel_plateau_not_drift():
    """
    Plateau em High (trend=50%) NÃO é drift — spec correta.
    window=(0,1,2,3,3,3,3): suspeito mas abaixo do threshold de 60%.
    Sprint 3 introduzirá trend ponderado para tratar este caso border.
    """
    s = GoalDriftSentinel(SECRET)
    sid = "sess-plateau"
    for lvl in ["NONE", "LOW", "MEDIUM", "HIGH", "HIGH", "HIGH", "HIGH"]:
        report = s.record_and_analyze(sid, lvl, "ALLOW")
    assert report.trend_pct == 50
    assert report.policy_drift_detected is False


def test_sentinel_action_lowercase_pressure():
    """Gap 4: 'allow' minúsculo agora conta como pressão de eficiência."""
    s = GoalDriftSentinel(SECRET)
    sid = "sess-lower"
    for _ in range(7):
        s.record_and_analyze(sid, "HIGH", "allow")
    report = s.record_and_analyze(sid, "HIGH", "allow")
    assert report.asymmetric_pressure is True


def test_sentinel_unknown_drift_conservative():
    """Gap 2: drift_level desconhecido → score High (3), não 0."""
    s = GoalDriftSentinel(SECRET)
    report = s.record_and_analyze("sess-x", "GARBAGE_LEVEL", "ALLOW")
    assert 3 in report.drift_score_sequence
