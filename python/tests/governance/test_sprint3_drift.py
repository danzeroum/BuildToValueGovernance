"""
Testes Sprint 3 — trend ponderado + burst detection
GoalDriftSentinel v1.2.0
"""
import pytest
from buildtovalue.governance.goal_drift_sentinel import (
    GoalDriftSentinel, _compute_trend_pct, _is_burst, DRIFT_SCORE,
)

S = b"test-secret-sprint3"


# ── _compute_trend_pct (ponderado) ───────────────────────────────────────────

def test_trend_plateau_lower_than_uniform():
    """(0,1,2,3,3,3,3): ponderado=28% vs uniforme=50% — plateau reconhecido."""
    assert _compute_trend_pct([0, 1, 2, 3, 3, 3, 3]) == 28

def test_trend_uniform_full_ascent():
    """Escalada contínua: ponderado == 100%."""
    assert _compute_trend_pct([0, 1, 2, 3, 4]) == 100

def test_trend_burst_at_end_higher_than_uniform():
    """
    (3,3,3,3,3,3,1,2,3) — ascendentes apenas nos 2 últimos steps (i=7,i=8):
      uniforme  = 2/8 = 25%
      ponderado = (7+8)/36 = 41% — ponderado > uniforme, burst tardio amplificado.
    """
    scores = [3, 3, 3, 3, 3, 3, 1, 2, 3]
    weighted = _compute_trend_pct(scores)
    uniform  = (2 * 100) // 8   # 25
    assert weighted > uniform
    assert weighted == 41

def test_trend_single_step_zero():
    assert _compute_trend_pct([3]) == 0

def test_trend_empty_zero():
    assert _compute_trend_pct([]) == 0


# ── _is_burst ────────────────────────────────────────────────────────────────

def test_burst_true():
    """Últimos 3 estritamente ascendentes."""
    assert _is_burst([0, 0, 0, 1, 2, 3]) is True

def test_burst_false_plateau_at_end():
    """Plateau no final: não é burst."""
    assert _is_burst([0, 1, 2, 3, 3, 3]) is False

def test_burst_false_too_short():
    assert _is_burst([1, 2]) is False

def test_burst_false_descent():
    assert _is_burst([3, 3, 2, 1]) is False


# ── GoalDriftSentinel: burst detection e2e ───────────────────────────────────

def test_burst_triggers_drift_with_pressure():
    """
    Sprint 3: burst (1→2→3) nos últimos 3 steps + High + pressão assimétrica
    → drift detectado mesmo sem atingir threshold global de 60%.
    """
    sentinel = GoalDriftSentinel(S)
    sid = "sess-burst"
    for _ in range(5):
        sentinel.record_and_analyze(sid, "High", "ALLOW")
    sentinel.record_and_analyze(sid, "Low",    "ALLOW")
    sentinel.record_and_analyze(sid, "Medium", "ALLOW")
    report = sentinel.record_and_analyze(sid, "High", "ALLOW")

    assert report.policy_drift_detected is True, (
        f"Burst nao detectado: trend={report.trend_pct}%, "
        f"window={report.drift_score_sequence}"
    )

def test_burst_without_pressure_not_drift():
    """Burst sem pressão assimétrica não é drift (pode ser recover normal)."""
    sentinel = GoalDriftSentinel(S)
    sid = "sess-burst-no-pressure"
    for _ in range(5):
        sentinel.record_and_analyze(sid, "High", "BLOCK")
    sentinel.record_and_analyze(sid, "Low",    "BLOCK")
    sentinel.record_and_analyze(sid, "Medium", "BLOCK")
    report = sentinel.record_and_analyze(sid, "High", "BLOCK")
    assert report.asymmetric_pressure is False
    assert report.policy_drift_detected is False

def test_plateau_still_not_drift_after_sprint3():
    """Regressão Sprint 0: plateau (0,1,2,3,3,3,3) continua não sendo drift."""
    sentinel = GoalDriftSentinel(S)
    sid = "sess-plateau-regression"
    for lvl in ["None", "Low", "Medium", "High", "High", "High", "High"]:
        report = sentinel.record_and_analyze(sid, lvl, "ALLOW")
    assert report.trend_pct == 28
    assert report.policy_drift_detected is False
