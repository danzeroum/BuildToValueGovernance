import pytest
from buildtovalue.governance._normalize import normalize_drift_level, normalize_action
from buildtovalue.governance.goal_drift_sentinel import GoalDriftSentinel, DRIFT_SCORE

def test_drift_uppercase_rust():
    assert normalize_drift_level("LOW")      == "Low"
    assert normalize_drift_level("MEDIUM")   == "Medium"
    assert normalize_drift_level("HIGH")     == "High"
    assert normalize_drift_level("CRITICAL") == "Critical"
    assert normalize_drift_level("NONE")     == "None"

def test_drift_titlecase_passthrough():
    for k in ("None", "Low", "Medium", "High", "Critical"):
        assert normalize_drift_level(k) == k

def test_drift_invalid_failsecure():
    result = normalize_drift_level("UNKNOWN_LEVEL")
    assert result == "High"
    assert DRIFT_SCORE[result] == 3

def test_drift_invalid_non_string():
    assert normalize_drift_level(None) == "High"
    assert normalize_drift_level(42)   == "High"

def test_action_lowercase_fixed():
    assert normalize_action("allow")      == "ALLOW"
    assert normalize_action("log")        == "LOG"
    assert normalize_action("block")      == "BLOCK"
    assert normalize_action("  Redact  ") == "REDACT"

def test_action_invalid_failsecure():
    assert normalize_action("PERMIT") == "BLOCK"
    assert normalize_action("")       == "BLOCK"
    assert normalize_action(None)     == "BLOCK"

def test_sentinel_was_blind_before_fix():
    # Documenta o bug histórico: DRIFT_SCORE.get("HIGH", 0) retornava 0
    assert DRIFT_SCORE.get("HIGH", 0) == 0

def test_sentinel_sees_rust_critical_after_fix():
    """
    Rust envia 'CRITICAL' uppercase → normalizado → disparo imediato.
    Antes do fix: score=0, drift=False. Após fix: score=4, drift=True.
    """
    s = GoalDriftSentinel(b"test-secret-sprint0")
    report = s.record_and_analyze("sess-critical", "CRITICAL", "ALLOW")
    assert report.policy_drift_detected is True
    assert report.drift_action.value == "BLOCK"
    assert 4 in report.drift_score_sequence  # Critical=4 entrou no buffer

def test_sentinel_sees_rust_escalation_trend_after_fix():
    """
    Escalada contínua uppercase: trend >= 60% + High → drift detectado.
    Sequência: 6 passos todos ascendentes = 100% trend.
    """
    s = GoalDriftSentinel(b"test-secret-sprint0")
    sid = "sess-trend"
    sequence = ["NONE", "LOW", "LOW", "MEDIUM", "HIGH", "HIGH"]
    actions  = ["ALLOW"] * 6
    # Primeiro bloco: popula baseline sem drift
    for lvl, act in zip(sequence, actions):
        s.record_and_analyze(sid, lvl, act)
    # Segundo bloco: 4 passos sempre subindo (High para Critical)
    for lvl, act in zip(["LOW", "MEDIUM", "HIGH", "CRITICAL"], ["ALLOW"] * 4):
        report = s.record_and_analyze(sid, lvl, act)
    assert report.policy_drift_detected is True

def test_sentinel_plateau_not_drift():
    """
    Plateau em High (trend=50%) NÃO é drift — spec correta.
    window=(0,1,2,3,3,3,3): suspeito mas abaixo do threshold de 60%.
    """
    s = GoalDriftSentinel(b"test-secret-sprint0")
    sid = "sess-plateau"
    sequence = ["NONE", "LOW", "MEDIUM", "HIGH", "HIGH", "HIGH", "HIGH"]
    for lvl in sequence:
        report = s.record_and_analyze(sid, lvl, "ALLOW")
    assert report.trend_pct == 50
    assert report.policy_drift_detected is False  # correto: plateau != escalada

def test_sentinel_action_lowercase_pressure():
    s = GoalDriftSentinel(b"test-secret-sprint0")
    sid = "sess-lower"
    for _ in range(7):
        s.record_and_analyze(sid, "HIGH", "allow")
    report = s.record_and_analyze(sid, "HIGH", "allow")
    assert report.asymmetric_pressure is True

def test_sentinel_unknown_drift_conservative():
    s = GoalDriftSentinel(b"test-secret-sprint0")
    report = s.record_and_analyze("sess-x", "GARBAGE_LEVEL", "ALLOW")
    assert 3 in report.drift_score_sequence  # High=3, não 0
