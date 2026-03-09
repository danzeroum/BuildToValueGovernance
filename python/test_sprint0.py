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
    old_score = DRIFT_SCORE.get("HIGH", 0)
    assert old_score == 0

def test_sentinel_sees_rust_drift_after_fix():
    s = GoalDriftSentinel(b"test-secret-sprint0")
    sid = "session-rust-uppercase"
    sequence = ["NONE", "LOW", "MEDIUM", "HIGH", "HIGH", "HIGH", "HIGH"]
    actions  = ["ALLOW"] * 7
    reports = [s.record_and_analyze(sid, lvl, act)
               for lvl, act in zip(sequence, actions)]
    last = reports[-1]
    assert last.policy_drift_detected is True, \
        f"Drift nao detectado! trend={last.trend_pct}%, window={last.drift_score_sequence}"
    assert last.drift_action.value in ("ESCALATE_HUMAN", "BLOCK")

def test_sentinel_action_lowercase_pressure():
    s = GoalDriftSentinel(b"test-secret-sprint0")
    sid = "session-lowercase-action"
    for _ in range(7):
        s.record_and_analyze(sid, "HIGH", "allow")
    report = s.record_and_analyze(sid, "HIGH", "allow")
    assert report.asymmetric_pressure is True

def test_sentinel_unknown_drift_conservative():
    s = GoalDriftSentinel(b"test-secret-sprint0")
    report = s.record_and_analyze("session-x", "GARBAGE_LEVEL", "ALLOW")
    assert 3 in report.drift_score_sequence
