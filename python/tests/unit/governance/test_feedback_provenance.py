"""Testes unitarios -- FeedbackProvenanceGuard (PROP-036)."""
import json
import time
import pytest

from buildtovalue.governance.feedback_provenance import (
    FeedbackEvent,
    FeedbackPolarity,
    FeedbackProvenanceGuard,
    FeedbackRisk,
    FeedbackVerdict,
    _flip_ratio,
    _burst_detected,
)

_KEY = b"test-hmac-key-prop036"


def _guard() -> FeedbackProvenanceGuard:
    return FeedbackProvenanceGuard(hmac_key=_KEY)


def _event(uid: str, polarity: FeedbackPolarity, target: str = "gen-001") -> FeedbackEvent:
    return FeedbackEvent(user_id=uid, polarity=polarity, target_id=target)


# -- Init ---------------------------------------------------------------------

def test_rejects_empty_key():
    with pytest.raises(ValueError):
        FeedbackProvenanceGuard(hmac_key=b"")


# -- Helpers ------------------------------------------------------------------

def test_flip_ratio_alternating():
    seq = [FeedbackPolarity.POSITIVE, FeedbackPolarity.NEGATIVE] * 5
    assert _flip_ratio(seq) == 1.0


def test_flip_ratio_all_same():
    seq = [FeedbackPolarity.POSITIVE] * 10
    assert _flip_ratio(seq) == 0.0


def test_flip_ratio_single():
    assert _flip_ratio([FeedbackPolarity.POSITIVE]) == 0.0


def test_burst_detected_true():
    now = time.time()
    ts = [now + i * 0.1 for i in range(5)]
    assert _burst_detected(ts, burst_count=5, burst_window_secs=30.0) is True


def test_burst_not_detected_spread():
    now = time.time()
    ts = [now + i * 10 for i in range(5)]
    assert _burst_detected(ts, burst_count=5, burst_window_secs=30.0) is False


def test_burst_below_count():
    now = time.time()
    ts = [now, now + 1]
    assert _burst_detected(ts, burst_count=5, burst_window_secs=30.0) is False


# -- Classificacao ------------------------------------------------------------

def test_normal_pattern_is_low():
    g = _guard()
    for _ in range(5):
        v = g.evaluate(_event("u1", FeedbackPolarity.POSITIVE))
    assert v.risk == FeedbackRisk.LOW


def test_alternating_pattern_quarantines():
    g = _guard()
    for i in range(12):
        pol = FeedbackPolarity.POSITIVE if i % 2 == 0 else FeedbackPolarity.NEGATIVE
        v = g.evaluate(_event("u2", pol))
    assert v.risk == FeedbackRisk.QUARANTINE
    assert v.flip_ratio >= 0.60


def test_burst_with_alternation_quarantines():
    """Burst so quarentena quando combinado com alternancia (flip_ratio > 0)."""
    g = FeedbackProvenanceGuard(
        hmac_key=_KEY,
        burst_window_secs=60.0,
        burst_count=3,
    )
    now = time.time()
    # alternancia + burst: POSITIVE/NEGATIVE rapido
    for i in range(4):
        pol = FeedbackPolarity.POSITIVE if i % 2 == 0 else FeedbackPolarity.NEGATIVE
        ev = FeedbackEvent(
            user_id="u3",
            polarity=pol,
            target_id="gen",
            timestamp=now + i * 0.5,
        )
        v = g.evaluate(ev)
    assert v.burst_detected is True
    assert v.risk == FeedbackRisk.QUARANTINE


# -- Invariantes --------------------------------------------------------------

def test_explain_decision_always_present():
    g = _guard()
    v = g.evaluate(_event("u4", FeedbackPolarity.POSITIVE))
    assert "risk" in v.explain_decision
    assert "reason" in v.explain_decision
    assert "flip_ratio" in v.explain_decision
    assert v.explain_decision["prop"] == "PROP-036"


def test_ledger_entry_has_hmac():
    g = _guard()
    v = g.evaluate(_event("u5", FeedbackPolarity.NEGATIVE))
    entry = json.loads(v.ledger_entry)
    assert "hmac_sha256" in entry
    assert len(entry["hmac_sha256"]) == 64


def test_verdict_is_frozen():
    g = _guard()
    v = g.evaluate(_event("u6", FeedbackPolarity.POSITIVE))
    with pytest.raises((AttributeError, TypeError)):
        v.risk = FeedbackRisk.QUARANTINE  # type: ignore


def test_is_quarantined_helper():
    g = _guard()
    for i in range(12):
        pol = FeedbackPolarity.POSITIVE if i % 2 == 0 else FeedbackPolarity.NEGATIVE
        v = g.evaluate(_event("u7", pol))
    assert v.is_quarantined()


# -- Fail-secure --------------------------------------------------------------

def test_fail_secure_on_exception(monkeypatch):
    g = _guard()

    def _boom(window):
        raise RuntimeError("forced error")

    import buildtovalue.governance.feedback_provenance as mod
    monkeypatch.setattr(mod, "_flip_ratio", _boom)

    v = g.evaluate(_event("u8", FeedbackPolarity.POSITIVE))
    assert v.risk == FeedbackRisk.QUARANTINE
    assert v.explain_decision.get("is_error") is True


# -- Reset e quarantined_users ------------------------------------------------

def test_reset_clears_state():
    g = _guard()
    for i in range(12):
        pol = FeedbackPolarity.POSITIVE if i % 2 == 0 else FeedbackPolarity.NEGATIVE
        g.evaluate(_event("u9", pol))
    g.reset_user("u9")
    v = g.evaluate(_event("u9", FeedbackPolarity.POSITIVE))
    assert v.risk == FeedbackRisk.LOW


def test_quarantined_users_list():
    g = _guard()
    for _ in range(5):
        g.evaluate(_event("u10", FeedbackPolarity.POSITIVE))
    for i in range(12):
        pol = FeedbackPolarity.POSITIVE if i % 2 == 0 else FeedbackPolarity.NEGATIVE
        g.evaluate(_event("u11", pol))
    q = g.quarantined_users()
    assert "u11" in q
    assert "u10" not in q


def test_different_users_isolated():
    g = _guard()
    for i in range(12):
        pol = FeedbackPolarity.POSITIVE if i % 2 == 0 else FeedbackPolarity.NEGATIVE
        g.evaluate(_event("u12", pol))
    v_clean = g.evaluate(_event("u13", FeedbackPolarity.POSITIVE))
    assert v_clean.risk == FeedbackRisk.LOW
