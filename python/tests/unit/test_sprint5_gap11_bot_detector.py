"""
Tests — Gap 11: BotDetector anti-bot std_dev (Sprint 5)

Cobertura:
  - _std_dev: uniform/varied/edge cases
  - BotDetector: insufficient_data, bot_suspect, not_bot
  - Isolamento de sessoes, reset, fail-secure
  - explain_decision presente em todos os casos
"""
import math
import pytest

from buildtovalue.governance.bot_detector import (
    BotDetector,
    BotVerdict,
    _std_dev,
    _SessionIntervals,
)


# ─────────────────────────────────────────────
# Unit: _std_dev
# ─────────────────────────────────────────────

class TestStdDevFunction:
    def test_uniform_returns_zero(self):
        assert _std_dev([100.0] * 6) == pytest.approx(0.0, abs=1e-9)

    def test_varied_returns_positive(self):
        assert _std_dev([10.0, 200.0, 15.0, 300.0, 50.0]) > 50.0

    def test_single_value_returns_zero(self):
        assert _std_dev([42.0]) == pytest.approx(0.0)

    def test_empty_returns_zero(self):
        assert _std_dev([]) == pytest.approx(0.0)

    def test_two_values_bessel_correction(self):
        # std_dev([0, 100]) = sqrt(5000) ~= 70.71
        result = _std_dev([0.0, 100.0])
        assert result == pytest.approx(math.sqrt(5000.0), rel=1e-6)

    def test_known_value(self):
        # [2,4,4,4,5,5,7,9] bessel ~= 2.138
        result = _std_dev([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
        assert result == pytest.approx(2.138, rel=0.01)


# ─────────────────────────────────────────────
# BotDetector — INSUFFICIENT_DATA
# ─────────────────────────────────────────────

class TestBotDetectorInsufficientData:
    def test_first_request_insufficient(self):
        det = BotDetector(min_samples=5)
        sig = det.record("sess-1")
        assert sig.verdict == BotVerdict.INSUFFICIENT_DATA
        assert sig.std_dev_ms is None
        assert sig.sample_count == 0

    def test_below_min_samples(self):
        det = BotDetector(min_samples=5)
        for _ in range(4):
            sig = det.record("sess-2")
        assert sig.verdict == BotVerdict.INSUFFICIENT_DATA
        assert sig.sample_count < 5

    def test_explain_always_present(self):
        det = BotDetector(min_samples=5)
        sig = det.record("sess-explain")
        assert sig.explain_decision
        assert len(sig.explain_decision) > 10


# ─────────────────────────────────────────────
# BotDetector — BOT_SUSPECT
# ─────────────────────────────────────────────

class TestBotDetectorBotSuspect:
    def test_uniform_intervals_bot_suspect(self):
        """
        Injeta intervals uniformes (10ms) < threshold (50ms).
        std_dev = 0 -> BOT_SUSPECT.
        """
        det = BotDetector(threshold_ms=50.0, min_samples=5)
        _inject_uniform_intervals(det, "sess-bot", interval_ms=10.0, count=6)
        sig = det._do_record("sess-bot")
        assert sig.verdict == BotVerdict.BOT_SUSPECT
        assert sig.std_dev_ms is not None
        assert sig.std_dev_ms < 50.0
        assert "BOT_SUSPECT" in sig.explain_decision

    def test_explain_contains_threshold(self):
        det = BotDetector(threshold_ms=50.0, min_samples=3)
        _inject_uniform_intervals(det, "sess-t", interval_ms=10.0, count=4)
        sig = det._do_record("sess-t")
        assert "50.0ms" in sig.explain_decision

    def test_bot_suspect_sample_count_correct(self):
        det = BotDetector(threshold_ms=50.0, min_samples=5)
        _inject_uniform_intervals(det, "sess-cnt", interval_ms=5.0, count=8)
        sig = det._do_record("sess-cnt")
        assert sig.sample_count == 8


# ─────────────────────────────────────────────
# BotDetector — NOT_BOT
# ─────────────────────────────────────────────

class TestBotDetectorNotBot:
    def test_varied_intervals_not_bot(self):
        """
        Intervals com alta variancia (human-like) -> NOT_BOT.
        """
        det = BotDetector(threshold_ms=50.0, min_samples=4)
        _inject_intervals(det, "sess-human", [50.0, 350.0, 20.0, 900.0, 80.0, 500.0])
        sig = det._do_record("sess-human")
        assert sig.verdict == BotVerdict.NOT_BOT
        assert sig.std_dev_ms is not None
        assert sig.std_dev_ms >= 50.0

    def test_explain_not_bot(self):
        det = BotDetector(threshold_ms=50.0, min_samples=4)
        _inject_intervals(det, "sess-h2", [100.0, 800.0, 50.0, 600.0, 200.0])
        sig = det._do_record("sess-h2")
        assert "NOT_BOT" in sig.explain_decision


# ─────────────────────────────────────────────
# Isolamento e reset
# ─────────────────────────────────────────────

class TestBotDetectorIsolation:
    def test_sessions_isolated(self):
        det = BotDetector(threshold_ms=50.0, min_samples=3)
        _inject_uniform_intervals(det, "bot", interval_ms=10.0, count=4)
        _inject_intervals(det, "human", [100.0, 800.0, 50.0, 600.0])
        sig_bot   = det._do_record("bot")
        sig_human = det._do_record("human")
        assert sig_bot.verdict   == BotVerdict.BOT_SUSPECT
        assert sig_human.verdict == BotVerdict.NOT_BOT

    def test_reset_clears_state(self):
        det = BotDetector(threshold_ms=50.0, min_samples=3)
        _inject_uniform_intervals(det, "sess-r", interval_ms=10.0, count=5)
        det.reset_session("sess-r")
        sig = det.record("sess-r")
        assert sig.verdict == BotVerdict.INSUFFICIENT_DATA
        assert sig.sample_count == 0

    def test_reset_nonexistent_session_noop(self):
        det = BotDetector()
        det.reset_session("ghost")  # nao deve lancar


# ─────────────────────────────────────────────
# Fail-secure
# ─────────────────────────────────────────────

class TestBotDetectorFailSecure:
    def test_corrupted_state_returns_not_bot(self):
        det = BotDetector(min_samples=3)
        det._sessions["corrupted"] = None  # type: ignore
        sig = det.record("corrupted")
        assert sig.verdict == BotVerdict.NOT_BOT
        assert "FAIL-SECURE" in sig.explain_decision
        assert "Contestavel" in sig.explain_decision

    def test_invalid_threshold_raises(self):
        with pytest.raises(ValueError, match="threshold_ms"):
            BotDetector(threshold_ms=0.0)

    def test_fail_secure_explain_has_session_id(self):
        det = BotDetector(min_samples=3)
        det._sessions["broken"] = None  # type: ignore
        sig = det.record("broken")
        assert sig.session_id == "broken"


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _inject_intervals(
    det: BotDetector, session_id: str, intervals: list[float]
) -> None:
    """Injeta intervals diretamente no estado interno (bypass time.time)."""
    from collections import deque
    state = _SessionIntervals()
    state.last_ts_ms = 0.0
    for iv in intervals:
        state.intervals.append(iv)
    det._sessions[session_id] = state
    det._session_mgr.touch(session_id)


def _inject_uniform_intervals(
    det: BotDetector, session_id: str,
    interval_ms: float, count: int,
) -> None:
    _inject_intervals(det, session_id, [interval_ms] * count)
