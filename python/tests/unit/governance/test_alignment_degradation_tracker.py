"""Testes unitários para AlignmentDegradationTracker.

pytest python/tests/unit/governance/test_alignment_degradation_tracker.py -v
"""
import pytest

from buildtovalue.governance.alignment_degradation_tracker import (
    AlignmentDegradationTracker,
    AlignmentSnapshot,
    _MIN_SAMPLES,
    _PROBLEMATIC_VERDICTS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tracker() -> AlignmentDegradationTracker:
    return AlignmentDegradationTracker(threshold=0.4, window=20, min_samples=3)


@pytest.fixture
def strict_tracker() -> AlignmentDegradationTracker:
    return AlignmentDegradationTracker(threshold=0.1, window=20, min_samples=2)


def _fill_agent(
    tracker: AlignmentDegradationTracker,
    agent_id: str,
    collab_verdicts: list[str],
    solo_verdicts: list[str],
) -> None:
    for v in collab_verdicts:
        tracker.record(agent_id, v, is_collaborative=True)
    for v in solo_verdicts:
        tracker.record(agent_id, v, is_collaborative=False)


# ---------------------------------------------------------------------------
# Testes: record()
# ---------------------------------------------------------------------------

class TestRecord:
    def test_record_stores_snapshot(self, tracker: AlignmentDegradationTracker) -> None:
        tracker.record("agent-1", "ALLOW", is_collaborative=True)
        snaps = tracker.snapshots("agent-1")
        assert len(snaps) == 1
        assert snaps[0].verdict == "ALLOW"
        assert snaps[0].is_collaborative is True
        assert snaps[0].agent_id == "agent-1"

    def test_record_ring_buffer_respects_window(self) -> None:
        tracker = AlignmentDegradationTracker(window=5)
        for _ in range(10):
            tracker.record("agent-x", "ALLOW", is_collaborative=True)
        assert len(tracker.snapshots("agent-x")) == 5

    def test_record_multiple_agents_isolated(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        tracker.record("agent-a", "ALLOW", is_collaborative=True)
        tracker.record("agent-b", "BLOCK", is_collaborative=False)
        assert tracker.snapshots("agent-a")[0].verdict == "ALLOW"
        assert tracker.snapshots("agent-b")[0].verdict == "BLOCK"

    def test_snapshot_is_frozen(self, tracker: AlignmentDegradationTracker) -> None:
        tracker.record("agent-1", "ALLOW", is_collaborative=True)
        snap = tracker.snapshots("agent-1")[0]
        with pytest.raises(Exception):
            snap.verdict = "BLOCK"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Testes: degradation_score()
# ---------------------------------------------------------------------------

class TestDegradationScore:
    def test_zero_score_when_all_allow(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        _fill_agent(tracker, "a1", ["ALLOW"] * 5, ["ALLOW"] * 5)
        assert tracker.degradation_score("a1") == 0.0

    def test_zero_score_when_same_rate_both_contexts(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        # 50% BLOCK em ambos → degradação = 0
        _fill_agent(
            tracker, "a1",
            ["BLOCK", "ALLOW", "BLOCK", "ALLOW", "BLOCK"],
            ["BLOCK", "ALLOW", "BLOCK", "ALLOW", "BLOCK"],
        )
        assert tracker.degradation_score("a1") == pytest.approx(0.0)

    def test_high_score_when_bad_collab(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        # 100% BLOCK collab, 0% BLOCK solo → score=1.0
        _fill_agent(tracker, "a1", ["BLOCK"] * 5, ["ALLOW"] * 5)
        assert tracker.degradation_score("a1") == pytest.approx(1.0)

    def test_partial_score_calculation(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        # 4/5 BLOCK collab = 0.8, 1/5 BLOCK solo = 0.2 → score=0.6
        _fill_agent(
            tracker, "a1",
            ["BLOCK", "BLOCK", "BLOCK", "BLOCK", "ALLOW"],
            ["BLOCK", "ALLOW", "ALLOW", "ALLOW", "ALLOW"],
        )
        assert tracker.degradation_score("a1") == pytest.approx(0.6)

    def test_zero_score_when_insufficient_collab_samples(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        # Apenas 2 amostras collab (min=3) → score=0.0
        _fill_agent(tracker, "a1", ["BLOCK", "BLOCK"], ["ALLOW"] * 5)
        assert tracker.degradation_score("a1") == 0.0

    def test_zero_score_when_insufficient_solo_samples(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        _fill_agent(tracker, "a1", ["BLOCK"] * 5, ["ALLOW", "ALLOW"])
        assert tracker.degradation_score("a1") == 0.0

    def test_zero_score_for_unknown_agent(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        assert tracker.degradation_score("unknown-agent") == 0.0

    def test_score_never_negative(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        # Solo piora mais que collab → score deve ser 0.0 (não negativo)
        _fill_agent(tracker, "a1", ["ALLOW"] * 5, ["BLOCK"] * 5)
        assert tracker.degradation_score("a1") == 0.0

    def test_refuse_verdict_counts_as_problematic(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        _fill_agent(tracker, "a1", ["REFUSE"] * 5, ["ALLOW"] * 5)
        assert tracker.degradation_score("a1") == pytest.approx(1.0)

    def test_educate_verdict_not_problematic(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        # EDUCATE não é problemático
        _fill_agent(tracker, "a1", ["EDUCATE"] * 5, ["ALLOW"] * 5)
        assert tracker.degradation_score("a1") == 0.0


# ---------------------------------------------------------------------------
# Testes: check()
# ---------------------------------------------------------------------------

class TestCheck:
    def test_check_returns_none_when_below_threshold(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        _fill_agent(tracker, "a1", ["ALLOW"] * 5, ["ALLOW"] * 5)
        assert tracker.check("a1") is None

    def test_check_returns_reason_when_above_threshold(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        # score=1.0 > threshold=0.4
        _fill_agent(tracker, "a1", ["BLOCK"] * 5, ["ALLOW"] * 5)
        reason = tracker.check("a1")
        assert reason is not None
        assert "ALIGNMENT_DEGRADATION" in reason
        assert "a1" in reason
        assert "score" in reason.lower() or "degradação" in reason.lower()

    def test_check_returns_none_for_unknown_agent(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        assert tracker.check("ghost-agent") is None

    def test_check_returns_none_with_insufficient_data(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        tracker.record("a1", "BLOCK", is_collaborative=True)
        tracker.record("a1", "BLOCK", is_collaborative=True)
        assert tracker.check("a1") is None

    def test_check_strict_threshold(
        self, strict_tracker: AlignmentDegradationTracker
    ) -> None:
        # threshold=0.1; 3/5 BLOCK collab = 0.6, 1/5 BLOCK solo = 0.2 → score=0.4 > 0.1
        _fill_agent(
            strict_tracker, "a1",
            ["BLOCK", "BLOCK", "BLOCK", "ALLOW", "ALLOW"],
            ["BLOCK", "ALLOW", "ALLOW", "ALLOW", "ALLOW"],
        )
        assert strict_tracker.check("a1") is not None

    def test_reason_string_contains_threshold(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        _fill_agent(tracker, "a1", ["BLOCK"] * 5, ["ALLOW"] * 5)
        reason = tracker.check("a1")
        assert "0.4" in reason or "threshold" in reason.lower()


# ---------------------------------------------------------------------------
# Testes: snapshots()
# ---------------------------------------------------------------------------

class TestSnapshots:
    def test_snapshots_returns_empty_list_for_unknown_agent(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        assert tracker.snapshots("no-one") == []

    def test_snapshots_returns_copy(
        self, tracker: AlignmentDegradationTracker
    ) -> None:
        tracker.record("a1", "ALLOW", is_collaborative=True)
        snaps = tracker.snapshots("a1")
        snaps.clear()
        # Original não deve ser afetado
        assert len(tracker.snapshots("a1")) == 1
