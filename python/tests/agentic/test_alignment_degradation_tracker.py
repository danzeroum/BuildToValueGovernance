"""
Tests for AlignmentDegradationTracker.

Covers:
  1. Solo agent with no collaboration → degradation_score ≈ 0.0
  2. Collaborative jailbreak abort → increases degradation_score
  3. Ring buffer evicts oldest session at window=20
  4. threshold_exceeded flag set when score > 0.4
  5. Fail-secure on ledger error
  6. Formula correctness with manually computed values
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from buildtovalue.agentic.alignment_degradation_tracker import (
    AlignmentDegradationTracker,
    DegradationReport,
)
from buildtovalue.governance.durable_ledger import DurableLedger


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-tracker-ledger")


@pytest.fixture
def tracker(ledger: DurableLedger) -> AlignmentDegradationTracker:
    return AlignmentDegradationTracker(ledger=ledger, window=20, threshold=0.4)


# ─── Tests ────────────────────────────────────────────────────────────────────

def test_solo_agent_no_degradation(tracker: AlignmentDegradationTracker) -> None:
    """Agent with only solo sessions and no problems → score = 0.0."""
    for i in range(5):
        tracker.record_session(
            agent_id="agent-solo",
            session_id=f"sess-{i}",
            is_collaborative=False,
            abort_reason=None,
            drift_score=0.05,
        )
    report = tracker.compute_degradation("agent-solo")

    assert isinstance(report, DegradationReport)
    assert report.agent_id == "agent-solo"
    # collab_rate = 0/0 → 0.0; solo_rate = 0/5 → 0.0; score = 0.0
    assert report.degradation_score == pytest.approx(0.0)
    assert report.problematic_collab_rate == pytest.approx(0.0)
    assert report.problematic_solo_rate == pytest.approx(0.0)
    assert not report.threshold_exceeded
    assert report.window_sessions == 5
    assert len(report.signature) == 64  # HMAC-SHA256 hex


def test_collab_jailbreak_increases_degradation_score(
    tracker: AlignmentDegradationTracker,
) -> None:
    """Collaborative jailbreak abort raises collab_rate → positive degradation."""
    # 1 clean solo session
    tracker.record_session(
        agent_id="agent-collab",
        session_id="solo-1",
        is_collaborative=False,
        abort_reason=None,
        drift_score=0.0,
    )
    # 2 collaborative jailbreak sessions out of 2
    for i in range(2):
        tracker.record_session(
            agent_id="agent-collab",
            session_id=f"collab-{i}",
            is_collaborative=True,
            abort_reason="jailbreak_blocked",
            drift_score=0.0,
        )

    report = tracker.compute_degradation("agent-collab")

    # collab_rate = 2/2 = 1.0; solo_rate = 0/1 = 0.0; score = 1.0
    assert report.degradation_score == pytest.approx(1.0)
    assert report.problematic_collab_rate == pytest.approx(1.0)
    assert report.problematic_solo_rate == pytest.approx(0.0)
    assert report.threshold_exceeded  # 1.0 > 0.4


def test_ring_buffer_evicts_oldest_session_at_window_20(
    tracker: AlignmentDegradationTracker,
) -> None:
    """After 21 records the oldest is evicted; window_sessions stays at 20."""
    for i in range(21):
        tracker.record_session(
            agent_id="agent-ring",
            session_id=f"sess-{i}",
            is_collaborative=True,
            abort_reason=None,
            drift_score=0.0,
        )
    report = tracker.compute_degradation("agent-ring")
    assert report.window_sessions == 20


def test_threshold_exceeded_flag_set_above_04(
    tracker: AlignmentDegradationTracker,
) -> None:
    """threshold_exceeded is True iff degradation_score > 0.4."""
    # 3 collab sessions: 2 problematic (rate=0.667), 0 solo
    tracker.record_session("agent-t", "s1", True, "goal_drift triggered", 0.0)
    tracker.record_session("agent-t", "s2", True, "incompatible_policy", 0.0)
    tracker.record_session("agent-t", "s3", True, None, 0.05)

    report = tracker.compute_degradation("agent-t")
    # collab_rate = 2/3 ≈ 0.667; solo_rate = 0/0 = 0.0; score ≈ 0.667 > 0.4
    assert report.threshold_exceeded
    assert report.degradation_score > 0.4


def test_fail_secure_on_ledger_error() -> None:
    """Ledger error during record_session is swallowed; compute still works via buffer."""
    broken_ledger = MagicMock(spec=DurableLedger)
    broken_ledger.append.side_effect = RuntimeError("ledger unavailable")

    tracker = AlignmentDegradationTracker(ledger=broken_ledger, window=20)

    # record_session should not raise even when ledger fails
    tracker.record_session(
        agent_id="agent-err",
        session_id="sess-err",
        is_collaborative=True,
        abort_reason=None,
        drift_score=0.1,
    )

    # Buffer was updated before ledger call, so compute still works
    report = tracker.compute_degradation("agent-err")
    assert isinstance(report, DegradationReport)
    # Session was recorded in the buffer — we expect it to be counted
    assert report.window_sessions == 1


def test_degradation_score_formula_correctness(
    tracker: AlignmentDegradationTracker,
) -> None:
    """
    Manual computation:
      collab sessions: 4 total, 1 problematic → collab_rate = 0.25
      solo sessions:   6 total, 3 problematic → solo_rate   = 0.50
      degradation_score = 0.25 - 0.50 = -0.25  (agent safer in collab)
      threshold_exceeded = False (-0.25 < 0.4)
    """
    agent = "agent-formula"

    # 4 collab: 1 with goal_drift, 3 clean
    tracker.record_session(agent, "c1", True, "goal_drift triggered", 0.0)
    for i in range(3):
        tracker.record_session(agent, f"c{i+2}", True, None, 0.05)

    # 6 solo: 3 problematic (high drift), 3 clean
    for i in range(3):
        tracker.record_session(agent, f"s{i+1}", False, None, 0.9)  # drift > threshold
    for i in range(3):
        tracker.record_session(agent, f"s{i+4}", False, None, 0.05)

    report = tracker.compute_degradation(agent)

    assert report.problematic_collab_rate == pytest.approx(1 / 4)
    assert report.problematic_solo_rate == pytest.approx(3 / 6)
    assert report.degradation_score == pytest.approx(0.25 - 0.50, abs=1e-9)
    assert not report.threshold_exceeded
    assert report.window_sessions == 10
    assert "agent-formula" in report.explain_decision
    assert "degradation_score" in report.explain_decision


# ─── Fail-secure path of compute_degradation (#183 — Jonas invariant) ──────────
#
# test_fail_secure_on_ledger_error (above) covers a ledger failure during
# record_session (swallowed, buffer intact). It does NOT cover the distinct
# path where compute_degradation's own computation raises: the try/except must
# return a worst-case report (score=1.0, threshold_exceeded=True) so a failed
# assessment forces manual review rather than silently passing.

def test_compute_degradation_returns_fail_secure_on_internal_error(
    tracker: AlignmentDegradationTracker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If _compute raises, compute_degradation returns a fail-secure report."""
    tracker.record_session("agent-x", "s1", True, None, 0.1)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("scoring backend exploded")

    # Force the real try/except in compute_degradation (not a mock of itself):
    # _sign_report is invoked inside _compute, so this raises mid-computation.
    monkeypatch.setattr(tracker, "_sign_report", boom)

    report = tracker.compute_degradation("agent-x")

    assert isinstance(report, DegradationReport)
    # Jonas: worst-case forces manual review.
    assert report.degradation_score == 1.0
    assert report.threshold_exceeded is True
    assert report.problematic_collab_rate == 1.0
    assert report.problematic_solo_rate == 0.0
    assert report.window_sessions == 0
    assert "FAIL-SECURE" in report.explain_decision
    assert "agent-x" in report.explain_decision


def test_fail_secure_report_is_signed(
    tracker: AlignmentDegradationTracker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The fail-secure report carries a non-empty HMAC signature (Jonas)."""
    def boom(*_args: object, **_kwargs: object) -> None:
        raise ValueError("kaboom")

    monkeypatch.setattr(tracker, "_compute", boom)

    report = tracker.compute_degradation("agent-y")

    assert report.signature, "fail-secure report must be signed"
    # Signature is a hex SHA-256 digest.
    assert len(report.signature) == 64
    assert int(report.signature, 16) >= 0  # valid hex
