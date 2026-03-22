"""
Tests for ArenaReporter (ARIA sub-component 4).

Covers:
  - Clean session generates report with security_score=1.0
  - Violations detected from BLOCK/ABORT events in ledger
  - Evidence chain integrity (entry hashes from DurableLedger)
  - utility_score=None in standalone mode
  - Report signature valid (64-char HMAC-SHA256)
  - Report with negotiation_summary
  - Fail-secure on ledger exception
  - ArenaReport is frozen
"""
from __future__ import annotations

import time
import pytest
from datetime import datetime, timezone

from buildtovalue.agentic.arena_reporter import ArenaReporter, ArenaReport, Violation
from buildtovalue.agentic.types import NegotiationMessage, NegotiationResult
from buildtovalue.governance.durable_ledger import DurableLedger


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def empty_ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-reporter-key")


@pytest.fixture
def reporter(empty_ledger: DurableLedger) -> ArenaReporter:
    return ArenaReporter(ledger=empty_ledger)


def populate_ledger_clean(ledger: DurableLedger, n: int = 3, session_id: str = "test-session") -> None:
    """Add n clean events to ledger."""
    for i in range(n):
        ledger.append({
            "event": "negotiation.confirmed",
            "session_id": session_id,
            "round_number": i + 1,
            "explain_decision": f"Clean event {i+1}: negotiation proceeding normally",
        })


def populate_ledger_with_violations(ledger: DurableLedger, session_id: str = "test-session") -> None:
    """Add some clean + some violation events."""
    ledger.append({
        "event": "negotiation.proposed",
        "session_id": session_id,
        "round_number": 1,
        "explain_decision": "NegotiationEngine: proposed at round 1",
    })
    ledger.append({
        "event": "negotiation.aborted",
        "session_id": session_id,
        "round_number": 2,
        "abort_reason": "goal_drift",
        "explain_decision": "NegotiationEngine ABORT (goal_drift): GoalDriftSentinel triggered",
    })
    ledger.append({
        "event": "protocol_designer.fail_secure",
        "session_id": session_id,
        "explain_decision": "ProtocolDesigner FAIL-SECURE: registry error",
    })


def make_negotiation_result(status: str = "confirmed") -> NegotiationResult:
    msg = NegotiationMessage(
        type="propose", policy={"integrity": True}, reason=None,
        round_number=1, timestamp=time.time(), signature="test-sig"
    )
    return NegotiationResult(
        status=status,
        shared_policy={"integrity": True} if status == "confirmed" else None,
        rounds=2,
        duration_seconds=0.5,
        drift_score=0.0,
        abort_reason=None if status == "confirmed" else "timeout",
        transcript=(msg,),
        explain_decision=f"Test negotiation {status}",
        timestamp=time.time(),
        signature="test-result-sig",
    )


# ─── Basic Report Tests ───────────────────────────────────────────────────────

def test_clean_session_high_security_score(reporter: ArenaReporter, empty_ledger: DurableLedger):
    populate_ledger_clean(empty_ledger)
    report = reporter.generate_report("test-session")
    assert report.security_score > 0.5


def test_empty_ledger_gives_perfect_score(reporter: ArenaReporter):
    report = reporter.generate_report("empty-session")
    assert report.security_score == 1.0


def test_report_has_session_id(reporter: ArenaReporter, empty_ledger: DurableLedger):
    populate_ledger_clean(empty_ledger, session_id="my-session")
    report = reporter.generate_report("my-session")
    assert report.session_id == "my-session"


def test_report_is_frozen(reporter: ArenaReporter):
    report = reporter.generate_report("test")
    with pytest.raises((AttributeError, TypeError)):
        report.security_score = 0.5  # type: ignore[misc]


def test_report_has_timestamp(reporter: ArenaReporter):
    before = time.time()
    report = reporter.generate_report("test")
    after = time.time()
    assert before <= report.timestamp <= after


def test_report_has_explanation(reporter: ArenaReporter):
    report = reporter.generate_report("test")
    assert isinstance(report.explanation, str)
    assert len(report.explanation) > 10


# ─── Utility Score Tests ──────────────────────────────────────────────────────

def test_utility_score_none_in_standalone(reporter: ArenaReporter):
    """Without passing utility_score, it should be None (standalone mode)."""
    report = reporter.generate_report("test")
    assert report.utility_score is None
    assert "standalone" in report.explanation.lower() or "N/A" in report.explanation


def test_utility_score_passed_externally(reporter: ArenaReporter):
    """Passing utility_score should appear in report."""
    report = reporter.generate_report("test", utility_score=0.85)
    assert report.utility_score == 0.85
    assert "0.85" in report.explanation


def test_utility_score_not_computed_by_btv(reporter: ArenaReporter, empty_ledger: DurableLedger):
    """BTV should never compute utility_score — explanation must say it's external."""
    populate_ledger_clean(empty_ledger)
    report = reporter.generate_report("test-session")
    # Explanation must acknowledge utility_score is external
    assert "external" in report.explanation.lower() or "Arena" in report.explanation


# ─── Violation Tests ─────────────────────────────────────────────────────────

def test_violations_detected_from_ledger(reporter: ArenaReporter, empty_ledger: DurableLedger):
    populate_ledger_with_violations(empty_ledger)
    report = reporter.generate_report("test-session")
    assert len(report.violations) >= 2


def test_violation_details_populated(reporter: ArenaReporter, empty_ledger: DurableLedger):
    populate_ledger_with_violations(empty_ledger)
    report = reporter.generate_report("test-session")
    for v in report.violations:
        assert isinstance(v.event_type, str)
        assert isinstance(v.details, str)
        assert len(v.details) > 0


def test_violations_lower_security_score(reporter: ArenaReporter, empty_ledger: DurableLedger):
    """Adding violations should lower the security score."""
    populate_ledger_with_violations(empty_ledger)
    report_with_violations = reporter.generate_report("test-session")

    clean_ledger = DurableLedger(hmac_key=b"clean-key")
    populate_ledger_clean(clean_ledger)
    clean_reporter = ArenaReporter(ledger=clean_ledger)
    clean_report = clean_reporter.generate_report("test-session")

    assert report_with_violations.security_score <= clean_report.security_score


def test_abort_event_is_violation(reporter: ArenaReporter, empty_ledger: DurableLedger):
    empty_ledger.append({
        "event": "negotiation.aborted",
        "session_id": "abort-session",
        "explain_decision": "NegotiationEngine ABORT: timeout",
    })
    report = reporter.generate_report("abort-session")
    assert len(report.violations) >= 1


# ─── Evidence Chain Tests ─────────────────────────────────────────────────────

def test_evidence_chain_from_ledger(reporter: ArenaReporter, empty_ledger: DurableLedger):
    populate_ledger_clean(empty_ledger, n=3)
    report = reporter.generate_report("test-session")
    # Evidence chain should have 3 hashes (one per ledger entry)
    assert len(report.evidence_chain) == 3


def test_evidence_chain_contains_hex_hashes(reporter: ArenaReporter, empty_ledger: DurableLedger):
    populate_ledger_clean(empty_ledger, n=2)
    report = reporter.generate_report("test-session")
    for h in report.evidence_chain:
        assert isinstance(h, str)
        assert len(h) > 0  # Should be hex string from BLAKE2b


def test_evidence_chain_empty_for_empty_ledger(reporter: ArenaReporter):
    report = reporter.generate_report("empty-session")
    assert report.evidence_chain == ()


# ─── Signature Tests ──────────────────────────────────────────────────────────

def test_report_signature_valid(reporter: ArenaReporter):
    report = reporter.generate_report("test")
    assert isinstance(report.signature, str)
    assert len(report.signature) == 64  # HMAC-SHA256 hex


def test_different_sessions_have_different_signatures(reporter: ArenaReporter):
    report_a = reporter.generate_report("session-a", utility_score=0.9)
    report_b = reporter.generate_report("session-b", utility_score=0.8)
    assert report_a.signature != report_b.signature


# ─── Negotiation Summary Tests ────────────────────────────────────────────────

def test_report_with_confirmed_negotiation(reporter: ArenaReporter):
    result = make_negotiation_result("confirmed")
    report = reporter.generate_report("test", negotiation_result=result)
    assert report.negotiation_summary is not None
    assert report.negotiation_summary.status == "confirmed"
    assert "negotiation_status=confirmed" in report.explanation


def test_report_with_aborted_negotiation(reporter: ArenaReporter):
    result = make_negotiation_result("aborted")
    report = reporter.generate_report("test", negotiation_result=result)
    assert report.negotiation_summary is not None
    assert report.negotiation_summary.status == "aborted"


def test_report_without_negotiation(reporter: ArenaReporter):
    report = reporter.generate_report("test")
    assert report.negotiation_summary is None
    assert "no negotiation" in report.explanation


# ─── Fail-Secure Tests ────────────────────────────────────────────────────────

def test_fail_secure_report_has_signature():
    """Even a fail-secure report must have a valid signature."""
    # Simulate a broken ledger
    from unittest.mock import MagicMock
    mock_ledger = MagicMock()
    mock_ledger.entries.side_effect = RuntimeError("ledger corrupted")
    reporter = ArenaReporter(ledger=mock_ledger)
    report = reporter.generate_report("broken-session")
    assert report.security_score == 0.0
    assert len(report.signature) == 64
    assert "FAIL-SECURE" in report.explanation
