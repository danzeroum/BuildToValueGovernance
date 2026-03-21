"""Tests for SkillBehaviorMonitor — Scenario C10/C33: Supply Chain Trojan."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.skill_behavior_monitor import (
    SkillAnomalyFinding,
    SkillBehaviorMonitor,
)


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _make_ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-key")


def _make_monitor(threshold: float = 0.30) -> SkillBehaviorMonitor:
    return SkillBehaviorMonitor(anomaly_threshold=threshold)


# ------------------------------------------------------------------ #
# TestRecordAction                                                    #
# ------------------------------------------------------------------ #

class TestRecordAction:
    def test_action_recorded_in_session_cache(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_action("skill-1", "CALENDAR_WRITE", ledger)

        assert "skill-1" in monitor._session_actions
        assert monitor._session_actions["skill-1"]["CALENDAR_WRITE"] == 1

    def test_action_appended_to_ledger(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_action("skill-1", "CALENDAR_WRITE", ledger)

        skill_entries = [
            e for e in ledger.entries()
            if e.payload.get("type") == "skill_action"
        ]
        assert len(skill_entries) == 1
        assert skill_entries[0].payload["skill_id"] == "skill-1"
        assert skill_entries[0].payload["action_category"] == "CALENDAR_WRITE"

    def test_ledger_failure_does_not_raise(self) -> None:
        monitor = _make_monitor()
        ledger = MagicMock(spec=DurableLedger)
        ledger.append.side_effect = RuntimeError("DB error")

        # Should not raise — logs warning internally
        monitor.record_action("skill-1", "CALENDAR_WRITE", ledger)

        # Session cache should still be updated
        assert monitor._session_actions["skill-1"]["CALENDAR_WRITE"] == 1

    def test_multiple_actions_increment_counter(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        for _ in range(5):
            monitor.record_action("skill-1", "CALENDAR_WRITE", ledger)
        assert monitor._session_actions["skill-1"]["CALENDAR_WRITE"] == 5


# ------------------------------------------------------------------ #
# TestDetectAnomaly — SIM-1 + SIM-2                                   #
# ------------------------------------------------------------------ #

class TestDetectAnomaly:
    def test_no_anomaly_single_category(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        for _ in range(5):
            monitor.record_action("dentist-booker", "CALENDAR_WRITE", ledger)
        result = monitor.detect_anomaly("dentist-booker", ledger)
        assert result is None

    def test_high_risk_new_category_flagged(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        # Baseline: CALENDAR_WRITE
        for _ in range(5):
            monitor.record_action("dentist-booker", "CALENDAR_WRITE", ledger)
        # Inject high-risk category directly into session
        monitor._session_actions["dentist-booker"]["FINANCIAL_TRANSFER"] = 2
        result = monitor.detect_anomaly("dentist-booker", ledger)
        assert result is not None
        assert result.anomalous_category == "FINANCIAL_TRANSFER"

    def test_data_exfiltration_new_category_flagged(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        for _ in range(5):
            monitor.record_action("reader-skill", "FILE_READ", ledger)
        monitor._session_actions["reader-skill"]["DATA_EXFILTRATION"] = 1
        result = monitor.detect_anomaly("reader-skill", ledger)
        assert result is not None
        assert result.anomalous_category == "DATA_EXFILTRATION"

    def test_rate_spike_above_threshold(self) -> None:
        # Use a low threshold to trigger rate spike detection
        monitor = _make_monitor(threshold=0.10)
        ledger = _make_ledger()

        # Baseline in ledger: mostly CALENDAR_WRITE
        for _ in range(10):
            monitor.record_action("skill-1", "CALENDAR_WRITE", ledger)

        # Reset session cache, then add mostly a new (non-high-risk) category
        monitor._session_actions.clear()
        for _ in range(8):
            monitor._session_actions.setdefault("skill-1", __import__("collections").Counter())
            monitor._session_actions["skill-1"]["EMAIL_SEND"] += 1
        for _ in range(2):
            monitor._session_actions["skill-1"]["CALENDAR_WRITE"] += 1

        result = monitor.detect_anomaly("skill-1", ledger)
        assert result is not None
        assert result.anomalous_category == "EMAIL_SEND"

    def test_empty_session_no_anomaly(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        assert monitor.detect_anomaly("unknown-skill", ledger) is None

    def test_unknown_skill_no_anomaly(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        # Record for one skill, check anomaly for another
        monitor.record_action("skill-a", "CALENDAR_WRITE", ledger)
        assert monitor.detect_anomaly("skill-b", ledger) is None


# ------------------------------------------------------------------ #
# TestDetectAnomalyFailSecure — SIM-5                                 #
# ------------------------------------------------------------------ #

class TestDetectAnomalyFailSecure:
    def test_internal_error_returns_finding(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()

        # Record some actions so session cache has data
        monitor.record_action("skill-1", "CALENDAR_WRITE", ledger)

        # Force error by monkeypatching _detect_inner to raise
        original = monitor._detect_inner

        def _raise_on_call(*args, **kwargs):
            raise RuntimeError("Simulated internal error")

        monitor._detect_inner = _raise_on_call  # type: ignore[assignment]

        result = monitor.detect_anomaly("skill-1", ledger)
        assert result is not None
        assert result.anomalous_category == "INTERNAL_ERROR"
        assert "fail-secure" in result.explain_decision.lower()

        # Restore
        monitor._detect_inner = original  # type: ignore[assignment]


# ------------------------------------------------------------------ #
# TestLoadBaseline                                                    #
# ------------------------------------------------------------------ #

class TestLoadBaseline:
    def test_baseline_from_ledger_entries(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        for _ in range(3):
            monitor.record_action("skill-1", "CALENDAR_WRITE", ledger)
        for _ in range(2):
            monitor.record_action("skill-1", "EMAIL_SEND", ledger)

        baseline = monitor._load_baseline("skill-1", ledger)
        assert baseline["CALENDAR_WRITE"] == 3
        assert baseline["EMAIL_SEND"] == 2

    def test_baseline_filters_by_skill_id(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_action("skill-a", "CALENDAR_WRITE", ledger)
        monitor.record_action("skill-b", "FILE_READ", ledger)

        baseline_a = monitor._load_baseline("skill-a", ledger)
        assert baseline_a["CALENDAR_WRITE"] == 1
        assert "FILE_READ" not in baseline_a


# ------------------------------------------------------------------ #
# TestExplainDecision                                                 #
# ------------------------------------------------------------------ #

class TestExplainDecision:
    def test_anomaly_finding_has_explain(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        for _ in range(5):
            monitor.record_action("skill-1", "CALENDAR_WRITE", ledger)
        monitor._session_actions["skill-1"]["FINANCIAL_TRANSFER"] = 2
        result = monitor.detect_anomaly("skill-1", ledger)
        assert result is not None
        assert result.explain_decision

    def test_explain_contains_skill_id(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        for _ in range(5):
            monitor.record_action("dentist-booker", "CALENDAR_WRITE", ledger)
        monitor._session_actions["dentist-booker"]["CREDENTIAL_ACCESS"] = 1
        result = monitor.detect_anomaly("dentist-booker", ledger)
        assert result is not None
        assert "dentist-booker" in result.explain_decision
