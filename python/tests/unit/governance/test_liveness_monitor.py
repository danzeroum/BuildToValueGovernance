"""Tests for LivenessMonitor — Scenario C08: Dead Man's Switch."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from buildtovalue.governance.agent_pdp import AgentVerdict
from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.liveness_monitor import (
    AutonomyLevel,
    LivenessMonitor,
)


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _make_ledger() -> DurableLedger:
    return DurableLedger(hmac_key=b"test-key")


def _make_monitor() -> LivenessMonitor:
    return LivenessMonitor(hmac_key=b"test-liveness-key")


def _insert_backdated_confirmation(
    ledger: DurableLedger,
    agent_id: str,
    days_ago: int,
) -> None:
    """Insert a liveness_confirmation entry backdated by `days_ago` days."""
    past = datetime.now(timezone.utc) - timedelta(days=days_ago)
    iso = past.isoformat().replace("+00:00", "Z")
    ledger.append({
        "type": "liveness_confirmation",
        "agent_id": agent_id,
        "confirmed_at_iso": iso,
        "hmac_signature": "a" * 64,
        "explain_decision": f"Test backdated confirmation ({days_ago}d ago)",
    })


def _make_request_mock() -> MagicMock:
    request = MagicMock()
    request.action.metadata = {}
    return request


def _make_workflow_mock() -> MagicMock:
    workflow = MagicMock()
    ticket = MagicMock()
    ticket.ticket_id = "ticket-001"
    workflow.request_approval.return_value = ticket
    return workflow


def _make_contestability_mock() -> MagicMock:
    contestability = MagicMock()
    appeal = MagicMock()
    appeal.appeal_id = "appeal-001"
    contestability.submit_appeal.return_value = appeal
    return contestability


# ------------------------------------------------------------------ #
# TestRecordHumanConfirmation                                         #
# ------------------------------------------------------------------ #

class TestRecordHumanConfirmation:
    def test_confirmation_appended_to_ledger(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_human_confirmation("agent-1", ledger)

        entries = ledger.entries()
        confirmation_entries = [
            e for e in entries
            if e.payload.get("type") == "liveness_confirmation"
        ]
        assert len(confirmation_entries) == 1
        assert confirmation_entries[0].payload["agent_id"] == "agent-1"

    def test_confirmation_has_hmac_signature(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_human_confirmation("agent-1", ledger)

        entry = ledger.entries()[-1]
        sig = entry.payload.get("hmac_signature", "")
        assert len(sig) == 64  # HMAC-SHA256 hex

    def test_confirmation_has_explain_decision(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_human_confirmation("agent-1", ledger)

        entry = ledger.entries()[-1]
        assert entry.payload.get("explain_decision")


# ------------------------------------------------------------------ #
# TestDaysSinceLastConfirmation                                       #
# ------------------------------------------------------------------ #

class TestDaysSinceLastConfirmation:
    def test_fresh_confirmation_zero_days(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_human_confirmation("agent-1", ledger)
        days = monitor.days_since_last_confirmation("agent-1", ledger)
        assert days == 0

    def test_never_confirmed_returns_9999(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        days = monitor.days_since_last_confirmation("agent-never", ledger)
        assert days == 9999

    def test_multiple_confirmations_uses_latest(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        # Insert old confirmation (20 days ago)
        _insert_backdated_confirmation(ledger, "agent-1", 20)
        # Insert fresh confirmation
        monitor.record_human_confirmation("agent-1", ledger)
        days = monitor.days_since_last_confirmation("agent-1", ledger)
        assert days == 0

    def test_different_agents_independent(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_human_confirmation("agent-a", ledger)
        days_a = monitor.days_since_last_confirmation("agent-a", ledger)
        days_b = monitor.days_since_last_confirmation("agent-b", ledger)
        assert days_a == 0
        assert days_b == 9999

    def test_backdated_confirmation_correct_days(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        _insert_backdated_confirmation(ledger, "agent-1", 10)
        days = monitor.days_since_last_confirmation("agent-1", ledger)
        assert days >= 10


# ------------------------------------------------------------------ #
# TestAutonomyLevel                                                   #
# ------------------------------------------------------------------ #

class TestAutonomyLevel:
    def test_full_when_recent(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_human_confirmation("agent-1", ledger)
        level = monitor.autonomy_level("agent-1", ledger)
        assert level == AutonomyLevel.FULL

    def test_restricted_at_7_days(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        _insert_backdated_confirmation(ledger, "agent-1", 7)
        level = monitor.autonomy_level("agent-1", ledger)
        assert level == AutonomyLevel.RESTRICTED

    def test_restricted_at_15_days(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        _insert_backdated_confirmation(ledger, "agent-1", 15)
        level = monitor.autonomy_level("agent-1", ledger)
        assert level == AutonomyLevel.RESTRICTED

    def test_hibernation_at_30_days(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        _insert_backdated_confirmation(ledger, "agent-1", 30)
        level = monitor.autonomy_level("agent-1", ledger)
        assert level == AutonomyLevel.HIBERNATION

    def test_hibernation_at_9999_days(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        level = monitor.autonomy_level("agent-never", ledger)
        assert level == AutonomyLevel.HIBERNATION

    def test_full_at_6_days_boundary(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        _insert_backdated_confirmation(ledger, "agent-1", 6)
        level = monitor.autonomy_level("agent-1", ledger)
        assert level == AutonomyLevel.FULL


# ------------------------------------------------------------------ #
# TestGateIrreversible — SIM-1 + SIM-2 + SIM-5                       #
# ------------------------------------------------------------------ #

class TestGateIrreversible:
    def test_full_level_allows(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_human_confirmation("agent-1", ledger)
        result = monitor.gate_irreversible(
            "agent-1",
            _make_request_mock(),
            _make_workflow_mock(),
            _make_contestability_mock(),
            ledger,
        )
        assert result.verdict == AgentVerdict.ALLOW

    def test_hibernation_blocks_unconditionally(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        result = monitor.gate_irreversible(
            "agent-never",
            _make_request_mock(),
            _make_workflow_mock(),
            _make_contestability_mock(),
            ledger,
        )
        assert result.verdict == AgentVerdict.BLOCK
        assert "HIBERNATION" in result.explain

    def test_restricted_creates_approval_ticket(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        _insert_backdated_confirmation(ledger, "agent-1", 15)

        workflow = _make_workflow_mock()
        contestability = _make_contestability_mock()

        result = monitor.gate_irreversible(
            "agent-1",
            _make_request_mock(),
            workflow,
            contestability,
            ledger,
        )
        assert result.verdict == AgentVerdict.PENDING_APPROVAL
        workflow.request_approval.assert_called_once()

    def test_restricted_creates_appeal(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        _insert_backdated_confirmation(ledger, "agent-1", 15)

        contestability = _make_contestability_mock()

        result = monitor.gate_irreversible(
            "agent-1",
            _make_request_mock(),
            _make_workflow_mock(),
            contestability,
            ledger,
        )
        assert result.verdict == AgentVerdict.PENDING_APPROVAL
        contestability.submit_appeal.assert_called_once()

    def test_restricted_failure_blocks_fail_secure(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        _insert_backdated_confirmation(ledger, "agent-1", 15)

        workflow = _make_workflow_mock()
        workflow.request_approval.side_effect = RuntimeError("Workflow unavailable")

        result = monitor.gate_irreversible(
            "agent-1",
            _make_request_mock(),
            workflow,
            _make_contestability_mock(),
            ledger,
        )
        assert result.verdict == AgentVerdict.BLOCK
        assert "fail-secure" in result.explain.lower()

    def test_explain_always_present(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        # Test FULL
        monitor.record_human_confirmation("agent-1", ledger)
        r1 = monitor.gate_irreversible(
            "agent-1", _make_request_mock(), _make_workflow_mock(),
            _make_contestability_mock(), ledger,
        )
        assert r1.explain

        # Test HIBERNATION
        r2 = monitor.gate_irreversible(
            "agent-never", _make_request_mock(), _make_workflow_mock(),
            _make_contestability_mock(), ledger,
        )
        assert r2.explain

    def test_gate_field_is_liveness_monitor(self) -> None:
        monitor = _make_monitor()
        ledger = _make_ledger()
        monitor.record_human_confirmation("agent-1", ledger)
        result = monitor.gate_irreversible(
            "agent-1", _make_request_mock(), _make_workflow_mock(),
            _make_contestability_mock(), ledger,
        )
        assert result.gate == "liveness_monitor"
