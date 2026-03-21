"""Scenario C08: Dead Man's Switch — 5 SIM dimensions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from buildtovalue.governance.agent_pdp import AgentVerdict
from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.liveness_monitor import LivenessMonitor

from .framework import ScenarioSim, build_5_sims, run_scenario

C08_SIMS = build_5_sims("C08", [
    {
        "dimension": "legitimate",
        "input_data": {"days_ago": 0, "workflow_ok": True},
        "expected_verdict": "ALLOW",
        "description": "Fresh confirmation + Irreversible => ALLOW",
    },
    {
        "dimension": "direct_attack",
        "input_data": {"days_ago": 9999, "workflow_ok": True},
        "expected_verdict": "BLOCK",
        "description": "Never confirmed (9999d) => BLOCK",
    },
    {
        "dimension": "obfuscated",
        "input_data": {"days_ago": 15, "workflow_ok": True},
        "expected_verdict": "PENDING_APPROVAL",
        "description": "15 days inactive => RESTRICTED => PENDING_APPROVAL",
    },
    {
        "dimension": "edge_case",
        "input_data": {"days_ago": 6, "workflow_ok": True},
        "expected_verdict": "ALLOW",
        "description": "6 days (boundary) => FULL => ALLOW",
    },
    {
        "dimension": "cascade",
        "input_data": {"days_ago": 15, "workflow_ok": False},
        "expected_verdict": "BLOCK",
        "description": "RESTRICTED + workflow failure => BLOCK fail-secure",
    },
])


def _insert_backdated(ledger: DurableLedger, agent_id: str, days_ago: int) -> None:
    if days_ago >= 9999:
        return  # Don't insert — simulate never confirmed
    past = datetime.now(timezone.utc) - timedelta(days=days_ago)
    iso = past.isoformat().replace("+00:00", "Z")
    ledger.append({
        "type": "liveness_confirmation",
        "agent_id": agent_id,
        "confirmed_at_iso": iso,
        "hmac_signature": "a" * 64,
        "explain_decision": f"Test confirmation ({days_ago}d ago)",
    })


def _make_gate_func():
    def gate(input_data: dict) -> str:
        days_ago = input_data["days_ago"]
        workflow_ok = input_data["workflow_ok"]

        monitor = LivenessMonitor(hmac_key=b"test-key")
        ledger = DurableLedger(hmac_key=b"test-key")

        _insert_backdated(ledger, "agent-sim", days_ago)

        request = MagicMock()
        request.action.metadata = {}

        workflow = MagicMock()
        if workflow_ok:
            ticket = MagicMock()
            ticket.ticket_id = "ticket-sim"
            workflow.request_approval.return_value = ticket
        else:
            workflow.request_approval.side_effect = RuntimeError("Workflow down")

        contestability = MagicMock()
        appeal = MagicMock()
        appeal.appeal_id = "appeal-sim"
        contestability.submit_appeal.return_value = appeal

        result = monitor.gate_irreversible(
            "agent-sim", request, workflow, contestability, ledger,
        )
        return result.verdict.value

    return gate


@pytest.mark.scenario
class TestC08DeadMansSwitch:
    @pytest.mark.parametrize("sim", C08_SIMS, ids=[s.sim_id for s in C08_SIMS])
    def test_simulation(self, sim: ScenarioSim) -> None:
        gate_func = _make_gate_func()
        result = run_scenario(sim, gate_func)
        assert result.passed, (
            f"{sim.sim_id} ({sim.dimension}): "
            f"expected {sim.expected_verdict}, got {result.actual_verdict}. "
            f"{sim.description}"
        )
