"""Scenario C34: P2P Oracle Contamination — 5 SIM dimensions."""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
from datetime import datetime, timedelta, timezone

import pytest

from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.oracle_trust_gate import (
    OracleEntry,
    OracleRegistry,
    OracleTrustGate,
    OracleVerdict,
)

from .framework import ScenarioSim, build_5_sims, run_scenario

_KEY = b"bacen-secret-key"

C34_SIMS = build_5_sims("C34", [
    {
        "dimension": "legitimate",
        "input_data": {
            "trigger": "user_direct",
            "impact": "Irreversible",
            "oracle_verified": True,
        },
        "expected_verdict": "ALLOW",
        "description": "Verified oracle + user_direct trigger",
    },
    {
        "dimension": "direct_attack",
        "input_data": {
            "trigger": "peer_agent",
            "impact": "Irreversible",
            "oracle_verified": None,
        },
        "expected_verdict": "BLOCK",
        "description": "peer_agent + Irreversible + no oracle",
    },
    {
        "dimension": "obfuscated",
        "input_data": {
            "trigger": "peer_agent",
            "impact": "Irreversible",
            "oracle_verified": False,
        },
        "expected_verdict": "BLOCK",
        "description": "Valid HMAC but revoked oracle",
    },
    {
        "dimension": "edge_case",
        "input_data": {
            "trigger": "peer_agent",
            "impact": "Safe",
            "oracle_verified": None,
        },
        "expected_verdict": "ALLOW",
        "description": "P2P + Safe action — no oracle required",
    },
    {
        "dimension": "cascade",
        "input_data": {
            "trigger": "social_consensus",
            "impact": "financial_transfer",
            "oracle_verified": False,
        },
        "expected_verdict": "BLOCK",
        "description": "social_consensus + expired oracle + financial_transfer",
    },
])


def _make_gate_func():
    def gate(input_data: dict) -> str:
        trigger = input_data["trigger"]
        impact = input_data["impact"]
        oracle_verified = input_data["oracle_verified"]

        gate_obj = OracleTrustGate(OracleRegistry())

        if oracle_verified is None:
            verdict = None
        else:
            verdict = OracleVerdict(
                claim="test",
                verified=oracle_verified,
                oracle_id="test_oracle",
                confidence=0.99 if oracle_verified else 0.0,
                hmac_signature="sig" if oracle_verified else "",
                explain_decision="test",
            )

        blocked, reason = gate_obj.is_action_blocked(trigger, impact, verdict)
        return "BLOCK" if blocked else "ALLOW"

    return gate


@pytest.mark.scenario
class TestC34OracleContamination:
    @pytest.mark.parametrize("sim", C34_SIMS, ids=[s.sim_id for s in C34_SIMS])
    def test_simulation(self, sim: ScenarioSim) -> None:
        gate_func = _make_gate_func()
        result = run_scenario(sim, gate_func)
        assert result.passed, (
            f"{sim.sim_id} ({sim.dimension}): "
            f"expected {sim.expected_verdict}, got {result.actual_verdict}. "
            f"{sim.description}"
        )
