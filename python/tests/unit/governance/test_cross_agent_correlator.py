"""Tests for CrossAgentCorrelator — Gap D."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from buildtovalue.governance.cross_agent_correlator import (
    CircuitState,
    CrossAgentCorrelator,
)


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    policy = {
        "circuit_breaker": {
            "failure_threshold": 3,
            "window_s": 60,
            "cooldown_s": 0,  # instant for tests
            "half_open_max": 1,
        },
        "conflict_rules": [
            {
                "action_a": "deploy",
                "action_b": "deploy",
                "conflict": True,
                "reason": "Concurrent deploys forbidden",
            },
        ],
    }
    p = tmp_path / "coordination_rules.yaml"
    p.write_text(yaml.dump(policy))
    return p


@pytest.fixture
def correlator(policy_path: Path) -> CrossAgentCorrelator:
    return CrossAgentCorrelator(policy_path=policy_path)


class TestConflictDetection:
    def test_no_conflict(self, correlator: CrossAgentCorrelator) -> None:
        r = correlator.correlate("agent-a", "read")
        assert r.allowed is True
        assert r.conflict is None

    def test_concurrent_deploy_conflict(self, correlator: CrossAgentCorrelator) -> None:
        correlator.correlate("agent-a", "deploy")
        r = correlator.correlate("agent-b", "deploy")
        assert r.allowed is False
        assert "Concurrent deploys" in r.conflict

    def test_different_actions_ok(self, correlator: CrossAgentCorrelator) -> None:
        correlator.correlate("agent-a", "deploy")
        r = correlator.correlate("agent-b", "read")
        assert r.allowed is True


class TestCircuitBreaker:
    def test_circuit_opens_on_failures(self, correlator: CrossAgentCorrelator) -> None:
        for i in range(3):
            correlator.record_failure(f"agent-{i}")
        # With cooldown_s=0, circuit transitions immediately to HALF_OPEN
        # after the first correlate call. Exhaust half-open allowance.
        r1 = correlator.correlate("agent-x", "read")
        assert r1.circuit_state == CircuitState.HALF_OPEN
        r2 = correlator.correlate("agent-y", "read")
        assert r2.allowed is False

    def test_circuit_transitions_to_half_open(
        self, correlator: CrossAgentCorrelator
    ) -> None:
        for i in range(3):
            correlator.record_failure(f"agent-{i}")
        # cooldown_s=0, so transition is immediate
        r = correlator.correlate("agent-x", "read")
        # After prune + check, should be half-open now
        assert r.circuit_state in (CircuitState.OPEN, CircuitState.HALF_OPEN)

    def test_success_closes_half_open(self, correlator: CrossAgentCorrelator) -> None:
        correlator._circuit = CircuitState.HALF_OPEN
        correlator.record_success("agent-x")
        assert correlator._circuit == CircuitState.CLOSED


class TestNoPolicy:
    def test_default_correlator(self) -> None:
        c = CrossAgentCorrelator()
        r = c.correlate("agent-a", "read")
        assert r.allowed is True
