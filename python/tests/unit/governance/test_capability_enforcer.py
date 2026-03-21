"""Tests for CapabilityEnforcer — Gap C."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from buildtovalue.governance.agent_pdp import (
    ActionImpact,
    AgentAction,
    AgentContext,
    AgentDecisionRequest,
    AgentVerdict,
)
from buildtovalue.governance.capability_enforcer import CapabilityEnforcer
from buildtovalue.governance.capability_registry import CapabilityRegistry


@pytest.fixture
def registry(tmp_path: Path) -> CapabilityRegistry:
    policy = {
        "default_capabilities": ["llm_inference"],
        "agents": {
            "med-agent": {
                "capabilities": ["llm_inference", "patient_lookup"],
                "revoked": [],
            },
        },
    }
    p = tmp_path / "caps.yaml"
    p.write_text(yaml.dump(policy))
    return CapabilityRegistry(policy_path=p)


@pytest.fixture
def enforcer(registry: CapabilityRegistry) -> CapabilityEnforcer:
    return CapabilityEnforcer(registry=registry)


def _make_request(
    agent_id: str, capabilities: list[str]
) -> AgentDecisionRequest:
    return AgentDecisionRequest(
        agent_id=agent_id,
        session_id="s1",
        action=AgentAction(
            name="test_action",
            impact=ActionImpact.SAFE,
            capabilities=capabilities,
        ),
        parameters_hash="a" * 64,
    )


class TestEnforce:
    def test_no_capabilities_required(self, enforcer: CapabilityEnforcer) -> None:
        req = _make_request("med-agent", [])
        r = enforcer.enforce(req)
        assert r.verdict == AgentVerdict.ALLOW

    def test_has_capability(self, enforcer: CapabilityEnforcer) -> None:
        req = _make_request("med-agent", ["patient_lookup"])
        r = enforcer.enforce(req)
        assert r.verdict == AgentVerdict.ALLOW

    def test_missing_capability_blocked(self, enforcer: CapabilityEnforcer) -> None:
        req = _make_request("med-agent", ["model_deploy"])
        r = enforcer.enforce(req)
        assert r.verdict == AgentVerdict.BLOCK
        assert "model_deploy" in r.explain

    def test_unknown_agent_defaults(self, enforcer: CapabilityEnforcer) -> None:
        req = _make_request("unknown-agent", ["llm_inference"])
        r = enforcer.enforce(req)
        assert r.verdict == AgentVerdict.ALLOW

    def test_unknown_agent_missing(self, enforcer: CapabilityEnforcer) -> None:
        req = _make_request("unknown-agent", ["patient_lookup"])
        r = enforcer.enforce(req)
        assert r.verdict == AgentVerdict.BLOCK


class TestMakeFinding:
    def test_finding_generated(self) -> None:
        f = CapabilityEnforcer.make_finding("test")
        assert f.rule_id == "CAPABILITY_EXCEEDED"
        assert f.severity == 0.9
        assert f.module == "capability_enforcer"

    def test_custom_confidence(self) -> None:
        f = CapabilityEnforcer.make_finding("test", confidence=0.7)
        assert f.confidence == 0.7
