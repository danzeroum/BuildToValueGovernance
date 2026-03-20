"""Tests for ApprovalWorkflow — Gap F."""
from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

from buildtovalue.governance.agent_pdp import (
    ActionImpact,
    AgentAction,
    AgentContext,
    AgentDecisionRequest,
)
from buildtovalue.governance.approval_workflow import (
    ApprovalStatus,
    ApprovalWorkflow,
)


def _make_request(
    action_name: str = "test",
    impact: ActionImpact = ActionImpact.SAFE,
    trust: float = 0.5,
) -> AgentDecisionRequest:
    return AgentDecisionRequest(
        agent_id="test-agent",
        session_id="s1",
        action=AgentAction(name=action_name, impact=impact),
        parameters_hash="a" * 64,
        context=AgentContext(session_trust_score=trust),
    )


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    policy = {
        "default_timeout_s": 2,
        "approval_triggers": {
            "impact_requires_approval": ["Irreversible"],
            "trust_score_threshold": 0.3,
            "actions_require_approval": ["lora_deploy"],
        },
        "expired_action": "BLOCK",
    }
    p = tmp_path / "approval_rules.yaml"
    p.write_text(yaml.dump(policy))
    return p


@pytest.fixture
def workflow(policy_path: Path) -> ApprovalWorkflow:
    return ApprovalWorkflow(policy_path=policy_path)


class TestNeedsApproval:
    def test_irreversible_needs_approval(self, workflow: ApprovalWorkflow) -> None:
        req = _make_request(impact=ActionImpact.IRREVERSIBLE)
        assert workflow.needs_approval(req) is True

    def test_safe_no_approval(self, workflow: ApprovalWorkflow) -> None:
        req = _make_request(impact=ActionImpact.SAFE)
        assert workflow.needs_approval(req) is False

    def test_low_trust_needs_approval(self, workflow: ApprovalWorkflow) -> None:
        req = _make_request(trust=0.1)
        assert workflow.needs_approval(req) is True

    def test_action_name_trigger(self, workflow: ApprovalWorkflow) -> None:
        req = _make_request(action_name="lora_deploy")
        assert workflow.needs_approval(req) is True


class TestTicketLifecycle:
    def test_create_and_approve(self, workflow: ApprovalWorkflow) -> None:
        req = _make_request()
        ticket = workflow.request_approval(req, "test reason")
        assert ticket.status == ApprovalStatus.PENDING
        assert len(ticket.hmac_sha256) == 64

        resolved = workflow.resolve(ticket.ticket_id, True, "admin-1")
        assert resolved.status == ApprovalStatus.APPROVED
        assert resolved.approver_id == "admin-1"

    def test_create_and_deny(self, workflow: ApprovalWorkflow) -> None:
        req = _make_request()
        ticket = workflow.request_approval(req, "risky")
        resolved = workflow.resolve(ticket.ticket_id, False, "admin-2")
        assert resolved.status == ApprovalStatus.DENIED

    def test_ticket_expires(self, workflow: ApprovalWorkflow) -> None:
        req = _make_request()
        ticket = workflow.request_approval(req, "test", timeout_s=0)
        time.sleep(0.01)
        status = workflow.check_status(ticket.ticket_id)
        assert status == ApprovalStatus.EXPIRED

    def test_unknown_ticket_expired(self, workflow: ApprovalWorkflow) -> None:
        status = workflow.check_status("nonexistent-id")
        assert status == ApprovalStatus.EXPIRED


class TestFailSecure:
    def test_resolve_unknown_raises(self, workflow: ApprovalWorkflow) -> None:
        with pytest.raises(ValueError, match="Unknown ticket"):
            workflow.resolve("bad-id", True, "admin")

    def test_resolve_expired_stays_expired(self, workflow: ApprovalWorkflow) -> None:
        req = _make_request()
        ticket = workflow.request_approval(req, "test", timeout_s=0)
        time.sleep(0.01)
        resolved = workflow.resolve(ticket.ticket_id, True, "admin")
        assert resolved.status == ApprovalStatus.EXPIRED


class TestNoPolicy:
    def test_default_workflow(self) -> None:
        wf = ApprovalWorkflow()
        req = _make_request()
        assert wf.needs_approval(req) is False
