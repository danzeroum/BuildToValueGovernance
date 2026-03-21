"""Shared test fixtures for BuildToValueGovernance test suite."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest

from buildtovalue.governance.agent_pdp import (
    ActionImpact,
    AgentAction,
    AgentContext,
    AgentDecisionRequest,
    AgentVerdict,
)
from buildtovalue.governance.approval_workflow import ApprovalWorkflow
from buildtovalue.governance.contestability_loop import ContestabilityLoop
from buildtovalue.governance.durable_ledger import DurableLedger


@pytest.fixture
def make_durable_ledger():
    """Factory fixture returning a fresh DurableLedger."""
    def _factory(hmac_key: bytes = b"test-key") -> DurableLedger:
        return DurableLedger(hmac_key=hmac_key)
    return _factory


@pytest.fixture
def make_agent_request():
    """Factory fixture returning an AgentDecisionRequest."""
    def _factory(
        agent_id: str = "test-agent",
        action_name: str = "test_action",
        impact: ActionImpact = ActionImpact.SAFE,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentDecisionRequest:
        action = AgentAction(name=action_name, impact=impact)
        if metadata:
            action.metadata = metadata  # type: ignore[attr-defined]
        return AgentDecisionRequest(
            agent_id=agent_id,
            session_id="test-session",
            action=action,
            parameters_hash="a" * 64,
        )
    return _factory


@pytest.fixture
def make_approval_workflow():
    """Factory returning a MagicMock spec'd to ApprovalWorkflow."""
    def _factory() -> MagicMock:
        mock = MagicMock(spec=ApprovalWorkflow)
        ticket = MagicMock()
        ticket.ticket_id = "ticket-001"
        mock.request_approval.return_value = ticket
        return mock
    return _factory


@pytest.fixture
def make_contestability_loop():
    """Factory returning a MagicMock spec'd to ContestabilityLoop."""
    def _factory() -> MagicMock:
        mock = MagicMock(spec=ContestabilityLoop)
        appeal = MagicMock()
        appeal.appeal_id = "appeal-001"
        mock.submit_appeal.return_value = appeal
        return mock
    return _factory
