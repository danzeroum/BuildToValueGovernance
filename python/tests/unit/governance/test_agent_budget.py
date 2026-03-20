"""Tests for AgentBudget — Gap I."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from buildtovalue.governance.agent_budget import AgentBudget, BudgetStatus
from buildtovalue.governance.agent_pdp import AgentVerdict


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    policy = {
        "defaults": {
            "max_tokens": 1000,
            "max_cost_usd": 1.0,
            "max_api_calls": 5,
        },
        "agents": {
            "limited-agent": {
                "max_tokens": 100,
                "max_cost_usd": 0.50,
                "max_api_calls": 2,
            },
        },
    }
    p = tmp_path / "budget_limits.yaml"
    p.write_text(yaml.dump(policy))
    return p


@pytest.fixture
def budget(policy_path: Path) -> AgentBudget:
    return AgentBudget(policy_path=policy_path)


class TestCheckBudget:
    def test_within_budget(self, budget: AgentBudget) -> None:
        r = budget.check_budget("some-agent", estimated_tokens=100)
        assert r.verdict == AgentVerdict.ALLOW

    def test_token_limit_exceeded(self, budget: AgentBudget) -> None:
        r = budget.check_budget("some-agent", estimated_tokens=2000)
        assert r.verdict == AgentVerdict.BLOCK
        assert "Token limit" in r.explain

    def test_cost_limit(self, budget: AgentBudget) -> None:
        budget.record_usage("some-agent", tokens_used=10, cost_usd=1.01)
        r = budget.check_budget("some-agent")
        assert r.verdict == AgentVerdict.BLOCK
        assert "Cost limit" in r.explain

    def test_api_calls_limit(self, budget: AgentBudget) -> None:
        for _ in range(5):
            budget.record_usage("some-agent", tokens_used=1)
        r = budget.check_budget("some-agent")
        assert r.verdict == AgentVerdict.BLOCK
        assert "API call limit" in r.explain


class TestRecordUsage:
    def test_usage_accumulates(self, budget: AgentBudget) -> None:
        budget.record_usage("a", tokens_used=50, cost_usd=0.10)
        budget.record_usage("a", tokens_used=30, cost_usd=0.05)
        status = budget.get_remaining("a")
        assert status.tokens_used == 80
        assert status.api_calls_used == 2

    def test_agent_specific_limits(self, budget: AgentBudget) -> None:
        budget.record_usage("limited-agent", tokens_used=50)
        budget.record_usage("limited-agent", tokens_used=60)
        r = budget.check_budget("limited-agent")
        assert r.verdict == AgentVerdict.BLOCK


class TestGetRemaining:
    def test_full_budget(self, budget: AgentBudget) -> None:
        status = budget.get_remaining("some-agent")
        assert status.tokens_remaining == 1000
        assert status.cost_remaining_usd == 1.0
        assert status.api_calls_remaining == 5

    def test_partial_budget(self, budget: AgentBudget) -> None:
        budget.record_usage("some-agent", tokens_used=300, cost_usd=0.40)
        status = budget.get_remaining("some-agent")
        assert status.tokens_remaining == 700


class TestReset:
    def test_reset_clears_usage(self, budget: AgentBudget) -> None:
        budget.record_usage("a", tokens_used=500)
        budget.reset("a")
        status = budget.get_remaining("a")
        assert status.tokens_used == 0


class TestEducateAt80Pct:
    def test_educate_near_token_limit(self, budget: AgentBudget) -> None:
        budget.record_usage("some-agent", tokens_used=850)
        r = budget.check_budget("some-agent")
        assert r.verdict == AgentVerdict.EDUCATE

    def test_educate_near_cost_limit(self, budget: AgentBudget) -> None:
        budget.record_usage("some-agent", tokens_used=1, cost_usd=0.81)
        r = budget.check_budget("some-agent")
        assert r.verdict == AgentVerdict.EDUCATE

    def test_educate_near_api_limit(self, budget: AgentBudget) -> None:
        for _ in range(4):
            budget.record_usage("some-agent", tokens_used=1)
        r = budget.check_budget("some-agent")
        assert r.verdict == AgentVerdict.EDUCATE


class TestToolCallCircuitBreaker:
    def test_tool_calls_within_limit(self, budget: AgentBudget) -> None:
        r = budget.check_tool_calls("some-agent", "req-1")
        assert r.verdict == AgentVerdict.ALLOW

    def test_tool_calls_exceed_limit(self, budget: AgentBudget) -> None:
        for _ in range(20):
            budget.check_tool_calls("some-agent", "req-1")
        r = budget.check_tool_calls("some-agent", "req-1")
        assert r.verdict == AgentVerdict.BLOCK


class TestNoPolicy:
    def test_default_budget(self) -> None:
        b = AgentBudget()
        r = b.check_budget("any-agent")
        assert r.verdict == AgentVerdict.ALLOW
