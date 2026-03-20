"""AgentBudget — Gap I: Agent Budget/Token Tracking.

Tracks per-agent token usage, cost, and API call counts.
Exceeding budget -> BLOCK with explanation.

Invariants:
- Fail-secure: budget error -> conservative limit (BLOCK)
- Monotonic counters (never decrease)
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .agent_pdp import AgentVerdict
from .chatbot_gates import GateResult

logger = logging.getLogger("btv.governance.agent_budget")

_DEFAULT_TOKENS = 1_000_000
_DEFAULT_COST = 10.0
_DEFAULT_CALLS = 500


@dataclass
class BudgetLimits:
    max_tokens: int = _DEFAULT_TOKENS
    max_cost_usd: float = _DEFAULT_COST
    max_api_calls: int = _DEFAULT_CALLS


@dataclass
class BudgetStatus:
    agent_id: str
    tokens_used: int
    tokens_remaining: int
    cost_used_usd: float
    cost_remaining_usd: float
    api_calls_used: int
    api_calls_remaining: int


@dataclass
class _Usage:
    tokens: int = 0
    cost_usd: float = 0.0
    api_calls: int = 0


class AgentBudget:
    """Tracks and enforces per-agent resource budgets."""

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        raw = self._load(policy_path) if policy_path else {}
        defaults = raw.get("defaults", {})
        self._default = BudgetLimits(
            max_tokens=defaults.get("max_tokens", _DEFAULT_TOKENS),
            max_cost_usd=defaults.get("max_cost_usd", _DEFAULT_COST),
            max_api_calls=defaults.get("max_api_calls", _DEFAULT_CALLS),
        )
        self._agents: Dict[str, BudgetLimits] = {}
        for aid, cfg in raw.get("agents", {}).items():
            self._agents[aid] = BudgetLimits(
                max_tokens=cfg.get("max_tokens", self._default.max_tokens),
                max_cost_usd=cfg.get("max_cost_usd", self._default.max_cost_usd),
                max_api_calls=cfg.get("max_api_calls", self._default.max_api_calls),
            )
        self._usage: Dict[str, _Usage] = {}

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def _limits(self, agent_id: str) -> BudgetLimits:
        return self._agents.get(agent_id, self._default)

    def _get_usage(self, agent_id: str) -> _Usage:
        if agent_id not in self._usage:
            self._usage[agent_id] = _Usage()
        return self._usage[agent_id]

    def check_budget(
        self, agent_id: str, estimated_tokens: int = 0
    ) -> GateResult:
        """Check if agent has remaining budget."""
        limits = self._limits(agent_id)
        usage = self._get_usage(agent_id)

        if usage.tokens + estimated_tokens > limits.max_tokens:
            return _block(
                "agent_budget",
                f"Token limit exceeded: {usage.tokens}/{limits.max_tokens}",
            )
        if usage.cost_usd >= limits.max_cost_usd:
            return _block(
                "agent_budget",
                f"Cost limit exceeded: ${usage.cost_usd:.2f}/${limits.max_cost_usd:.2f}",
            )
        if usage.api_calls >= limits.max_api_calls:
            return _block(
                "agent_budget",
                f"API call limit exceeded: {usage.api_calls}/{limits.max_api_calls}",
            )
        return _allow("agent_budget", "Within budget")

    def record_usage(
        self,
        agent_id: str,
        tokens_used: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        """Record resource consumption (monotonic)."""
        usage = self._get_usage(agent_id)
        usage.tokens += tokens_used
        usage.cost_usd += cost_usd
        usage.api_calls += 1

    def get_remaining(self, agent_id: str) -> BudgetStatus:
        """Get remaining budget for an agent."""
        limits = self._limits(agent_id)
        usage = self._get_usage(agent_id)
        return BudgetStatus(
            agent_id=agent_id,
            tokens_used=usage.tokens,
            tokens_remaining=max(0, limits.max_tokens - usage.tokens),
            cost_used_usd=usage.cost_usd,
            cost_remaining_usd=max(0.0, limits.max_cost_usd - usage.cost_usd),
            api_calls_used=usage.api_calls,
            api_calls_remaining=max(0, limits.max_api_calls - usage.api_calls),
        )

    def reset(self, agent_id: str) -> None:
        """Reset usage counters for an agent."""
        self._usage.pop(agent_id, None)


def _block(gate: str, reason: str) -> GateResult:
    logger.warning("BLOCK: gate=%s reason=%s", gate, reason)
    return GateResult(
        verdict=AgentVerdict.BLOCK,
        evidence_id=None,
        explain=f"[{gate}] {reason}",
        gate=gate,
    )


def _allow(gate: str, reason: str) -> GateResult:
    return GateResult(
        verdict=AgentVerdict.ALLOW,
        evidence_id=None,
        explain=f"[{gate}] {reason}",
        gate=gate,
    )
