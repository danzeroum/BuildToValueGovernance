"""CapabilityEnforcer — Gap C: Capability-Based Access Control (Enforcer).

Enforces capability requirements by cross-referencing
AgentDecisionRequest.action.capabilities with the CapabilityRegistry.

Invariants:
- Fail-secure: missing capability -> BLOCK
- explain_decision in every GateResult
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import logging
from typing import Optional

from .agent_pdp import AgentDecisionRequest, AgentVerdict
from .capability_registry import CapabilityRegistry
from .chatbot_gates import GateResult

logger = logging.getLogger("btv.governance.capability_enforcer")


class CapabilityEnforcer:
    """Enforces capabilities on AgentDecisionRequests."""

    def __init__(self, registry: CapabilityRegistry) -> None:
        self._registry = registry

    def enforce(self, request: AgentDecisionRequest) -> GateResult:
        """Check if agent has required capabilities for the action."""
        required = request.action.capabilities
        if not required:
            return _allow(
                "capability_enforcer",
                "No capabilities required for this action",
            )

        result = self._registry.check_capabilities(
            request.agent_id, required
        )

        if not result.allowed:
            return _block(
                "capability_enforcer",
                f"Missing capabilities: {sorted(result.missing)}",
            )

        return _allow(
            "capability_enforcer",
            f"Agent '{request.agent_id}' authorized",
        )


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
