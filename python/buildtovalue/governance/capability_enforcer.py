"""CapabilityEnforcer — Gap C: Capability-Based Access Control (Enforcer).

Enforces capability requirements by cross-referencing
AgentDecisionRequest.action.capabilities with the CapabilityRegistry.

Invariants:
- Fail-secure: missing capability -> BLOCK
- explain_decision in every GateResult
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import logging
from typing import Optional

from .agent_pdp import AgentDecisionRequest, AgentVerdict
from .capability_registry import CapabilityRegistry
from .chatbot_gates import GateResult
from .types import SimpleFinding

logger = logging.getLogger("btv.governance.capability_enforcer")


class CapabilityEnforcer:
    """Enforces capabilities on AgentDecisionRequests."""

    def __init__(
        self,
        registry: CapabilityRegistry,
        hmac_key: bytes = b"btv-capability-default-key",
    ) -> None:
        self._registry = registry
        self._hmac_key = hmac_key

    def _sign(self, payload: str) -> str:
        """Return hex HMAC-SHA256 digest of *payload* using the instance key."""
        return hmac_lib.new(
            self._hmac_key, payload.encode(), hashlib.sha256
        ).hexdigest()

    @staticmethod
    def make_finding(reason: str, confidence: float = 0.9) -> SimpleFinding:
        """Create a SimpleFinding for capability violations."""
        return SimpleFinding(
            rule_id="CAPABILITY_EXCEEDED",
            confidence=confidence,
            severity=0.9,
            module="capability_enforcer",
        )

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
            reason = f"Missing capabilities: {sorted(result.missing)}"
            sig = self._sign(reason)
            logger.info(
                "BLOCK finding generated: rule=CAPABILITY_EXCEEDED sig=%s", sig
            )
            return _block("capability_enforcer", reason)

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
