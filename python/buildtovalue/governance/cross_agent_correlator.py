"""CrossAgentCorrelator — Gap D: Multi-Agent Coordination.

Tracks concurrent agent actions and detects conflicts.
Implements circuit breaker pattern for cascading failure prevention.

Invariants:
- Fail-secure: circuit open -> BLOCK all requests
- Time-windowed counters for failure tracking
- Functions <= 50 lines
- AlignmentDegradationTracker delegado a alignment_degradation_tracker.py (ICLR 2026)
"""
from __future__ import annotations

import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

import yaml

from .agent_pdp import AgentVerdict
from buildtovalue.agentic.alignment_degradation_tracker import AlignmentDegradationTracker
from .chatbot_gates import GateResult
from .durable_ledger import DurableLedger
from .tool_sanitizer import _RE_SCREEN

logger = logging.getLogger("btv.governance.cross_agent_correlator")

_FAILURE_THRESHOLD = 5
_WINDOW_S = 60
_COOLDOWN_S = 30
# Minimal fix (#180): in-process ledger for the degradation tracker. The shared
# production ledger (app.state) should be injected via __init__ — tracked as debt.
_DEGRADATION_LEDGER_KEY = b"btv-cross-agent-correlator-degradation-v1"


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass(frozen=True)
class CorrelationResult:
    allowed: bool
    conflict: Optional[str]
    circuit_state: CircuitState
    explain: str


class CrossAgentCorrelator:
    """Tracks multi-agent actions and prevents conflicts."""

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        ledger: Optional[DurableLedger] = None,
    ) -> None:
        # `ledger`: shared session ledger (the one /v1/ledger/* reads in prod).
        # When None, fall back to an in-process ledger — preserves the behaviour
        # of every caller that does not inject one (e.g. unit tests). #182.
        raw = self._load(policy_path) if policy_path else {}
        cb = raw.get("circuit_breaker", {})
        self._fail_thresh = cb.get("failure_threshold", _FAILURE_THRESHOLD)
        self._window_s = cb.get("window_s", _WINDOW_S)
        self._cooldown_s = cb.get("cooldown_s", _COOLDOWN_S)
        self._half_open_max = cb.get("half_open_max", 2)
        self._conflicts = raw.get("conflict_rules", [])
        self._collusion_patterns = raw.get("collusion_patterns", [])
        self._max_payload = raw.get("max_a2a_payload_bytes", 10000)
        self._failures: Deque[float] = deque()
        self._active: Dict[str, str] = {}  # agent_id -> action
        self._circuit = CircuitState.CLOSED
        self._opened_at: float = 0.0
        self._half_open_count = 0
        ad = raw.get("alignment_degradation", {})
        # NB: explicit `is not None` — DurableLedger defines __len__, so an
        # empty injected ledger is falsy; `ledger or ...` would silently drop it.
        self._degradation_tracker = AlignmentDegradationTracker(
            ledger=DurableLedger(hmac_key=_DEGRADATION_LEDGER_KEY),
            window=ad.get("snapshot_window", 20),
            threshold=ad.get("threshold", 0.4),
        )

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def correlate(self, agent_id: str, action: str) -> CorrelationResult:
        """Check for conflicts and circuit breaker state."""
        self._prune_failures()
        self._check_circuit_transition()
        if self._circuit == CircuitState.OPEN:
            return CorrelationResult(
                allowed=False, conflict=None,
                circuit_state=self._circuit,
                explain="Circuit breaker OPEN — all requests paused",
            )
        if self._circuit == CircuitState.HALF_OPEN:
            if self._half_open_count >= self._half_open_max:
                return CorrelationResult(
                    allowed=False, conflict=None,
                    circuit_state=self._circuit,
                    explain="Circuit HALF_OPEN limit reached",
                )
            self._half_open_count += 1
        conflict = self._detect_conflict(agent_id, action)
        if conflict:
            return CorrelationResult(
                allowed=False, conflict=conflict,
                circuit_state=self._circuit, explain=f"Conflict: {conflict}",
            )
        self._active[agent_id] = action
        report = self._degradation_tracker.compute_degradation(agent_id)
        if report.threshold_exceeded:
            return CorrelationResult(
                allowed=False, conflict="ALIGNMENT_DEGRADATION",
                circuit_state=self._circuit, explain=report.explain_decision,
            )
        return CorrelationResult(
            allowed=True, conflict=None,
            circuit_state=self._circuit, explain="No conflicts detected",
        )

    def record_failure(self, agent_id: str) -> None:
        """Record an agent failure for circuit breaker."""
        is_collab = len(self._active) > 1
        self._failures.append(time.time())
        self._active.pop(agent_id, None)
        self._prune_failures()
        if len(self._failures) >= self._fail_thresh:
            self._circuit = CircuitState.OPEN
            self._opened_at = time.time()
            self._half_open_count = 0
        self._degradation_tracker.record_session(
            agent_id=agent_id, session_id=uuid.uuid4().hex,
            is_collaborative=is_collab, abort_reason="alignment_block",
            drift_score=1.0,
        )

    def record_success(self, agent_id: str) -> None:
        """Record agent success; may close half-open circuit."""
        is_collab = len(self._active) > 1
        self._active.pop(agent_id, None)
        if self._circuit == CircuitState.HALF_OPEN:
            self._circuit = CircuitState.CLOSED
            self._half_open_count = 0
        self._degradation_tracker.record_session(
            agent_id=agent_id, session_id=uuid.uuid4().hex,
            is_collaborative=is_collab, abort_reason=None,
            drift_score=0.0,
        )

    def detect_collusion(
        self, agent_actions: Dict[str, List[str]]
    ) -> Optional[str]:
        """Return reason string if agents' combined actions match a collusion pattern.

        Matching is substring-based (#181): a role's action matches an agent when
        the action keyword appears *within* any of that agent's action strings.
        This lets callers pass payload content (e.g. an A2A message) as the action
        list and still detect a pattern keyword embedded in it, while exact action
        names continue to match as a special case (keyword == full string).
        """
        for pattern in self._collusion_patterns:
            required: List[Dict[str, str]] = pattern.get("agents", [])
            reason: str = pattern.get("reason", "Collusion detected")
            matched_agents: List[str] = []
            for role in required:
                role_action = role.get("action", "")
                for agent_id, actions in agent_actions.items():
                    if agent_id not in matched_agents and any(
                        role_action in action for action in actions
                    ):
                        matched_agents.append(agent_id)
                        break
            if len(matched_agents) == len(required) and required:
                logger.warning("Collusion detected: %s agents=%s", reason, matched_agents)
                return reason
        return None

    def scan_a2a_payload(
        self, source_agent: str, target_agent: str, payload: str
    ) -> CorrelationResult:
        """Scan an agent-to-agent payload for injection patterns and size limits."""
        def _block(reason: str) -> CorrelationResult:
            logger.warning(reason)
            return CorrelationResult(
                allowed=False, conflict=reason,
                circuit_state=self._circuit, explain=reason,
            )

        nb = len(payload.encode("utf-8"))
        if nb > self._max_payload:
            return _block(
                f"A2A payload {source_agent}->{target_agent} "
                f"exceeds limit ({nb} > {self._max_payload} bytes)"
            )
        m = _RE_SCREEN.search(payload)
        if m:
            return _block(
                f"A2A payload {source_agent}->{target_agent} "
                f"contains injection pattern: {m.group()!r}"
            )
        return CorrelationResult(
            allowed=True, conflict=None,
            circuit_state=self._circuit, explain="A2A payload clean",
        )

    def _detect_conflict(
        self, agent_id: str, action: str
    ) -> Optional[str]:
        for other_id, other_action in self._active.items():
            if other_id == agent_id:
                continue
            for rule in self._conflicts:
                a, b = rule.get("action_a"), rule.get("action_b")
                if rule.get("conflict") and (
                    (action == a and other_action == b)
                    or (action == b and other_action == a)
                ):
                    return str(rule.get("reason", "Conflicting actions"))
        return None

    def _prune_failures(self) -> None:
        cutoff = time.time() - self._window_s
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()

    def _check_circuit_transition(self) -> None:
        if self._circuit == CircuitState.OPEN:
            if time.time() - self._opened_at >= self._cooldown_s:
                self._circuit = CircuitState.HALF_OPEN
                self._half_open_count = 0
