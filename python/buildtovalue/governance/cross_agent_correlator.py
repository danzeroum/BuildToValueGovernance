"""CrossAgentCorrelator — Gap D: Multi-Agent Coordination.

Tracks concurrent agent actions and detects conflicts.
Implements circuit breaker pattern for cascading failure prevention.

Invariants:
- Fail-secure: circuit open -> BLOCK all requests
- Time-windowed counters for failure tracking
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

import yaml

from .agent_pdp import AgentVerdict
from .chatbot_gates import GateResult

logger = logging.getLogger("btv.governance.cross_agent_correlator")

_FAILURE_THRESHOLD = 5
_WINDOW_S = 60
_COOLDOWN_S = 30


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

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        raw = self._load(policy_path) if policy_path else {}
        cb = raw.get("circuit_breaker", {})
        self._fail_thresh = cb.get("failure_threshold", _FAILURE_THRESHOLD)
        self._window_s = cb.get("window_s", _WINDOW_S)
        self._cooldown_s = cb.get("cooldown_s", _COOLDOWN_S)
        self._half_open_max = cb.get("half_open_max", 2)
        self._conflicts = raw.get("conflict_rules", [])
        self._failures: Deque[float] = deque()
        self._active: Dict[str, str] = {}  # agent_id -> action
        self._circuit = CircuitState.CLOSED
        self._opened_at: float = 0.0
        self._half_open_count: int = 0

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def correlate(
        self, agent_id: str, action: str
    ) -> CorrelationResult:
        """Check for conflicts and circuit breaker state."""
        self._prune_failures()
        self._check_circuit_transition()

        if self._circuit == CircuitState.OPEN:
            return CorrelationResult(
                allowed=False,
                conflict=None,
                circuit_state=self._circuit,
                explain="Circuit breaker OPEN — all requests paused",
            )

        if self._circuit == CircuitState.HALF_OPEN:
            if self._half_open_count >= self._half_open_max:
                return CorrelationResult(
                    allowed=False,
                    conflict=None,
                    circuit_state=self._circuit,
                    explain="Circuit HALF_OPEN limit reached",
                )
            self._half_open_count += 1

        conflict = self._detect_conflict(agent_id, action)
        if conflict:
            return CorrelationResult(
                allowed=False,
                conflict=conflict,
                circuit_state=self._circuit,
                explain=f"Conflict: {conflict}",
            )

        self._active[agent_id] = action
        return CorrelationResult(
            allowed=True,
            conflict=None,
            circuit_state=self._circuit,
            explain="No conflicts detected",
        )

    def record_failure(self, agent_id: str) -> None:
        """Record an agent failure for circuit breaker."""
        self._failures.append(time.time())
        self._active.pop(agent_id, None)
        self._prune_failures()
        if len(self._failures) >= self._fail_thresh:
            self._circuit = CircuitState.OPEN
            self._opened_at = time.time()
            self._half_open_count = 0

    def record_success(self, agent_id: str) -> None:
        """Record agent success; may close half-open circuit."""
        self._active.pop(agent_id, None)
        if self._circuit == CircuitState.HALF_OPEN:
            self._circuit = CircuitState.CLOSED
            self._half_open_count = 0

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
                    return rule.get("reason", "Conflicting actions")
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
