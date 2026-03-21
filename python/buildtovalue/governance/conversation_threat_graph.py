"""ConversationThreatGraph — Gap E: Multi-Turn Threat Modeling.

Maintains per-session threat graphs tracking action transitions.
Detects escalation patterns and multi-step attack sequences.

Uses SessionManager for LRU+TTL lifecycle.
Uses ring-buffer pattern (like GoalDriftSentinel) for recent turns.

Invariants:
- Fail-secure: error -> high threat assessment
- HMAC-SHA256 signed assessments
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import logging
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

import yaml

from .session_manager import SessionManager
from .types import ActionType

logger = logging.getLogger("btv.governance.conversation_threat_graph")

_WINDOW_SIZE = 10
_BURST_THRESHOLD = 3
_ESCALATION_PCT = 50


class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ThreatAssessment:
    session_id: str
    threat_level: ThreatLevel
    escalation_pct: float
    burst_detected: bool
    pattern_match: Optional[str]
    explain: str
    instruction_density: float = 0.0
    hmac_sha256: str = ""


@dataclass
class _TurnRecord:
    action: str
    risk_score: float


class ConversationThreatGraph:
    """Tracks per-session threat patterns across turns."""

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        hmac_key: bytes = b"btv-threat-default-key",
        max_sessions: int = 10_000,
        ttl_s: int = 1800,
    ) -> None:
        raw = self._load(policy_path) if policy_path else {}
        self._window = raw.get("window_size", _WINDOW_SIZE)
        self._burst_thresh = raw.get("burst_threshold", _BURST_THRESHOLD)
        self._esc_pct = raw.get("escalation_threshold_pct", _ESCALATION_PCT)
        self._risk = raw.get("risk_levels", {"low": 0.3, "medium": 0.6, "high": 0.8})
        self._sequences = raw.get("attack_sequences", [])
        self._key = hmac_key
        self._mgr = SessionManager(max_sessions=max_sessions, ttl_s=ttl_s)
        self._turns: Dict[str, Deque[_TurnRecord]] = {}

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def record_turn(
        self, session_id: str, action: str, risk_score: float
    ) -> ThreatAssessment:
        """Record a turn and return threat assessment."""
        evicted = self._mgr.touch(session_id)
        for sid in evicted:
            self._turns.pop(sid, None)

        if session_id not in self._turns:
            self._turns[session_id] = deque(maxlen=self._window)
        self._turns[session_id].append(
            _TurnRecord(action=action, risk_score=risk_score)
        )
        return self._assess(session_id)

    def _assess(self, session_id: str) -> ThreatAssessment:
        buf = self._turns.get(session_id, deque())
        esc_pct = self._escalation_pct(buf)
        burst = self._is_burst(buf)
        pattern = self._match_sequence(buf)
        density = self._instruction_density(buf)

        level = self._classify(esc_pct, burst, pattern, density)
        explain = (
            f"esc={esc_pct:.0f}% burst={burst} "
            f"pattern={pattern or 'none'} instr_density={density:.2f}"
        )
        sig = self._sign(f"{session_id}|{level}|{explain}")
        return ThreatAssessment(
            session_id=session_id,
            threat_level=level,
            escalation_pct=esc_pct,
            burst_detected=burst,
            pattern_match=pattern,
            explain=f"[threat_graph] {explain}",
            instruction_density=density,
            hmac_sha256=sig,
        )

    def _escalation_pct(self, buf: Deque[_TurnRecord]) -> float:
        if len(buf) < 2:
            return 0.0
        increases = sum(
            1 for i in range(1, len(buf))
            if buf[i].risk_score > buf[i - 1].risk_score
        )
        return (increases / (len(buf) - 1)) * 100

    def _is_burst(self, buf: Deque[_TurnRecord]) -> bool:
        if len(buf) < self._burst_thresh:
            return False
        high = self._risk.get("high", 0.8)
        recent = list(buf)[-self._burst_thresh:]
        return all(t.risk_score >= high for t in recent)

    def _match_sequence(self, buf: Deque[_TurnRecord]) -> Optional[str]:
        actions = [t.action for t in buf]
        for seq in self._sequences:
            pattern = seq.get("pattern", [])
            if len(actions) >= len(pattern):
                tail = actions[-len(pattern):]
                if tail == pattern:
                    return seq.get("name")
        return None

    def _instruction_density(self, buf: Deque[_TurnRecord]) -> float:
        """Return ratio of instruction-like actions to total actions in window."""
        if not buf:
            return 0.0
        # Unified keyword list (25 keywords: 20 EN + 5 PT-BR) — synced with
        # Rust PromptInjectionDetector::instruction_density() in mod.rs.
        _INSTR_KEYWORDS = {
            # EN keywords
            "ignore", "forget", "override", "bypass", "instructions",
            "instruct", "system", "execute", "sudo", "disregard",
            "pretend", "roleplay", "jailbreak", "unlock", "reset",
            "disable", "deactivate", "circumvent", "evade", "elevate",
            # PT-BR keywords
            "desconsidere", "esqueça", "sobreponha", "contorne", "desative",
        }
        count = sum(
            1 for t in buf
            if any(kw in t.action.lower() for kw in _INSTR_KEYWORDS)
        )
        return count / len(buf)

    def _classify(
        self, esc_pct: float, burst: bool, pattern: Optional[str],
        density: float = 0.0,
    ) -> ThreatLevel:
        if pattern or burst:
            return ThreatLevel.CRITICAL
        if esc_pct >= self._esc_pct:
            return ThreatLevel.HIGH
        if density > 0.5:
            return ThreatLevel.HIGH
        if esc_pct >= self._esc_pct / 2:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def _sign(self, payload: str) -> str:
        return hmac_lib.new(
            self._key, payload.encode(), hashlib.sha256
        ).hexdigest()
