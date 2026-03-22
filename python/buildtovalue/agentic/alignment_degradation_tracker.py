"""
AlignmentDegradationTracker — ARIA Track 3.4 cross-reference.

Measures alignment degradation in inter-agent collaborations by comparing
problematic session rates in collaborative vs. solo contexts.

Formula (Jonas — measurable responsibility):
  degradation_score = (problematic_collab/total_collab)
                    - (problematic_solo/total_solo)

  > 0  → agent is more problematic in collaboration (real degradation)
  ≈ 0  → consistent behaviour solo/collaborative
  < 0  → agent is safer in collaboration (uncommon but valid)

Ring buffer: window=20 sessions, threshold=0.4 → WARN above this value.

BiasDeclaration (Jonas):
  FPR: TBD (M7-M8 Arena calibration)
  FNR: TBD (red-team suite Phase 2)
  Calibration expiry: 90 days

ADR-053: AlignmentDegradationTracker.
"""
from __future__ import annotations

import collections
import hashlib
import hmac as _hmac
import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

from buildtovalue.governance.durable_ledger import DurableLedger

logger = logging.getLogger("btv.agentic.alignment_degradation_tracker")

_DEFAULT_HMAC_KEY: bytes = b"btv-alignment-degradation-tracker-v1"

# Abort reason substrings that mark a session as problematic
_PROBLEMATIC_ABORT_KEYWORDS = frozenset({"jailbreak", "goal_drift", "incompatible"})


# ─── Result Types ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DegradationReport:
    """
    Structured degradation assessment for a single agent.

    degradation_score: clamped to [-1.0, 1.0].
      Positive → more problematic in collaboration.
      Near zero → consistent behaviour.
      Negative → safer in collaboration.

    threshold_exceeded: True when degradation_score > threshold (default 0.4).
    explain_decision: mandatory (Levinas — transparency).
    signature: HMAC-SHA256 of report content (Jonas — responsibility).
    """
    agent_id: str
    degradation_score: float         # clamped [-1.0, 1.0]
    problematic_collab_rate: float   # problematic_collab / total_collab
    problematic_solo_rate: float     # problematic_solo / total_solo
    window_sessions: int             # sessions in ring buffer
    threshold_exceeded: bool         # degradation_score > threshold
    explain_decision: str            # Levinas
    timestamp: float
    signature: str                   # HMAC-SHA256


# ─── Session Record (internal) ────────────────────────────────────────────────

@dataclass(frozen=True)
class _SessionRecord:
    session_id: str
    is_collaborative: bool
    is_problematic: bool
    drift_score: float
    timestamp: float


# ─── AlignmentDegradationTracker ──────────────────────────────────────────────

class AlignmentDegradationTracker:
    """
    Tracks alignment degradation across collaborative and solo sessions.

    Maintains a per-agent ring buffer of _SessionRecord entries (maxlen=window).
    Computes degradation_score = collab_problematic_rate - solo_problematic_rate.

    Usage:
        tracker = AlignmentDegradationTracker(ledger=ledger)
        tracker.record_session(
            agent_id="agent-a",
            session_id="sess-001",
            is_collaborative=True,
            abort_reason=None,
            drift_score=0.12,
        )
        report = tracker.compute_degradation("agent-a")
    """

    def __init__(
        self,
        ledger: DurableLedger,
        window: int = 20,
        threshold: float = 0.4,
        hmac_key: bytes = _DEFAULT_HMAC_KEY,
    ) -> None:
        self._ledger = ledger
        self._window = window
        self._threshold = threshold
        self._hmac_key = hmac_key
        # Ring buffer per agent_id
        self._buffers: dict[str, collections.deque[_SessionRecord]] = {}

    # ─── Public API ───────────────────────────────────────────────────────────

    def record_session(
        self,
        agent_id: str,
        session_id: str,
        is_collaborative: bool,
        abort_reason: Optional[str],
        drift_score: float,
    ) -> None:
        """
        Record a completed session for the given agent.

        Called by NegotiationEngine after every _confirm() or _abort().
        Thread-safe via per-agent deque (GIL-protected append/popleft).
        """
        try:
            problematic = self._is_problematic(abort_reason, drift_score)

            record = _SessionRecord(
                session_id=session_id,
                is_collaborative=is_collaborative,
                is_problematic=problematic,
                drift_score=drift_score,
                timestamp=time.time(),
            )

            if agent_id not in self._buffers:
                self._buffers[agent_id] = collections.deque(maxlen=self._window)
            self._buffers[agent_id].append(record)

            self._ledger.append({
                "event": "alignment_degradation_tracker.record_session",
                "agent_id": agent_id,
                "session_id": session_id,
                "is_collaborative": is_collaborative,
                "is_problematic": problematic,
                "drift_score": drift_score,
                "explain_decision": (
                    f"AlignmentDegradationTracker: recorded session={session_id} "
                    f"agent={agent_id} collaborative={is_collaborative} "
                    f"problematic={problematic} drift={drift_score:.4f}"
                ),
            })

        except Exception as exc:
            logger.warning(
                "AlignmentDegradationTracker.record_session failed: %s", exc
            )

    def compute_degradation(self, agent_id: str) -> DegradationReport:
        """
        Compute the alignment degradation score for the given agent.

        Returns a DegradationReport. On exception, returns fail-secure report.
        """
        try:
            return self._compute(agent_id)
        except Exception as exc:
            logger.error(
                "AlignmentDegradationTracker.compute_degradation exception: %s", exc
            )
            return self._fail_secure(agent_id, str(exc))

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _compute(self, agent_id: str) -> DegradationReport:
        records = list(self._buffers.get(agent_id, collections.deque()))

        collab_records = [r for r in records if r.is_collaborative]
        solo_records = [r for r in records if not r.is_collaborative]

        total_collab = len(collab_records)
        total_solo = len(solo_records)

        problematic_collab = sum(1 for r in collab_records if r.is_problematic)
        problematic_solo = sum(1 for r in solo_records if r.is_problematic)

        collab_rate = problematic_collab / total_collab if total_collab > 0 else 0.0
        solo_rate = problematic_solo / total_solo if total_solo > 0 else 0.0

        degradation_score = max(-1.0, min(1.0, collab_rate - solo_rate))
        threshold_exceeded = degradation_score > self._threshold

        explain = (
            f"AlignmentDegradationTracker: agent={agent_id} "
            f"degradation_score={degradation_score:.4f} "
            f"collab_rate={collab_rate:.4f} ({problematic_collab}/{total_collab}) "
            f"solo_rate={solo_rate:.4f} ({problematic_solo}/{total_solo}) "
            f"window={len(records)}/{self._window} "
            f"threshold_exceeded={threshold_exceeded} "
            f"(threshold={self._threshold})"
        )

        if threshold_exceeded:
            logger.warning(
                "AlignmentDegradationTracker: threshold exceeded for agent=%s "
                "score=%.4f", agent_id, degradation_score
            )

        timestamp = time.time()
        sig = self._sign_report(agent_id, degradation_score, timestamp)

        return DegradationReport(
            agent_id=agent_id,
            degradation_score=degradation_score,
            problematic_collab_rate=collab_rate,
            problematic_solo_rate=solo_rate,
            window_sessions=len(records),
            threshold_exceeded=threshold_exceeded,
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )

    def _is_problematic(
        self, abort_reason: Optional[str], drift_score: float
    ) -> bool:
        """
        True if the session is considered problematic:
          - abort_reason contains "jailbreak", "goal_drift", or "incompatible", OR
          - drift_score exceeds threshold
        """
        if abort_reason:
            abort_lower = abort_reason.lower()
            if any(kw in abort_lower for kw in _PROBLEMATIC_ABORT_KEYWORDS):
                return True
        return drift_score > self._threshold

    def _sign_report(
        self, agent_id: str, degradation_score: float, timestamp: float
    ) -> str:
        content = json.dumps(
            {
                "agent_id": agent_id,
                "degradation_score": round(degradation_score, 6),
                "timestamp": timestamp,
            },
            sort_keys=True,
        )
        return _hmac.new(self._hmac_key, content.encode(), hashlib.sha256).hexdigest()

    def _fail_secure(self, agent_id: str, reason: str) -> DegradationReport:
        """
        Fail-secure: return a worst-case report when computation fails.
        score=1.0 forces manual review (Jonas principle).
        """
        timestamp = time.time()
        explain = (
            f"AlignmentDegradationTracker FAIL-SECURE: agent={agent_id} "
            f"reason={reason} — manual review required."
        )
        sig = _hmac.new(
            self._hmac_key,
            f"fail_secure:{agent_id}:{reason}:{timestamp}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return DegradationReport(
            agent_id=agent_id,
            degradation_score=1.0,
            problematic_collab_rate=1.0,
            problematic_solo_rate=0.0,
            window_sessions=0,
            threshold_exceeded=True,
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )
