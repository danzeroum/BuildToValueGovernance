"""
NegotiationEngine — A2A propose/counter/accept/abort state machine.

Enables two agents to negotiate a shared security policy with safety guarantees.
Deterministic: no LLM in the negotiation loop (structural policy comparison only).

State machine:
  IDLE → PROPOSED → COUNTERED → ACCEPTED → CONFIRMED
                              ↘ ABORTED (timeout, max_rounds, goal drift)
  Any state → ABORTED (on GoalDriftSentinel trigger or NegotiationGuard block)

Safety properties:
  - All incoming messages pass through NegotiationGuard before processing
  - GoalDriftSentinel monitors cumulative concessions per session
  - Hard abort: timeout, max_rounds exceeded, goal drift > threshold, jailbreak blocked
  - All state transitions logged to DurableLedger
  - explain_decision mandatory on NegotiationResult (Levinas)
  - HMAC-SHA256 on every NegotiationMessage and NegotiationResult (Jonas)

BiasDeclaration (Jonas principle):
  Abort rate on compatible policies: ~0 (should converge).
  Convergence rate: TBD (measured during M7-M8 Arena calibration).
  Calibration expiry: 90 days.

ADR-056: NegotiationEngine Protocol.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac as _hmac
import json
import logging
import time
import uuid
from enum import Enum
from typing import Optional

from buildtovalue.governance.goal_drift_sentinel import GoalDriftSentinel, DriftAction
from buildtovalue.governance.durable_ledger import DurableLedger

from .a2a_channel import A2AChannel
from .alignment_degradation_tracker import AlignmentDegradationTracker
from .negotiation_guard import NegotiationGuard
from .types import NegotiationMessage, NegotiationResult

logger = logging.getLogger("btv.agentic.negotiation_engine")

_DEFAULT_HMAC_KEY: bytes = b"btv-negotiation-engine-v1"


# ─── State Machine ────────────────────────────────────────────────────────────

class NegotiationState(str, Enum):
    IDLE = "IDLE"
    PROPOSED = "PROPOSED"
    COUNTERED = "COUNTERED"
    ACCEPTED = "ACCEPTED"
    CONFIRMED = "CONFIRMED"
    ABORTED = "ABORTED"


# ─── NegotiationEngine ────────────────────────────────────────────────────────

class NegotiationEngine:
    """
    Async A2A negotiation state machine.

    Usage (proposer):
        engine = NegotiationEngine(own_policy=policy_a, ...)
        result = await engine.propose(channel_a)

    Usage (responder):
        engine = NegotiationEngine(own_policy=policy_b, ...)
        result = await engine.respond(channel_b)

    The two engines communicate through matched InProcessChannel or MCPChannel.
    """

    def __init__(
        self,
        own_policy: dict,
        goal_sentinel: GoalDriftSentinel,
        negotiation_guard: NegotiationGuard,
        ledger: DurableLedger,
        max_rounds: int = 10,
        timeout_seconds: float = 300.0,
        hmac_key: bytes = _DEFAULT_HMAC_KEY,
        session_id: Optional[str] = None,
        tracker: Optional[AlignmentDegradationTracker] = None,
    ) -> None:
        self._own_policy = own_policy
        self._sentinel = goal_sentinel
        self._guard = negotiation_guard
        self._ledger = ledger
        self._max_rounds = max_rounds
        self._timeout = timeout_seconds
        self._hmac_key = hmac_key
        self._session_id = session_id or str(uuid.uuid4())
        self._state = NegotiationState.IDLE
        self._tracker = tracker
        self._last_drift_score: float = 0.0

    # ─── Public API ───────────────────────────────────────────────────────────

    async def propose(self, channel: A2AChannel) -> NegotiationResult:
        """
        Initiate negotiation as the proposer.

        1. Send own_policy as proposal
        2. Wait for counter / accept / reject
        3. Evaluate counter, send counter or accept
        4. Continue until confirmed, aborted, max_rounds, or timeout
        """
        start = time.time()
        transcript: list[NegotiationMessage] = []
        round_number = 1

        try:
            # Send initial proposal
            proposal = self._make_message("propose", self._own_policy, None, round_number)
            transcript.append(proposal)
            await channel.send(proposal)
            self._state = NegotiationState.PROPOSED
            self._log_event("propose", round_number, proposal)

            while round_number <= self._max_rounds:
                elapsed = time.time() - start
                remaining_timeout = self._timeout - elapsed

                if remaining_timeout <= 0:
                    return self._abort(
                        "timeout", round_number, transcript, start,
                        f"Timeout after {elapsed:.1f}s (max {self._timeout}s)"
                    )

                try:
                    incoming = await asyncio.wait_for(
                        channel.receive(remaining_timeout),
                        timeout=remaining_timeout,
                    )
                except asyncio.TimeoutError:
                    return self._abort(
                        "timeout", round_number, transcript, start,
                        f"Receive timeout after {self._timeout}s"
                    )

                # Safety check
                sanitized = self._guard.sanitize(incoming)
                if not sanitized.allowed:
                    return self._abort(
                        "jailbreak_blocked", round_number, transcript, start,
                        f"NegotiationGuard blocked message: {sanitized.reason}"
                    )
                incoming = sanitized.clean_message  # type: ignore[assignment]
                transcript.append(incoming)

                if incoming.type == "abort":
                    return self._abort(
                        "peer_abort", round_number, transcript, start,
                        f"Peer sent abort: {incoming.reason}"
                    )

                if incoming.type in ("accept", "confirm"):
                    # Peer accepted our last offer
                    self._state = NegotiationState.CONFIRMED
                    return self._confirm(
                        self._own_policy, round_number, transcript, start
                    )

                if incoming.type in ("propose", "counter"):
                    # Evaluate incoming policy
                    decision, counter_policy = self._evaluate_proposal(
                        incoming.policy or {}, self._own_policy
                    )

                    # Check goal drift
                    drift_report = self._check_drift(round_number, incoming.policy or {})
                    if drift_report.drift_action == DriftAction.BLOCK:
                        return self._abort(
                            "goal_drift", round_number, transcript, start,
                            f"GoalDriftSentinel triggered: {drift_report.explain_decision}"
                        )

                    round_number += 1
                    if round_number > self._max_rounds:
                        return self._abort(
                            "max_rounds", round_number - 1, transcript, start,
                            f"Max rounds ({self._max_rounds}) exceeded"
                        )

                    if decision == "accept":
                        # Accept incoming policy
                        accept_msg = self._make_message("accept", incoming.policy, None, round_number)
                        transcript.append(accept_msg)
                        await channel.send(accept_msg)
                        self._state = NegotiationState.CONFIRMED
                        return self._confirm(incoming.policy, round_number, transcript, start)

                    if decision == "reject":
                        abort_msg = self._make_message("abort", None, "Incompatible policy", round_number)
                        transcript.append(abort_msg)
                        await channel.send(abort_msg)
                        return self._abort(
                            "incompatible_policy", round_number, transcript, start,
                            "Policies cannot be reconciled"
                        )

                    # Counter-offer
                    counter_msg = self._make_message("counter", counter_policy, "Partial acceptance", round_number)
                    transcript.append(counter_msg)
                    await channel.send(counter_msg)
                    self._state = NegotiationState.COUNTERED
                    self._log_event("counter", round_number, counter_msg)

            return self._abort(
                "max_rounds", round_number, transcript, start,
                f"Max rounds ({self._max_rounds}) exceeded"
            )

        except Exception as exc:
            logger.error("NegotiationEngine.propose unexpected error: %s", exc)
            return self._abort(
                "error", len(transcript), transcript, start, str(exc)
            )

    async def respond(self, channel: A2AChannel) -> NegotiationResult:
        """
        Respond to an incoming negotiation as the responder.

        1. Wait for initial proposal
        2. Evaluate against own policy
        3. Accept, counter, or reject
        4. Continue until confirmed, aborted, max_rounds, or timeout
        """
        start = time.time()
        transcript: list[NegotiationMessage] = []
        round_number = 0

        try:
            while round_number < self._max_rounds:
                elapsed = time.time() - start
                remaining_timeout = self._timeout - elapsed

                if remaining_timeout <= 0:
                    return self._abort(
                        "timeout", round_number, transcript, start,
                        f"Timeout after {elapsed:.1f}s"
                    )

                try:
                    incoming = await asyncio.wait_for(
                        channel.receive(remaining_timeout),
                        timeout=remaining_timeout,
                    )
                except asyncio.TimeoutError:
                    return self._abort(
                        "timeout", round_number, transcript, start,
                        f"Receive timeout after {self._timeout}s"
                    )

                # Safety check
                sanitized = self._guard.sanitize(incoming)
                if not sanitized.allowed:
                    return self._abort(
                        "jailbreak_blocked", round_number, transcript, start,
                        f"NegotiationGuard blocked: {sanitized.reason}"
                    )
                incoming = sanitized.clean_message  # type: ignore[assignment]
                transcript.append(incoming)
                round_number = incoming.round_number

                if incoming.type == "abort":
                    return self._abort(
                        "peer_abort", round_number, transcript, start,
                        f"Peer sent abort: {incoming.reason}"
                    )

                if incoming.type in ("accept", "confirm"):
                    # Proposer accepted our last counter
                    self._state = NegotiationState.CONFIRMED
                    confirm_msg = self._make_message("confirm", self._own_policy, None, round_number + 1)
                    transcript.append(confirm_msg)
                    await channel.send(confirm_msg)
                    return self._confirm(self._own_policy, round_number, transcript, start)

                if incoming.type in ("propose", "counter"):
                    # Check goal drift
                    drift_report = self._check_drift(round_number, incoming.policy or {})
                    if drift_report.drift_action == DriftAction.BLOCK:
                        abort_msg = self._make_message(
                            "abort", None,
                            f"GoalDriftSentinel: {drift_report.explain_decision[:100]}",
                            round_number + 1,
                        )
                        transcript.append(abort_msg)
                        await channel.send(abort_msg)
                        return self._abort(
                            "goal_drift", round_number, transcript, start,
                            f"GoalDriftSentinel triggered: {drift_report.explain_decision}"
                        )

                    decision, counter_policy = self._evaluate_proposal(
                        incoming.policy or {}, self._own_policy
                    )
                    round_number += 1

                    if decision == "accept":
                        accept_msg = self._make_message("accept", incoming.policy, None, round_number)
                        transcript.append(accept_msg)
                        await channel.send(accept_msg)
                        self._state = NegotiationState.CONFIRMED
                        return self._confirm(incoming.policy, round_number, transcript, start)

                    if decision == "reject":
                        abort_msg = self._make_message("abort", None, "Incompatible policy", round_number)
                        transcript.append(abort_msg)
                        await channel.send(abort_msg)
                        return self._abort(
                            "incompatible_policy", round_number, transcript, start,
                            "Policies cannot be reconciled"
                        )

                    # Counter
                    counter_msg = self._make_message("counter", counter_policy, "Partial acceptance", round_number)
                    transcript.append(counter_msg)
                    await channel.send(counter_msg)
                    self._state = NegotiationState.COUNTERED
                    self._log_event("counter", round_number, counter_msg)

            return self._abort(
                "max_rounds", round_number, transcript, start,
                f"Max rounds ({self._max_rounds}) exceeded"
            )

        except Exception as exc:
            logger.error("NegotiationEngine.respond unexpected error: %s", exc)
            return self._abort(
                "error", len(transcript), transcript, start, str(exc)
            )

    # ─── Policy Evaluation ────────────────────────────────────────────────────

    def _evaluate_proposal(
        self, incoming: dict, own: dict
    ) -> tuple[str, Optional[dict]]:
        """
        Structural comparison of incoming policy vs. own requirements.

        Returns:
          ("accept", None)           — incoming satisfies all own requirements
          ("counter", merged_policy) — partial overlap, propose merge
          ("reject", None)           — incompatible (no overlap at all)

        No LLM — pure structural key comparison.
        """
        if not own:
            return "accept", None

        # Check which own requirements are satisfied
        satisfied = 0
        own_keys = set(own.keys())
        incoming_keys = set(incoming.keys()) if incoming else set()
        overlap = own_keys & incoming_keys

        for key in overlap:
            own_val = own[key]
            inc_val = incoming.get(key)
            # Accept if values match, or if own requires True and incoming provides it
            if inc_val == own_val or (own_val is True and inc_val):
                satisfied += 1

        if len(own_keys) == 0:
            return "accept", None

        satisfaction_ratio = satisfied / len(own_keys)

        if satisfaction_ratio >= 0.8:
            # Good enough — accept
            return "accept", None
        elif satisfaction_ratio > 0.0:
            # Partial — merge: own requirements + what we can accept from incoming
            merged = dict(own)  # Start with own requirements (non-negotiable)
            for key in incoming_keys - own_keys:
                merged[key] = incoming[key]  # Accept additional non-conflicting fields
            return "counter", merged
        else:
            # No overlap — reject
            return "reject", None

    # ─── Goal Drift Check ─────────────────────────────────────────────────────

    def _check_drift(self, round_number: int, incoming_policy: dict) -> object:
        """
        Compute concession ratio and report to GoalDriftSentinel.

        Maps concession ratio to drift level:
          < 10%  → None
          < 30%  → Low
          < 60%  → Medium
          < 80%  → High
          ≥ 80%  → Critical
        """
        if not self._own_policy:
            # Nothing to drift from — report None drift
            return self._sentinel.record_and_analyze(
                self._session_id, "None", "ALLOW"
            )

        own_keys = set(self._own_policy.keys())
        if not own_keys:
            return self._sentinel.record_and_analyze(
                self._session_id, "None", "ALLOW"
            )

        # Count requirements being conceded (not present or changed)
        conceded = sum(
            1 for k in own_keys
            if k not in incoming_policy or incoming_policy[k] != self._own_policy[k]
        )
        concession_ratio = conceded / len(own_keys)
        self._last_drift_score = concession_ratio

        if concession_ratio < 0.1:
            drift_level = "None"
        elif concession_ratio < 0.3:
            drift_level = "Low"
        elif concession_ratio < 0.6:
            drift_level = "Medium"
        elif concession_ratio < 0.8:
            drift_level = "High"
        else:
            drift_level = "Critical"

        action = "BLOCK" if drift_level in ("High", "Critical") else "ALLOW"
        return self._sentinel.record_and_analyze(
            self._session_id, drift_level, action
        )

    # ─── Message Construction ─────────────────────────────────────────────────

    def _make_message(
        self,
        msg_type: str,
        policy: Optional[dict],
        reason: Optional[str],
        round_number: int,
    ) -> NegotiationMessage:
        timestamp = time.time()
        content = f"{msg_type}:{json.dumps(policy, sort_keys=True, default=str)}:{reason}:{round_number}"
        signature = _hmac.new(self._hmac_key, content.encode(), hashlib.sha256).hexdigest()
        return NegotiationMessage(
            type=msg_type,  # type: ignore[arg-type]
            policy=policy,
            reason=reason,
            round_number=round_number,
            timestamp=timestamp,
            signature=signature,
        )

    def _sign_result(
        self,
        status: str,
        shared_policy: Optional[dict],
        rounds: int,
        timestamp: float,
    ) -> str:
        content = json.dumps(
            {"status": status, "policy": shared_policy, "rounds": rounds, "ts": timestamp},
            sort_keys=True, default=str,
        )
        return _hmac.new(self._hmac_key, content.encode(), hashlib.sha256).hexdigest()

    # ─── Result Constructors ──────────────────────────────────────────────────

    def _confirm(
        self,
        shared_policy: Optional[dict],
        rounds: int,
        transcript: list[NegotiationMessage],
        start: float,
    ) -> NegotiationResult:
        duration = time.time() - start
        timestamp = time.time()
        explain = (
            f"NegotiationEngine: confirmed after {rounds} round(s), "
            f"{duration:.2f}s. Shared policy keys: "
            f"{sorted(shared_policy.keys()) if shared_policy else []}. "
            f"Session: {self._session_id}."
        )
        sig = self._sign_result("confirmed", shared_policy, rounds, timestamp)
        result = NegotiationResult(
            status="confirmed",
            shared_policy=shared_policy,
            rounds=rounds,
            duration_seconds=duration,
            drift_score=self._last_drift_score,
            abort_reason=None,
            transcript=tuple(transcript),
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )
        self._log_result(result)
        if self._tracker:
            self._tracker.record_session(
                agent_id=self._session_id,
                session_id=self._session_id,
                is_collaborative=True,
                abort_reason=result.abort_reason,
                drift_score=result.drift_score,
            )
        return result

    def _abort(
        self,
        abort_type: str,
        rounds: int,
        transcript: list[NegotiationMessage],
        start: float,
        reason: str,
    ) -> NegotiationResult:
        duration = time.time() - start
        timestamp = time.time()
        self._state = NegotiationState.ABORTED
        explain = (
            f"NegotiationEngine ABORT ({abort_type}): {reason}. "
            f"Rounds: {rounds}/{self._max_rounds}. "
            f"Duration: {duration:.2f}s. Session: {self._session_id}."
        )
        sig = self._sign_result("aborted", None, rounds, timestamp)
        result = NegotiationResult(
            status="aborted",
            shared_policy=None,
            rounds=rounds,
            duration_seconds=duration,
            drift_score=self._last_drift_score,
            abort_reason=reason,
            transcript=tuple(transcript),
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )
        self._log_result(result)
        if self._tracker:
            self._tracker.record_session(
                agent_id=self._session_id,
                session_id=self._session_id,
                is_collaborative=True,
                abort_reason=result.abort_reason,
                drift_score=result.drift_score,
            )
        return result

    # ─── Ledger Logging ───────────────────────────────────────────────────────

    def _log_event(self, event: str, round_number: int, msg: NegotiationMessage) -> None:
        try:
            self._ledger.append({
                "event": f"negotiation.{event}",
                "session_id": self._session_id,
                "round_number": round_number,
                "message_type": msg.type,
                "explain_decision": (
                    f"NegotiationEngine: {event} at round {round_number}, "
                    f"session={self._session_id}"
                ),
            })
        except Exception as exc:
            logger.warning("NegotiationEngine: ledger log failed: %s", exc)

    def _log_result(self, result: NegotiationResult) -> None:
        try:
            self._ledger.append({
                "event": f"negotiation.{result.status}",
                "session_id": self._session_id,
                "status": result.status,
                "rounds": result.rounds,
                "duration_seconds": result.duration_seconds,
                "abort_reason": result.abort_reason,
                "explain_decision": result.explain_decision,
            })
        except Exception as exc:
            logger.warning("NegotiationEngine: result ledger log failed: %s", exc)
