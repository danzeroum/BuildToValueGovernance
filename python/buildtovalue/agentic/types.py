"""
Shared types for the agentic layer.

Defined here to avoid circular imports between:
  a2a_channel.py ← NegotiationMessage
  negotiation_guard.py ← NegotiationMessage
  negotiation_engine.py ← NegotiationMessage, NegotiationResult
  arena_reporter.py ← NegotiationResult

Invariants:
  - All dataclasses are frozen (immutable after creation)
  - NegotiationResult carries explain_decision (Levinas: transparency)
  - NegotiationResult carries signature (Jonas: responsibility)
"""
from __future__ import annotations

import hmac as _hmac
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Literal, Optional


# ─── Negotiation Message ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class NegotiationMessage:
    """
    Atomic unit of agent-to-agent communication during negotiation.

    signature: HMAC-SHA256 over (type + str(policy) + str(reason) + str(round_number))
    All messages must pass through NegotiationGuard before processing.
    """
    type: Literal["propose", "counter", "accept", "reject", "confirm", "abort"]
    policy: Optional[dict]
    reason: Optional[str]
    round_number: int
    timestamp: float
    signature: str  # HMAC-SHA256


# ─── Negotiation Result ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class NegotiationResult:
    """
    Final outcome of a negotiation session.

    status: "confirmed" if shared policy reached, "aborted" otherwise.
    shared_policy: only populated when status == "confirmed".
    explain_decision: mandatory (Levinas — full transparency of process).
    signature: HMAC-SHA256 of result content (Jonas — responsibility chain).
    """
    status: Literal["confirmed", "aborted"]
    shared_policy: Optional[dict]
    rounds: int
    duration_seconds: float
    drift_score: float
    abort_reason: Optional[str]
    transcript: tuple[NegotiationMessage, ...]
    explain_decision: str
    timestamp: float
    signature: str
