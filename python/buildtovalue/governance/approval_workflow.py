"""ApprovalWorkflow — Gap F: Human-in-the-Loop Approval.

Manages approval tickets for high-risk agent actions.
Tickets have TTL; expired tickets -> BLOCK (fail-secure).

Invariants:
- Fail-secure: expired -> BLOCK, error -> BLOCK
- HMAC-SHA256 signed tickets
- explain_decision on every status
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .agent_pdp import AgentDecisionRequest, AgentVerdict
from .types import ActionType

logger = logging.getLogger("btv.governance.approval_workflow")

_DEFAULT_TIMEOUT = 3600  # 1 hour


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


@dataclass
class ApprovalTicket:
    ticket_id: str
    request_id: str
    agent_id: str
    action_name: str
    reason: str
    status: ApprovalStatus
    created_at: float
    timeout_s: int
    approver_id: Optional[str] = None
    resolved_at: Optional[float] = None
    hmac_sha256: str = ""


class ApprovalWorkflow:
    """Manages human-in-the-loop approval tickets."""

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        hmac_key: bytes = b"btv-approval-default-key",
    ) -> None:
        raw = self._load(policy_path) if policy_path else {}
        self._timeout = raw.get("default_timeout_s", _DEFAULT_TIMEOUT)
        self._triggers = raw.get("approval_triggers", {})
        self._expired_action = raw.get("expired_action", "BLOCK")
        self._key = hmac_key
        self._tickets: Dict[str, ApprovalTicket] = {}

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def needs_approval(self, request: AgentDecisionRequest) -> bool:
        """Check if action requires HITL approval per policy."""
        impacts = self._triggers.get("impact_requires_approval", [])
        if request.action.impact.value in impacts:
            return True
        actions = self._triggers.get("actions_require_approval", [])
        if request.action.name in actions:
            return True
        threshold = self._triggers.get("trust_score_threshold", 0.0)
        if request.context.session_trust_score < threshold:
            return True
        return False

    def request_approval(
        self,
        request: AgentDecisionRequest,
        reason: str,
        timeout_s: Optional[int] = None,
    ) -> ApprovalTicket:
        """Create a pending approval ticket."""
        ticket_id = str(uuid.uuid4())
        now = time.time()
        sig = self._sign(f"{ticket_id}|{request.request_id}|{now}")
        ticket = ApprovalTicket(
            ticket_id=ticket_id,
            request_id=request.request_id,
            agent_id=request.agent_id,
            action_name=request.action.name,
            reason=reason,
            status=ApprovalStatus.PENDING,
            created_at=now,
            timeout_s=timeout_s if timeout_s is not None else self._timeout,
            hmac_sha256=sig,
        )
        self._tickets[ticket_id] = ticket
        logger.info("Approval requested: %s for %s", ticket_id, request.action.name)
        return ticket

    def check_status(self, ticket_id: str) -> ApprovalStatus:
        """Check ticket status; auto-expire if timed out."""
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            return ApprovalStatus.EXPIRED
        if ticket.status == ApprovalStatus.PENDING:
            if ticket.timeout_s == 0 or (
                time.time() - ticket.created_at >= ticket.timeout_s
            ):
                ticket.status = ApprovalStatus.EXPIRED
                ticket.resolved_at = time.time()
        return ticket.status

    def resolve(
        self,
        ticket_id: str,
        approved: bool,
        approver_id: str,
    ) -> ApprovalTicket:
        """Resolve a pending ticket."""
        ticket = self._tickets.get(ticket_id)
        if ticket is None:
            raise ValueError(f"Unknown ticket: {ticket_id}")
        if self.check_status(ticket_id) == ApprovalStatus.EXPIRED:
            return ticket
        ticket.status = (
            ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
        )
        ticket.approver_id = approver_id
        ticket.resolved_at = time.time()
        ticket.hmac_sha256 = self._sign(
            f"{ticket_id}|{ticket.status}|{approver_id}"
        )
        return ticket

    def _sign(self, payload: str) -> str:
        return hmac_lib.new(
            self._key, payload.encode(), hashlib.sha256
        ).hexdigest()
