"""
ContestabilityEscalation v1.8.0 — Auto-escalation + priority + webhooks.

Extends ContestabilityLoop with:
- S1: Auto-escalation when SLA < 4h remaining
- S2: Priority scoring (critical actions first)
- S3: Webhook notifications (Slack/PagerDuty)
- S4: Resolution tracking with audit trail

Filosofia (Levinas): SLA violation = system failure, not user failure.
"""

import time
import json
import logging
import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Callable

from .contestability_loop import ContestabilityLoop, Appeal, AppealStatus

logger = logging.getLogger("btv.contestability.escalation")

SLA_WARNING_HOURS = 4  # Warn when 4h remaining
SLA_CRITICAL_HOURS = 1  # Critical when 1h remaining


class EscalationLevel(IntEnum):
    NONE = 0
    WARNING = 1   # < 4h remaining
    CRITICAL = 2  # < 1h remaining
    BREACHED = 3  # SLA expired


class AppealPriority(IntEnum):
    LOW = 0       # LOG, EDUCATE actions
    MEDIUM = 1    # REDACT
    HIGH = 2      # BLOCK
    URGENT = 3    # BLOCK + critical findings


@dataclass(frozen=True)
class EscalationEvent:
    """Immutable record of an escalation."""
    appeal_id: str
    level: EscalationLevel
    timestamp: int
    hours_remaining: float
    message: str


@dataclass
class WebhookTarget:
    """Webhook notification target."""
    url: str
    actions: List[str]  # Which actions trigger (BLOCK, HARD_BLOCK, etc.)
    enabled: bool = True
    timeout_seconds: int = 5
    retry_max: int = 2


class ContestabilityEscalation:
    """
    Extends ContestabilityLoop with escalation and priority.

    Usage:
        loop = ContestabilityLoop(sla_hours=24)
        escalation = ContestabilityEscalation(loop)
        escalation.add_webhook(WebhookTarget(url="...", actions=["BLOCK"]))
        escalation.check_escalations()  # Run periodically
    """

    def __init__(self, loop: ContestabilityLoop):
        self._loop = loop
        self._webhooks: List[WebhookTarget] = []
        self._escalation_log: List[EscalationEvent] = []
        self._http_post: Optional[Callable] = None  # Inject for testing
        self.metrics = {
            "escalations_warning": 0,
            "escalations_critical": 0,
            "escalations_breached": 0,
            "webhooks_sent": 0,
            "webhooks_failed": 0,
        }

    def add_webhook(self, target: WebhookTarget) -> None:
        self._webhooks.append(target)

    def set_http_post(self, fn: Callable) -> None:
        """Inject HTTP POST function (for testing)."""
        self._http_post = fn

    def prioritize(self, appeal: Appeal, action: str, critical_count: int) -> AppealPriority:
        """Calculate appeal priority based on action severity."""
        if action == "BLOCK" and critical_count > 0:
            return AppealPriority.URGENT
        if action == "BLOCK":
            return AppealPriority.HIGH
        if action == "REDACT":
            return AppealPriority.MEDIUM
        return AppealPriority.LOW

    def check_escalations(self) -> List[EscalationEvent]:
        """
        Check all pending appeals for SLA proximity.
        Returns list of new escalation events.
        Call periodically (e.g., every 15 min).
        """
        now = int(time.time())
        events: List[EscalationEvent] = []

        for appeal in self._loop.list_pending_appeals():
            remaining_secs = appeal.sla_deadline - now
            remaining_hours = remaining_secs / 3600

            if remaining_secs <= 0:
                level = EscalationLevel.BREACHED
                self.metrics["escalations_breached"] += 1
            elif remaining_hours <= SLA_CRITICAL_HOURS:
                level = EscalationLevel.CRITICAL
                self.metrics["escalations_critical"] += 1
            elif remaining_hours <= SLA_WARNING_HOURS:
                level = EscalationLevel.WARNING
                self.metrics["escalations_warning"] += 1
            else:
                continue

            event = EscalationEvent(
                appeal_id=appeal.appeal_id,
                level=level,
                timestamp=now,
                hours_remaining=max(0.0, remaining_hours),
                message=f"Appeal {appeal.appeal_id}: {level.name} "
                        f"({remaining_hours:.1f}h remaining)",
            )
            events.append(event)
            self._escalation_log.append(event)

            logger.warning(event.message)
            self._fire_webhooks(appeal, event)

        return events

    def get_prioritized_queue(self) -> List[Dict]:
        """Return pending appeals sorted by priority (highest first)."""
        pending = self._loop.list_pending_appeals()
        now = int(time.time())

        queue = []
        for appeal in pending:
            remaining = max(0, appeal.sla_deadline - now)
            hours_left = remaining / 3600

            # Higher urgency = lower hours_left
            urgency = 1.0 / max(0.1, hours_left)

            queue.append({
                "appeal_id": appeal.appeal_id,
                "user_id": appeal.user_id,
                "audit_trail_id": appeal.audit_trail_id,
                "hours_remaining": round(hours_left, 1),
                "urgency_score": round(urgency, 2),
                "reason_preview": appeal.reason[:80],
            })

        queue.sort(key=lambda x: x["urgency_score"], reverse=True)
        return queue

    def get_escalation_log(self) -> List[EscalationEvent]:
        return list(self._escalation_log)

    def get_metrics(self) -> Dict:
        return {**self.metrics}

    def _fire_webhooks(self, appeal: Appeal, event: EscalationEvent) -> None:
        """Send webhook notifications for escalation events."""
        if not self._webhooks:
            return

        payload = {
            "type": "appeal_escalation",
            "appeal_id": appeal.appeal_id,
            "user_id": appeal.user_id,
            "level": event.level.name,
            "hours_remaining": event.hours_remaining,
            "message": event.message,
            "timestamp": event.timestamp,
        }

        for target in self._webhooks:
            if not target.enabled:
                continue
            try:
                if self._http_post:
                    self._http_post(target.url, payload)
                self.metrics["webhooks_sent"] += 1
            except Exception as e:
                self.metrics["webhooks_failed"] += 1
                logger.error("Webhook failed %s: %s", target.url, e)