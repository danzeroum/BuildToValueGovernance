"""
P7: ContestabilityEscalation tests.
"""

import time
import pytest
from unittest.mock import MagicMock

from buildtovalue.governance.contestability_loop import (
    ContestabilityLoop, AppealStatus,
)
from buildtovalue.governance.contestability_escalation import (
    ContestabilityEscalation,
    EscalationLevel,
    AppealPriority,
    WebhookTarget,
)


@pytest.fixture
def loop():
    return ContestabilityLoop(sla_hours=24)


@pytest.fixture
def escalation(loop):
    return ContestabilityEscalation(loop)


class TestPrioritize:

    def test_block_critical_is_urgent(self, escalation, loop):
        appeal = loop.submit_appeal(1, "u1", "This is a test reason for appeal.")
        p = escalation.prioritize(appeal, "BLOCK", critical_count=2)
        assert p == AppealPriority.URGENT

    def test_block_no_critical_is_high(self, escalation, loop):
        appeal = loop.submit_appeal(2, "u2", "This is a test reason for appeal.")
        p = escalation.prioritize(appeal, "BLOCK", critical_count=0)
        assert p == AppealPriority.HIGH

    def test_redact_is_medium(self, escalation, loop):
        appeal = loop.submit_appeal(3, "u3", "This is a test reason for appeal.")
        p = escalation.prioritize(appeal, "REDACT", critical_count=0)
        assert p == AppealPriority.MEDIUM

    def test_educate_is_low(self, escalation, loop):
        appeal = loop.submit_appeal(4, "u4", "This is a test reason for appeal.")
        p = escalation.prioritize(appeal, "EDUCATE", critical_count=0)
        assert p == AppealPriority.LOW


class TestEscalationCheck:

    def test_no_pending_no_events(self, escalation):
        events = escalation.check_escalations()
        assert events == []

    def test_fresh_appeal_no_escalation(self, escalation, loop):
        loop.submit_appeal(1, "u1", "This is a test reason for appeal.")
        events = escalation.check_escalations()
        assert events == []  # 24h remaining, no escalation

    def test_nearly_expired_triggers_warning(self, escalation, loop):
        appeal = loop.submit_appeal(1, "u1", "This is a test reason for appeal.")
        # Force SLA to 3h remaining
        appeal.sla_deadline = int(time.time()) + (3 * 3600)
        events = escalation.check_escalations()
        assert len(events) == 1
        assert events[0].level == EscalationLevel.WARNING

    def test_almost_expired_triggers_critical(self, escalation, loop):
        appeal = loop.submit_appeal(1, "u1", "This is a test reason for appeal.")
        appeal.sla_deadline = int(time.time()) + (30 * 60)  # 30 min
        events = escalation.check_escalations()
        assert len(events) == 1
        assert events[0].level == EscalationLevel.CRITICAL

    def test_expired_triggers_breached(self, escalation, loop):
        appeal = loop.submit_appeal(1, "u1", "This is a test reason for appeal.")
        appeal.sla_deadline = int(time.time()) - 60  # Already expired
        events = escalation.check_escalations()
        assert len(events) == 1
        assert events[0].level == EscalationLevel.BREACHED


class TestPrioritizedQueue:

    def test_most_urgent_first(self, escalation, loop):
        a1 = loop.submit_appeal(1, "u1", "This is a test reason for first appeal.")
        a2 = loop.submit_appeal(2, "u2", "This is a test reason for second appeal.")
        a1.sla_deadline = int(time.time()) + (2 * 3600)   # 2h left
        a2.sla_deadline = int(time.time()) + (20 * 3600)  # 20h left
        queue = escalation.get_prioritized_queue()
        assert len(queue) == 2
        assert queue[0]["appeal_id"] == a1.appeal_id  # Most urgent first

    def test_empty_queue(self, escalation):
        assert escalation.get_prioritized_queue() == []


class TestWebhooks:

    def test_webhook_fired_on_escalation(self, escalation, loop):
        mock_post = MagicMock()
        escalation.set_http_post(mock_post)
        escalation.add_webhook(WebhookTarget(
            url="https://hooks.slack.com/test",
            actions=["BLOCK"],
        ))
        appeal = loop.submit_appeal(1, "u1", "This is a test reason for appeal.")
        appeal.sla_deadline = int(time.time()) + (30 * 60)

        escalation.check_escalations()

        mock_post.assert_called_once()
        payload = mock_post.call_args[0][1]
        assert payload["type"] == "appeal_escalation"
        assert payload["level"] == "CRITICAL"
        assert escalation.metrics["webhooks_sent"] == 1

    def test_webhook_failure_counted(self, escalation, loop):
        mock_post = MagicMock(side_effect=Exception("timeout"))
        escalation.set_http_post(mock_post)
        escalation.add_webhook(WebhookTarget(url="https://fail.test", actions=["BLOCK"]))
        appeal = loop.submit_appeal(1, "u1", "This is a test reason for appeal.")
        appeal.sla_deadline = int(time.time()) - 10

        escalation.check_escalations()

        assert escalation.metrics["webhooks_failed"] == 1

    def test_disabled_webhook_skipped(self, escalation, loop):
        mock_post = MagicMock()
        escalation.set_http_post(mock_post)
        escalation.add_webhook(WebhookTarget(
            url="https://disabled.test", actions=["BLOCK"], enabled=False,
        ))
        appeal = loop.submit_appeal(1, "u1", "This is a test reason for appeal.")
        appeal.sla_deadline = int(time.time()) - 10

        escalation.check_escalations()

        mock_post.assert_not_called()


class TestMetrics:

    def test_escalation_metrics(self, escalation, loop):
        a1 = loop.submit_appeal(1, "u1", "This is a test reason for appeal one.")
        a2 = loop.submit_appeal(2, "u2", "This is a test reason for appeal two.")
        a1.sla_deadline = int(time.time()) + (3 * 3600)  # WARNING
        a2.sla_deadline = int(time.time()) - 60            # BREACHED

        escalation.check_escalations()

        m = escalation.get_metrics()
        assert m["escalations_warning"] == 1
        assert m["escalations_breached"] == 1

    def test_escalation_log(self, escalation, loop):
        appeal = loop.submit_appeal(1, "u1", "This is a test reason for appeal.")
        appeal.sla_deadline = int(time.time()) + (30 * 60)

        escalation.check_escalations()

        log = escalation.get_escalation_log()
        assert len(log) == 1
        assert log[0].appeal_id == appeal.appeal_id