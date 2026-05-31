"""
Webhook management API routes v1.0
GET  /v1/webhooks/status  — current config + stats
POST /v1/webhooks/reload  — reload config from YAML
POST /v1/webhooks/test    — send test notification

ADR: 0025-webhook-notifications.md
"""

import logging
import time

from fastapi import APIRouter, Depends

from buildtovalue.api.auth import require_api_key
from buildtovalue.api.webhook_dispatcher import (
    WebhookDispatcher,
    WebhookPayload,
)

logger = logging.getLogger("btv.api.webhooks")
# CRITICO-03: webhook management endpoints (status/reload/test) are privileged
# internal operations gated by an API key. NOTE: these are management routes,
# not inbound provider receivers (github/gitlab/jira), so HMAC signature
# verification (per the audit doc) does not apply here.
router = APIRouter(
    prefix="/v1/webhooks", tags=["webhooks"], dependencies=[Depends(require_api_key)]
)

# Shared dispatcher instance
dispatcher = WebhookDispatcher()


def get_dispatcher() -> WebhookDispatcher:
    """Access shared dispatcher (for integration with app.py)."""
    return dispatcher


@router.get("/status")
def webhook_status():
    """Current webhook configuration and dispatch stats."""
    return {
        "status": "ok",
        **dispatcher.stats,
    }


@router.post("/reload")
def webhook_reload():
    """Reload webhook config from YAML."""
    dispatcher.load_config()
    return {
        "status": "reloaded",
        "targets": dispatcher.target_count,
    }


@router.post("/test")
def webhook_test():
    """Send a test webhook to all configured targets."""
    payload = WebhookPayload(
        verdict_id="test_webhook_001",
        action="BLOCK",
        risk=0.99,
        findings=3,
        critical=1,
        hard_blocked=False,
        mercy_applied=False,
        profile="test",
        session_id="test_session",
        timestamp=time.time(),
    )
    results = dispatcher.notify_sync(payload)
    return {
        "status": "sent",
        "results": [
            {
                "url": r.url,
                "success": r.success,
                "status_code": r.status_code,
                "attempts": r.attempts,
                "error": r.error,
            }
            for r in results
        ],
    }