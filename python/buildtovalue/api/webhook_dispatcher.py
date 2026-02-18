"""
WebhookDispatcher v1.0
Fire-and-forget notifications for critical decisions.

Invariants:
  - Webhook failure NEVER blocks the verdict pipeline
  - Timeout: 5s per attempt
  - Retry: max 2 with linear backoff (1s, 2s)
  - No original input in payload (privacy)

ADR: 0026-webhook-notifications.md
"""

import logging
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

logger = logging.getLogger("btv.webhook")

DEFAULT_TIMEOUT = 5.0
DEFAULT_RETRY_MAX = 2
CONFIG_PATH = "data/policies/webhooks.yaml"


@dataclass(frozen=True)
class WebhookTarget:
    """A configured webhook endpoint."""
    url: str
    actions: List[str]
    enabled: bool = True
    timeout_seconds: float = DEFAULT_TIMEOUT
    retry_max: int = DEFAULT_RETRY_MAX


@dataclass(frozen=True)
class WebhookPayload:
    """What gets sent — never includes original input."""
    verdict_id: str
    action: str
    risk: float
    findings: int
    critical: int
    hard_blocked: bool
    mercy_applied: bool
    profile: str
    session_id: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return {
            "event": "btv.decision",
            "verdict_id": self.verdict_id,
            "action": self.action,
            "risk": self.risk,
            "findings": self.findings,
            "critical": self.critical,
            "hard_blocked": self.hard_blocked,
            "mercy_applied": self.mercy_applied,
            "profile": self.profile,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
        }


@dataclass
class WebhookResult:
    """Result of a single webhook dispatch attempt."""
    url: str
    success: bool
    status_code: Optional[int] = None
    attempts: int = 0
    error: Optional[str] = None


class WebhookDispatcher:
    """
    Dispatches webhook notifications for critical decisions.

    Fire-and-forget: failures are logged but never block the
    verdict pipeline. Dispatch runs in a background thread.
    """

    def __init__(
        self,
        config_path: str = CONFIG_PATH,
    ) -> None:
        self._targets: List[WebhookTarget] = []
        self._config_path = Path(config_path)
        self._dispatch_count = 0
        self._failure_count = 0
        self.load_config()

    def load_config(self) -> None:
        """Load webhook targets from YAML config."""
        self._targets = []
        if not self._config_path.is_file():
            logger.info("No webhook config at %s", self._config_path)
            return

        try:
            with open(self._config_path, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
            if not doc or "webhooks" not in doc:
                return
            for entry in doc["webhooks"]:
                target = WebhookTarget(
                    url=entry["url"],
                    actions=[a.upper() for a in entry.get("actions", [])],
                    enabled=entry.get("enabled", True),
                    timeout_seconds=entry.get(
                        "timeout_seconds", DEFAULT_TIMEOUT
                    ),
                    retry_max=entry.get("retry_max", DEFAULT_RETRY_MAX),
                )
                if target.enabled:
                    self._targets.append(target)
            logger.info(
                "Loaded %d webhook targets", len(self._targets)
            )
        except Exception as exc:
            logger.error("Failed to load webhook config: %s", exc)

    @property
    def target_count(self) -> int:
        return len(self._targets)

    @property
    def stats(self) -> Dict:
        return {
            "targets": self.target_count,
            "dispatched": self._dispatch_count,
            "failures": self._failure_count,
        }

    def should_notify(self, action: str) -> bool:
        """Check if any target wants this action."""
        action_upper = action.upper()
        return any(
            action_upper in t.actions
            for t in self._targets
        )

    def notify(self, payload: WebhookPayload) -> None:
        """
        Dispatch webhooks in background thread (fire-and-forget).

        Never blocks the calling thread. Failures are logged only.
        """
        if not self._targets:
            return
        if not self.should_notify(payload.action):
            return

        thread = threading.Thread(
            target=self._dispatch_all,
            args=(payload,),
            daemon=True,
        )
        thread.start()

    def notify_sync(self, payload: WebhookPayload) -> List[WebhookResult]:
        """
        Synchronous dispatch (for testing). Returns results.
        """
        return self._dispatch_all(payload)

    def _dispatch_all(
        self, payload: WebhookPayload
    ) -> List[WebhookResult]:
        """Send to all matching targets with retry."""
        results: List[WebhookResult] = []
        action_upper = payload.action.upper()
        data = payload.to_dict()

        for target in self._targets:
            if action_upper not in target.actions:
                continue
            result = self._send_with_retry(target, data)
            results.append(result)
            self._dispatch_count += 1
            if not result.success:
                self._failure_count += 1

        return results

    def _send_with_retry(
        self, target: WebhookTarget, data: Dict
    ) -> WebhookResult:
        """Send with linear backoff retry."""
        if not HTTPX_AVAILABLE:
            return WebhookResult(
                url=target.url,
                success=False,
                attempts=0,
                error="httpx not installed",
            )

        last_error = ""
        for attempt in range(1, target.retry_max + 2):  # +1 for initial
            try:
                resp = httpx.post(
                    target.url,
                    json=data,
                    timeout=target.timeout_seconds,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "BuildToValue-Webhook/1.0",
                        "X-BTV-Event": "decision",
                    },
                )
                if 200 <= resp.status_code < 300:
                    logger.info(
                        "Webhook sent to %s (attempt %d, %d)",
                        target.url, attempt, resp.status_code,
                    )
                    return WebhookResult(
                        url=target.url,
                        success=True,
                        status_code=resp.status_code,
                        attempts=attempt,
                    )
                last_error = f"HTTP {resp.status_code}"
            except Exception as exc:
                last_error = str(exc)

            if attempt <= target.retry_max:
                time.sleep(attempt)  # linear backoff: 1s, 2s

        logger.warning(
            "Webhook failed for %s after %d attempts: %s",
            target.url, target.retry_max + 1, last_error,
        )
        return WebhookResult(
            url=target.url,
            success=False,
            attempts=target.retry_max + 1,
            error=last_error,
        )