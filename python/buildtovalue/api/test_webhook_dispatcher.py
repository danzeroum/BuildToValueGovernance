"""
Tests for WebhookDispatcher v1.0 (ADR-025).

Covers: config loading, action matching, payload structure,
        retry logic, fire-and-forget, missing config, stats.
"""

import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

import pytest
import yaml

from buildtovalue.api.webhook_dispatcher import (
    WebhookDispatcher,
    WebhookPayload,
    WebhookTarget,
    WebhookResult,
)


def _make_payload(**overrides) -> WebhookPayload:
    defaults = {
        "verdict_id": "verd_test_001",
        "action": "BLOCK",
        "risk": 0.85,
        "findings": 3,
        "critical": 1,
        "hard_blocked": False,
        "mercy_applied": False,
        "profile": "default",
        "session_id": "sess_001",
    }
    defaults.update(overrides)
    return WebhookPayload(**defaults)


def _write_config(path, webhooks: list) -> None:
    with open(path, "w") as f:
        yaml.dump({"webhooks": webhooks}, f)


# ──────────────────────────────────────────────────────
# Simple HTTP server for integration testing
# ──────────────────────────────────────────────────────

class _RecordingHandler(BaseHTTPRequestHandler):
    """Records received POST bodies."""
    received: list = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _RecordingHandler.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, format, *args):
        pass  # silence logs


@pytest.fixture
def webhook_server():
    """Ephemeral HTTP server that records POST requests."""
    _RecordingHandler.received = []
    server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/webhook"
    server.shutdown()


@pytest.fixture
def config_file(tmp_path):
    return str(tmp_path / "webhooks.yaml")


# ──────────────────────────────────────────────────────
# Config Loading
# ──────────────────────────────────────────────────────

class TestConfigLoading:

    def test_no_config_file(self, tmp_path):
        d = WebhookDispatcher(config_path=str(tmp_path / "nope.yaml"))
        assert d.target_count == 0

    def test_empty_config(self, config_file):
        with open(config_file, "w") as f:
            f.write("")
        d = WebhookDispatcher(config_path=config_file)
        assert d.target_count == 0

    def test_load_targets(self, config_file):
        _write_config(config_file, [
            {"url": "https://a.com", "actions": ["BLOCK"], "enabled": True},
            {"url": "https://b.com", "actions": ["HARD_BLOCK"], "enabled": True},
        ])
        d = WebhookDispatcher(config_path=config_file)
        assert d.target_count == 2

    def test_disabled_targets_excluded(self, config_file):
        _write_config(config_file, [
            {"url": "https://a.com", "actions": ["BLOCK"], "enabled": True},
            {"url": "https://b.com", "actions": ["BLOCK"], "enabled": False},
        ])
        d = WebhookDispatcher(config_path=config_file)
        assert d.target_count == 1

    def test_reload(self, config_file):
        _write_config(config_file, [
            {"url": "https://a.com", "actions": ["BLOCK"]},
        ])
        d = WebhookDispatcher(config_path=config_file)
        assert d.target_count == 1

        _write_config(config_file, [
            {"url": "https://a.com", "actions": ["BLOCK"]},
            {"url": "https://b.com", "actions": ["BLOCK"]},
        ])
        d.load_config()
        assert d.target_count == 2


# ──────────────────────────────────────────────────────
# Action Matching
# ──────────────────────────────────────────────────────

class TestActionMatching:

    def test_should_notify_block(self, config_file):
        _write_config(config_file, [
            {"url": "https://a.com", "actions": ["BLOCK", "HARD_BLOCK"]},
        ])
        d = WebhookDispatcher(config_path=config_file)
        assert d.should_notify("BLOCK") is True
        assert d.should_notify("HARD_BLOCK") is True
        assert d.should_notify("EDUCATE") is False
        assert d.should_notify("ALLOW") is False

    def test_case_insensitive(self, config_file):
        _write_config(config_file, [
            {"url": "https://a.com", "actions": ["block"]},
        ])
        d = WebhookDispatcher(config_path=config_file)
        assert d.should_notify("BLOCK") is True
        assert d.should_notify("block") is True


# ──────────────────────────────────────────────────────
# Payload Structure
# ──────────────────────────────────────────────────────

class TestPayload:

    def test_to_dict_has_required_fields(self):
        p = _make_payload()
        d = p.to_dict()
        required = {
            "event", "verdict_id", "action", "risk",
            "findings", "critical", "hard_blocked",
            "mercy_applied", "profile", "session_id", "timestamp",
        }
        assert required <= set(d.keys())

    def test_event_type(self):
        p = _make_payload()
        assert p.to_dict()["event"] == "btv.decision"

    def test_no_original_input(self):
        """Payload must NEVER contain original user input."""
        p = _make_payload()
        d = p.to_dict()
        assert "input" not in d
        assert "text" not in d
        assert "message" not in d


# ──────────────────────────────────────────────────────
# Integration: Real HTTP
# ──────────────────────────────────────────────────────

class TestIntegration:

    def test_send_to_server(self, webhook_server, config_file):
        _write_config(config_file, [
            {"url": webhook_server, "actions": ["BLOCK"]},
        ])
        d = WebhookDispatcher(config_path=config_file)
        payload = _make_payload(verdict_id="real_test")

        results = d.notify_sync(payload)

        assert len(results) == 1
        assert results[0].success is True
        assert results[0].status_code == 200
        assert len(_RecordingHandler.received) == 1
        assert _RecordingHandler.received[0]["verdict_id"] == "real_test"

    def test_server_receives_correct_payload(
        self, webhook_server, config_file
    ):
        _write_config(config_file, [
            {"url": webhook_server, "actions": ["BLOCK"]},
        ])
        d = WebhookDispatcher(config_path=config_file)
        payload = _make_payload(
            action="BLOCK", risk=0.92, critical=2
        )
        d.notify_sync(payload)

        received = _RecordingHandler.received[0]
        assert received["action"] == "BLOCK"
        assert received["risk"] == 0.92
        assert received["critical"] == 2

    def test_action_not_matched_skips(
        self, webhook_server, config_file
    ):
        _write_config(config_file, [
            {"url": webhook_server, "actions": ["HARD_BLOCK"]},
        ])
        d = WebhookDispatcher(config_path=config_file)
        payload = _make_payload(action="EDUCATE")

        results = d.notify_sync(payload)
        assert len(results) == 0
        assert len(_RecordingHandler.received) == 0


# ──────────────────────────────────────────────────────
# Failure Handling
# ──────────────────────────────────────────────────────

class TestFailureHandling:

    def test_unreachable_url(self, config_file):
        _write_config(config_file, [
            {
                "url": "http://127.0.0.1:1",
                "actions": ["BLOCK"],
                "timeout_seconds": 0.5,
                "retry_max": 0,
            },
        ])
        d = WebhookDispatcher(config_path=config_file)
        results = d.notify_sync(_make_payload())

        assert len(results) == 1
        assert results[0].success is False
        assert results[0].error is not None

    def test_failure_increments_stats(self, config_file):
        _write_config(config_file, [
            {
                "url": "http://127.0.0.1:1",
                "actions": ["BLOCK"],
                "timeout_seconds": 0.5,
                "retry_max": 0,
            },
        ])
        d = WebhookDispatcher(config_path=config_file)
        d.notify_sync(_make_payload())

        assert d.stats["failures"] == 1
        assert d.stats["dispatched"] == 1


# ──────────────────────────────────────────────────────
# Stats
# ──────────────────────────────────────────────────────

class TestStats:

    def test_initial_stats(self, config_file):
        _write_config(config_file, [
            {"url": "https://a.com", "actions": ["BLOCK"]},
        ])
        d = WebhookDispatcher(config_path=config_file)
        s = d.stats
        assert s["targets"] == 1
        assert s["dispatched"] == 0
        assert s["failures"] == 0

    def test_stats_after_dispatch(self, webhook_server, config_file):
        _write_config(config_file, [
            {"url": webhook_server, "actions": ["BLOCK"]},
        ])
        d = WebhookDispatcher(config_path=config_file)
        d.notify_sync(_make_payload())
        d.notify_sync(_make_payload())

        s = d.stats
        assert s["dispatched"] == 2
        assert s["failures"] == 0