"""Integration tests for POST /v1/a2a/scan — C6 collusion wiring (#181).

Regression guard: detect_collusion returns Optional[str], so the endpoint must
report collusion via `collusion is not None`. The previous wiring tested
`isinstance(collusion, dict)`, which is always False, making collusion_detected
hardcoded to False (a silently dead C6 control).
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

import buildtovalue.api.app as app_module
from buildtovalue.governance.cross_agent_correlator import CrossAgentCorrelator

HEADERS = {"X-API-Key": "demo-key"}


@pytest.fixture()
def client():
    with TestClient(app_module.app) as c:
        yield c


@pytest.fixture()
def collusion_correlator(client, tmp_path: Path):
    """Install a correlator with a known collusion pattern on app.state, restore after.

    The /v1/a2a/scan route resolves the correlator via Depends(get_cross_agent),
    which reads request.app.state.cross_agent — so the override must target
    app.state, not a module global.
    """
    policy = {
        "collusion_patterns": [
            {
                "agents": [{"action": "read_secrets"}, {"action": "exfiltrate"}],
                "reason": "Data exfiltration collusion",
            }
        ],
    }
    p = tmp_path / "coordination_rules.yaml"
    p.write_text(yaml.dump(policy))
    original = app_module.app.state.cross_agent
    app_module.app.state.cross_agent = CrossAgentCorrelator(policy_path=p)
    try:
        yield
    finally:
        app_module.app.state.cross_agent = original


def test_a2a_scan_reports_collusion(client, collusion_correlator) -> None:
    # Both keywords live in the first 64 bytes (the snippet both agents receive).
    body = {"src": "agent-a", "dst": "agent-b", "payload": "read_secrets then exfiltrate"}
    r = client.post("/v1/a2a/scan", json=body, headers=HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert data["collusion_detected"] is True
    assert data["collusion_reason"] == "Data exfiltration collusion"


def test_a2a_scan_clean_payload_no_collusion(client, collusion_correlator) -> None:
    body = {"src": "agent-a", "dst": "agent-b", "payload": "fetch the public docs and summarise"}
    r = client.post("/v1/a2a/scan", json=body, headers=HEADERS)
    assert r.status_code == 200
    data = r.json()
    assert data["collusion_detected"] is False
    assert data["collusion_reason"] is None
