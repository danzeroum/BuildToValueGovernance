"""Lab v3.0 integration tests — /v1/multi-decide, /v1/fleet, /v1/metrics."""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

import buildtovalue.api.app as app_module
import buildtovalue.api.routes.metrics as metrics_module
from buildtovalue.governance.profile_manager import ProfileManager

HEADERS = {"X-API-Key": "demo-key"}


@pytest.fixture()
def client():
    with TestClient(app_module.app) as c:
        yield c


def test_multi_decide_returns_verdict_per_agent(client):
    body = {"prompt": "Como funciona a fotossíntese?", "agent_ids": ["default", "medical"]}
    r = client.post("/v1/multi-decide", json=body, headers=HEADERS)
    assert r.status_code == 200, r.text
    verdicts = r.json()["verdicts"]
    assert len(verdicts) == 2
    for v in verdicts:
        assert "bias_declaration" in v
        assert v["signature"]  # assinatura presente (não fail-secure)


def test_multi_decide_empty_agents_is_422(client):
    r = client.post("/v1/multi-decide", json={"prompt": "x", "agent_ids": []}, headers=HEADERS)
    assert r.status_code == 422


def test_decide_includes_bias_declaration(client):
    r = client.post("/v1/decide", json={"input_text": "olá", "session_id": "s"}, headers=HEADERS)
    assert r.status_code == 200, r.text
    bias = r.json()["bias_declaration"]
    assert set(bias) >= {"equity_score", "pii_redacted", "long_term_impact", "mercy_applied", "explain"}


def test_fleet_returns_contract_fields(client, tmp_path):
    # Perfil de agente sintético + capabilities (independente do cwd).
    (tmp_path / "agent-x.yaml").write_text(
        "id: agent-x\nname: Agent X\ndescription: test\nparent_id: base\n"
        "domain_config:\n  medical:\n    risk_multiplier: 0.7\n"
    )
    (tmp_path / "capabilities.yaml").write_text(
        "agents:\n  agent-x:\n    capabilities: [llm_inference, triage]\n"
    )
    app_module.app.state.profile_manager = ProfileManager(tmp_path)
    r = client.get("/v1/fleet", headers=HEADERS)
    assert r.status_code == 200, r.text
    agents = r.json()["agents"]
    assert len(agents) == 1
    a = agents[0]
    required = {"id", "name", "owner", "bundle", "model", "risk", "status",
                "blockRate", "decisions24h", "trust", "fria", "friaDate",
                "jurisdictions", "capabilities"}
    assert required <= set(a)
    assert a["id"] == "agent-x"
    assert a["bundle"] == "medical" and a["risk"] == "high"
    assert "triage" in a["capabilities"]


def test_metrics_7d_heatmap_and_block_rate(client, tmp_path, monkeypatch):
    now = int(time.time() * 1000)
    rows = []
    for i in range(40):
        act = "BLOCK" if i % 4 == 0 else ("EDUCATE" if i % 4 == 1 else "ALLOW")
        rows.append({
            "ts": now - i * 3600_000, "session": "s", "profile": "p",
            "policy_action": act, "final_action": act,
            "mercy": act == "EDUCATE", "risk": 0.3,
            "verdict_id": f"v{i}", "latency_ms": 30,
        })
    ledger = tmp_path / "decisions.jsonl"
    ledger.write_text("\n".join(json.dumps(r) for r in rows))
    monkeypatch.setattr(metrics_module, "_reader",
                        metrics_module.LedgerReader(ledger_path=str(ledger)))

    r = client.get("/v1/metrics?range=7d", headers=HEADERS)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["range"] == "7d"
    assert j["total_decisions"] == 40
    assert len(j["heatmap"]) == 7 and all(len(row) == 24 for row in j["heatmap"])
    # 10 BLOCKs (i%4==0), nenhum com mercy → block_rate = 10/40
    assert abs(j["block_rate"] - 0.25) < 1e-6
    assert sum(sum(row) for row in j["heatmap"]) == 40


def test_metrics_unknown_range_falls_back_to_7d(client):
    r = client.get("/v1/metrics?range=90d", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["range"] == "7d"
