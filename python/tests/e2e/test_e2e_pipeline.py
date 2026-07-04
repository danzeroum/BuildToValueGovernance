"""
E2E Pipeline tests: decide → compliance → risk classification → ledger.
Validates Phase B runtime compliance integration.
"""

import os
import time
import jwt as _jwt
import pytest
from fastapi.testclient import TestClient
from buildtovalue.api.app import app


@pytest.fixture(scope="module")
def client():
    os.environ.pop("BTV_API_KEYS", None)
    os.environ["BTV_ENV"] = "development"
    # CRITICO-03: POST /v1/appeals exige JWT — assina com o secret de teste
    _secret = os.environ.get("BTV_JWT_SECRET", "ci-test-jwt-secret-32bytes-padding!!")
    _now = int(time.time())
    _token = _jwt.encode(
        {"sub": "e2e-tester", "role": "admin", "iat": _now, "exp": _now + 3600},
        _secret, algorithm="HS256",
    )
    with TestClient(app, headers={"Authorization": f"Bearer {_token}"}) as c:
        yield c


# ═══════════════════════════════════════════════════════════════
# DECIDE — COMPLIANCE FIELDS PRESENT
# ═══════════════════════════════════════════════════════════════

class TestDecideCompliance:

    def test_decide_returns_risk_classification(self, client):
        resp = client.post("/v1/decide", json={
            "composite_risk": 0.3,
            "finding_count": 1,
            "critical_count": 0,
            "action": "LOG",
            "matched_policies": ["EMAIL"],
            "entropy": 3.5,
            "total_chars": 50,
            "blake3_hash": "abc123",
            "hard_blocked": False,
            "max_finding_confidence": 0.8,
            "input_text": "test input",
            "profile": "healthcare_assistant",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "risk_classification" in data
        assert "compliance_violations" in data
        assert "compliance_rate" in data

    def test_hard_block_no_compliance(self, client):
        resp = client.post("/v1/decide", json={
            "composite_risk": 0.95,
            "finding_count": 3,
            "critical_count": 1,
            "action": "BLOCK",
            "matched_policies": ["SQL_INJECTION"],
            "entropy": 5.0,
            "total_chars": 30,
            "blake3_hash": "def456",
            "hard_blocked": True,
            "max_finding_confidence": 0.99,
            "input_text": "DROP TABLE users",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "BLOCK"

    def test_verdict_always_signed(self, client):
        resp = client.post("/v1/decide", json={
            "composite_risk": 0.1,
            "finding_count": 0,
            "critical_count": 0,
            "action": "ALLOW",
            "matched_policies": [],
            "entropy": 2.0,
            "total_chars": 20,
            "blake3_hash": "ghi789",
            "hard_blocked": False,
            "max_finding_confidence": 0.0,
            "input_text": "hello",
        })
        data = resp.json()
        assert data["signature"] != ""
        assert data["contestable"] is True
        assert data["appeal_deadline_hours"] == 24


# ═══════════════════════════════════════════════════════════════
# RISK CLASSIFICATION ENDPOINT
# ═══════════════════════════════════════════════════════════════

class TestClassifyRisk:

    def test_healthcare_high_risk(self, client):
        resp = client.post("/v1/compliance/classify-risk", json={
            "agent_id": "test-agent",
            "sector": "healthcare",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "HIGH_RISK"
        assert data["annex_iii"] is True
        assert len(data["obligations"]) >= 10

    def test_general_minimal_risk(self, client):
        resp = client.post("/v1/compliance/classify-risk", json={
            "agent_id": "test-agent",
            "sector": "general",
        })
        data = resp.json()
        assert data["risk_level"] == "MINIMAL_RISK"

    def test_prohibited_capability(self, client):
        resp = client.post("/v1/compliance/classify-risk", json={
            "agent_id": "bad-agent",
            "sector": "marketing",
            "capabilities": ["subliminal_manipulation"],
        })
        data = resp.json()
        assert data["risk_level"] == "PROHIBITED"


# ═══════════════════════════════════════════════════════════════
# FRIA ENDPOINT
# ═══════════════════════════════════════════════════════════════

class TestFRIA:

    def test_fria_healthcare(self, client):
        resp = client.post("/v1/compliance/fria/generate", json={
            "agent_id": "med-bot",
            "sector": "healthcare",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_sections"] == 10
        assert data["risk_level"] == "HIGH_RISK"
        assert data["auto_filled"] + data["manual_pending"] == 10

    def test_fria_minimal(self, client):
        resp = client.post("/v1/compliance/fria/generate", json={
            "agent_id": "chat-bot",
            "sector": "general",
            "capabilities": ["chatbot"],
        })
        data = resp.json()
        assert data["risk_level"] == "LIMITED_RISK"

    def test_fria_prohibited(self, client):
        resp = client.post("/v1/compliance/fria/generate", json={
            "agent_id": "evil-bot",
            "sector": "general",
            "capabilities": ["social_scoring_public"],
        })
        data = resp.json()
        assert data["risk_level"] == "PROHIBITED"


# ═══════════════════════════════════════════════════════════════
# COMPLIANCE FRAMEWORKS
# ═══════════════════════════════════════════════════════════════

class TestComplianceFrameworks:

    def test_list_frameworks(self, client):
        resp = client.get("/v1/compliance/frameworks")
        assert resp.status_code == 200
        data = resp.json()
        ids = [f["id"] for f in data["frameworks"]]
        assert "LGPD" in ids
        assert "EU_AI_ACT" in ids

    def test_lgpd_report(self, client):
        resp = client.get("/v1/compliance/report/LGPD")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "LGPD"
        assert data["total_requirements"] > 0

    def test_eu_ai_act_report(self, client):
        resp = client.get("/v1/compliance/report/EU_AI_ACT")
        data = resp.json()
        assert data["framework"] == "EU_AI_ACT"


# ═══════════════════════════════════════════════════════════════
# TRUST + APPEALS (end-to-end)
# ═══════════════════════════════════════════════════════════════

class TestTrustAndAppeals:

    def test_trust_builds_over_decisions(self, client):
        sid = f"e2e-trust-{int(time.time())}"
        for _ in range(5):
            client.post("/v1/decide", json={
                "composite_risk": 0.05,
                "finding_count": 0,
                "critical_count": 0,
                "action": "ALLOW",
                "matched_policies": [],
                "entropy": 2.0,
                "total_chars": 10,
                "blake3_hash": "trust",
                "hard_blocked": False,
                "max_finding_confidence": 0.0,
                "input_text": "safe input",
                "session_id": sid,
            })
        resp = client.get(f"/v1/trust/{sid}")
        assert resp.status_code == 200
        assert resp.json()["trust_score"] > 0.5

    def test_appeal_submit_and_retrieve(self, client):
        resp = client.post("/v1/appeals", json={
            "audit_trail_id": 9999,
            "user_id": "e2e-tester",
            "reason": "E2E test appeal - verifying full pipeline contestability flow",
        })
        assert resp.status_code == 201
        appeal_id = resp.json()["appeal_id"]

        resp2 = client.get(f"/v1/appeals/{appeal_id}")
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "pending"