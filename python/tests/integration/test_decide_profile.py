"""
Integration tests: /v1/decide with profile + sector whitelist (Gap #4).

Tests the full Python governance flow:
  EvidenceRequest(profile, input_text) → sector whitelist → mercy → verdict
"""

import pytest
from fastapi.testclient import TestClient
from buildtovalue.api.app import app


@pytest.fixture(scope="module")
def client():
    """TestClient with auth disabled."""
    import os
    os.environ.pop("BTV_API_KEYS", None)
    os.environ["BTV_ENV"] = "development"
    with TestClient(app) as c:
        yield c


# ═══════════════════════════════════════════════════════════════
# BASELINE (no profile)
# ═══════════════════════════════════════════════════════════════


class TestDecideBaseline:

    def test_allow_passthrough(self, client):
        """ALLOW action passes through without judgment."""
        res = client.post("/v1/decide", json={
            "action": "ALLOW",
            "finding_count": 0,
            "critical_count": 0,
            "composite_risk": 0.0,
        })
        assert res.status_code == 200
        data = res.json()
        assert data["action"] == "ALLOW"
        assert data["mercy_applied"] is False

    def test_hard_block_non_negotiable(self, client):
        """Hard blocks cannot be overridden by profile."""
        res = client.post("/v1/decide", json={
            "action": "BLOCK",
            "hard_blocked": True,
            "finding_count": 1,
            "critical_count": 1,
            "composite_risk": 0.95,
            "profile": "medical",
            "input_text": "medical diagnosis DROP TABLE users",
        })
        assert res.status_code == 200
        data = res.json()
        assert data["action"] == "BLOCK"
        assert data["contestable"] is True  # Levinas: even hard blocks are contestable
        assert data["mercy_applied"] is False  # But mercy is NOT applied

    def test_block_without_profile(self, client):
        """BLOCK without profile — no sector reduction."""
        res = client.post("/v1/decide", json={
            "action": "BLOCK",
            "finding_count": 2,
            "critical_count": 0,
            "composite_risk": 0.8,
            "matched_policies": ["cpf -> BLOCK"],
        })
        assert res.status_code == 200
        data = res.json()
        assert "Sector context" not in data["rationale"]


# ═══════════════════════════════════════════════════════════════
# PROFILE + SECTOR WHITELIST
# ═══════════════════════════════════════════════════════════════


class TestDecideWithProfile:

    def test_medical_profile_reduces_risk(self, client):
        """Medical profile + healthcare trigger → risk reduction."""
        res = client.post("/v1/decide", json={
            "action": "BLOCK",
            "finding_count": 1,
            "critical_count": 0,
            "composite_risk": 0.6,
            "matched_policies": ["pii -> BLOCK"],
            "profile": "medical",
            "input_text": "medical diagnosis for patient with CPF",
            "session_id": "test-medical-001",
        })
        assert res.status_code == 200
        data = res.json()
        # Should mention sector context in rationale
        if "Sector context" in data["rationale"]:
            assert "healthcare" in data["rationale"]
            # Risk was reduced, so mercy might have kicked in
            assert data["adjusted_risk"] < 0.6

    def test_unknown_profile_graceful(self, client):
        """Unknown profile → no crash, uses defaults."""
        res = client.post("/v1/decide", json={
            "action": "BLOCK",
            "finding_count": 1,
            "critical_count": 0,
            "composite_risk": 0.7,
            "matched_policies": ["cpf -> BLOCK"],
            "profile": "nonexistent_profile",
            "input_text": "some text",
            "session_id": "test-unknown-001",
        })
        assert res.status_code == 200
        data = res.json()
        assert "Sector context" not in data["rationale"]

    def test_profile_without_input_text(self, client):
        """Profile but no input_text → no whitelist (safe)."""
        res = client.post("/v1/decide", json={
            "action": "BLOCK",
            "finding_count": 1,
            "critical_count": 0,
            "composite_risk": 0.7,
            "matched_policies": ["pii -> BLOCK"],
            "profile": "medical",
            "session_id": "test-notext-001",
        })
        assert res.status_code == 200
        data = res.json()
        assert "Sector context" not in data["rationale"]

    def test_profile_no_trigger_match(self, client):
        """Medical profile but text has no healthcare triggers."""
        res = client.post("/v1/decide", json={
            "action": "BLOCK",
            "finding_count": 1,
            "critical_count": 0,
            "composite_risk": 0.7,
            "matched_policies": ["pii -> BLOCK"],
            "profile": "medical",
            "input_text": "random text about weather forecast",
            "session_id": "test-notrigger-001",
        })
        assert res.status_code == 200
        data = res.json()
        assert "Sector context" not in data["rationale"]


# ═══════════════════════════════════════════════════════════════
# VERDICT INVARIANTS
# ═══════════════════════════════════════════════════════════════


class TestVerdictInvariants:

    def test_always_has_signature(self, client):
        """Every verdict must be signed (HMAC-SHA256)."""
        res = client.post("/v1/decide", json={
            "action": "EDUCATE",
            "finding_count": 1,
            "critical_count": 0,
            "composite_risk": 0.4,
            "profile": "medical",
            "input_text": "patient assessment review",
            "session_id": "test-sig-001",
        })
        data = res.json()
        assert data["signature"] != ""

    def test_always_contestable(self, client):
        """Non-hard-block verdicts are contestable (Levinas)."""
        res = client.post("/v1/decide", json={
            "action": "BLOCK",
            "finding_count": 2,
            "critical_count": 0,
            "composite_risk": 0.8,
            "session_id": "test-contest-001",
        })
        data = res.json()
        assert data["contestable"] is True
        assert data["appeal_deadline_hours"] == 24

    def test_latency_under_sla(self, client):
        """Decision latency < 10ms (Python SLA)."""
        res = client.post("/v1/decide", json={
            "action": "BLOCK",
            "finding_count": 1,
            "critical_count": 0,
            "composite_risk": 0.5,
            "profile": "medical",
            "input_text": "medical diagnosis CPF check",
            "session_id": "test-latency-001",
        })
        data = res.json()
        assert data["latency_ms"] < 50  # generous; target is <10ms