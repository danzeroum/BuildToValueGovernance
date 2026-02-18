"""
Tests for Appeals API endpoints (ADR-023).

Coverage: 10 scenarios (5 endpoints × happy + error paths).
"""

import pytest
from fastapi.testclient import TestClient
from buildtovalue.api.app import app


@pytest.fixture
def client():
    """TestClient with fresh ContestabilityLoop."""
    from buildtovalue.api import app as app_module
    from buildtovalue.governance.contestability_loop import ContestabilityLoop

    app_module._contestability_loop = ContestabilityLoop(sla_hours=24)
    return TestClient(app)


# ═══════════════════════════════════════════════════════════════
# POST /v1/appeals
# ═══════════════════════════════════════════════════════════════

class TestSubmitAppeal:

    def test_submit_success(self, client):
        """201: Valid appeal submitted."""
        res = client.post("/v1/appeals", json={
            "audit_trail_id": 12345,
            "user_id": "user-001",
            "reason": "This was a test CPF from ABNT standards, not real data.",
        })
        assert res.status_code == 201
        data = res.json()
        assert data["appeal_id"].startswith("APL-12345-")
        assert data["status"] == "pending"
        assert data["sla_deadline"] > data["timestamp"]
        assert data["is_overdue"] is False

    def test_submit_with_evidence(self, client):
        """201: Appeal with evidence URL."""
        res = client.post("/v1/appeals", json={
            "audit_trail_id": 12345,
            "user_id": "user-001",
            "reason": "Test CPF from official documentation.",
            "evidence": "https://example.com/proof.pdf",
        })
        assert res.status_code == 201
        assert res.json()["evidence_provided"] == "https://example.com/proof.pdf"

    def test_submit_reason_too_short(self, client):
        """422: Reason under 20 chars (Pydantic validation)."""
        res = client.post("/v1/appeals", json={
            "audit_trail_id": 12345,
            "user_id": "user-001",
            "reason": "Too short",
        })
        assert res.status_code == 422
# ═══════════════════════════════════════════════════════════════
# GET /v1/appeals/{appeal_id}
# ═══════════════════════════════════════════════════════════════

class TestGetAppeal:

    def test_get_existing(self, client):
        """200: Found."""
        # Create first
        create = client.post("/v1/appeals", json={
            "audit_trail_id": 1,
            "user_id": "u1",
            "reason": "Reason with enough characters here.",
        })
        appeal_id = create.json()["appeal_id"]

        res = client.get(f"/v1/appeals/{appeal_id}")
        assert res.status_code == 200
        assert res.json()["appeal_id"] == appeal_id

    def test_get_not_found(self, client):
        """404: Not found."""
        res = client.get("/v1/appeals/APL-99999-000000")
        assert res.status_code == 404


# ═══════════════════════════════════════════════════════════════
# POST /v1/appeals/{appeal_id}/resolve
# ═══════════════════════════════════════════════════════════════

class TestResolveAppeal:

    def _create_appeal(self, client) -> str:
        res = client.post("/v1/appeals", json={
            "audit_trail_id": 42,
            "user_id": "u1",
            "reason": "Test CPF from ABNT documentation.",
        })
        return res.json()["appeal_id"]

    def test_resolve_accept(self, client):
        """200: Accept appeal."""
        aid = self._create_appeal(client)
        res = client.post(f"/v1/appeals/{aid}/resolve", json={
            "accepted": True,
            "reviewer_notes": "Confirmed: test data, false positive.",
            "reviewer_id": "reviewer@btv.com",
        })
        assert res.status_code == 200
        assert res.json()["status"] == "accepted"
        assert res.json()["reviewer_notes"] is not None

    def test_resolve_reject(self, client):
        """200: Reject appeal."""
        aid = self._create_appeal(client)
        res = client.post(f"/v1/appeals/{aid}/resolve", json={
            "accepted": False,
            "reviewer_notes": "Real PII confirmed by cross-reference.",
            "reviewer_id": "reviewer@btv.com",
        })
        assert res.status_code == 200
        assert res.json()["status"] == "rejected"

    def test_resolve_already_resolved(self, client):
        """409: Cannot resolve twice."""
        aid = self._create_appeal(client)
        # Resolve first time
        client.post(f"/v1/appeals/{aid}/resolve", json={
            "accepted": True,
            "reviewer_notes": "First resolution is final.",
            "reviewer_id": "reviewer@btv.com",
        })
        # Try again
        res = client.post(f"/v1/appeals/{aid}/resolve", json={
            "accepted": False,
            "reviewer_notes": "Attempting second resolution.",
            "reviewer_id": "reviewer@btv.com",
        })
        assert res.status_code == 409

    def test_resolve_not_found(self, client):
        """404: Appeal doesn't exist."""
        res = client.post("/v1/appeals/APL-99999-000/resolve", json={
            "accepted": True,
            "reviewer_notes": "This appeal does not exist.",
            "reviewer_id": "reviewer@btv.com",
        })
        assert res.status_code == 404


# ═══════════════════════════════════════════════════════════════
# GET /v1/appeals (list + filter)
# ═══════════════════════════════════════════════════════════════

class TestListAppeals:

    def test_list_empty(self, client):
        """200: No appeals."""
        res = client.get("/v1/appeals")
        assert res.status_code == 200
        assert res.json()["total"] == 0

    def test_list_filter_by_status(self, client):
        """200: Filter by status=pending."""
        # Create 2 appeals
        client.post("/v1/appeals", json={
            "audit_trail_id": 1,
            "user_id": "u1",
            "reason": "Reason one with enough chars.",
        })
        r2 = client.post("/v1/appeals", json={
            "audit_trail_id": 2,
            "user_id": "u2",
            "reason": "Reason two with enough chars.",
        })
        # Resolve one
        aid2 = r2.json()["appeal_id"]
        client.post(f"/v1/appeals/{aid2}/resolve", json={
            "accepted": True,
            "reviewer_notes": "Accepted after review.",
            "reviewer_id": "rev",
        })

        # Filter pending only
        res = client.get("/v1/appeals?status=pending")
        assert res.status_code == 200
        assert res.json()["total"] == 1
        assert res.json()["appeals"][0]["status"] == "pending"

    def test_list_filter_by_user(self, client):
        """200: Filter by user_id."""
        client.post("/v1/appeals", json={
            "audit_trail_id": 1, "user_id": "alice",
            "reason": "Alice's reason is long enough.",
        })
        client.post("/v1/appeals", json={
            "audit_trail_id": 2, "user_id": "bob",
            "reason": "Bob's reason is also long enough.",
        })

        res = client.get("/v1/appeals?user_id=alice")
        assert res.json()["total"] == 1
        assert res.json()["appeals"][0]["user_id"] == "alice"


# ═══════════════════════════════════════════════════════════════
# GET /v1/appeals/metrics
# ═══════════════════════════════════════════════════════════════

class TestAppealMetrics:

    def test_metrics_initial(self, client):
        """200: All fields present, zeroed."""
        res = client.get("/v1/appeals/metrics")
        assert res.status_code == 200
        data = res.json()
        assert data["appeals_submitted"] == 0
        assert data["pending_appeals"] == 0
        assert data["sla_compliance_rate"] == 1.0

    def test_metrics_after_flow(self, client):
        """200: Metrics reflect submit+resolve."""
        # Submit
        r = client.post("/v1/appeals", json={
            "audit_trail_id": 1, "user_id": "u1",
            "reason": "Reason with enough characters.",
        })
        aid = r.json()["appeal_id"]

        # Resolve
        client.post(f"/v1/appeals/{aid}/resolve", json={
            "accepted": True,
            "reviewer_notes": "Confirmed false positive.",
            "reviewer_id": "rev",
        })

        res = client.get("/v1/appeals/metrics")
        data = res.json()
        assert data["appeals_submitted"] == 1
        assert data["appeals_accepted"] == 1
        assert data["appeal_success_rate"] == 1.0
        assert data["pending_appeals"] == 0