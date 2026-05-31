"""RED tests — CRITICO-03: governance endpoints must require authentication.

Plan: Passo 3. With BTV_API_KEYS configured, unauthenticated writes/reads to
appeals/ledger/webhooks must be rejected (401). They currently succeed.
"""
import pytest

pytestmark = pytest.mark.security


def test_submit_appeal_without_credentials_is_rejected(client_with_api_key):
    res = client_with_api_key.post("/v1/appeals", json={
        "audit_trail_id": 12345,
        "user_id": "user-001",
        "reason": "no credentials supplied",
    })
    assert res.status_code == 401, "POST /v1/appeals must require auth"


def test_submit_appeal_with_jwt_is_accepted(client_with_api_key, bearer):
    res = client_with_api_key.post(
        "/v1/appeals",
        json={
            "audit_trail_id": 222,
            "user_id": "user-001",
            "reason": "A valid appeal reason that is at least twenty chars long.",
        },
        headers=bearer("admin"),
    )
    assert res.status_code == 201


def test_ledger_query_without_credentials_is_rejected(client_with_api_key):
    res = client_with_api_key.get("/v1/ledger/query")
    assert res.status_code == 401, "GET /v1/ledger/query must require auth"


def test_webhook_reload_without_credentials_is_rejected(client_with_api_key):
    res = client_with_api_key.post("/v1/webhooks/reload")
    assert res.status_code == 401, "POST /v1/webhooks/reload must require auth"
