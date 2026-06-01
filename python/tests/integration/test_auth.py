"""
Tests: API Key Authentication (Gap #6).
"""

import os
import pytest
from fastapi.testclient import TestClient
from buildtovalue.api.app import app


@pytest.fixture(scope="module")
def client_no_auth():
    """Client with auth disabled (no BTV_API_KEYS)."""
    os.environ.pop("BTV_API_KEYS", None)
    os.environ["BTV_ENV"] = "development"
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def client_with_auth():
    """Client with auth enabled."""
    os.environ["BTV_API_KEYS"] = "btv_test_key_1,btv_test_key_2"
    os.environ["BTV_ENV"] = "development"
    with TestClient(app) as c:
        yield c


class TestAuthDisabled:

    def test_decide_works_without_key(self, client_no_auth):
        """Dev mode: requests work without API key."""
        res = client_no_auth.post("/v1/decide", json={
            "action": "ALLOW",
        })
        assert res.status_code == 200


class TestAuthEnabled:

    def test_decide_with_valid_key(self, client_with_auth):
        """Valid key → 200."""
        res = client_with_auth.post(
            "/v1/decide",
            json={"action": "ALLOW"},
            headers={"X-API-Key": "btv_test_key_1"},
        )
        assert res.status_code == 200

    def test_decide_with_invalid_key(self, client_with_auth):
        """Invalid key → 401 with RFC 7807 Problem Details (Passo 11)."""
        res = client_with_auth.post(
            "/v1/decide",
            json={"action": "ALLOW"},
            headers={"X-API-Key": "wrong_key"},
        )
        assert res.status_code == 401
        body = res.json()
        assert body["status"] == 401
        assert body["title"] == "Unauthorized"
        assert "Invalid or missing API key" in body["detail"]

    def test_decide_without_key(self, client_with_auth):
        """No key → 401."""
        res = client_with_auth.post(
            "/v1/decide",
            json={"action": "ALLOW"},
        )
        assert res.status_code == 401

    def test_health_always_public(self, client_with_auth):
        """Health endpoint never requires auth."""
        res = client_with_auth.get("/health")
        assert res.status_code == 200