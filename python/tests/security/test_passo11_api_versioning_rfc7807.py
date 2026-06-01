"""RED tests — Passo 11: API prefix normalization + RFC 7807 Problem Details.

§1.4 item 7: all active routes use /v1/...; the legacy /api/v1/* path must
301-redirect to /v1/* (no double-prefix). All 4xx/5xx responses must carry
Content-Type: application/problem+json and an RFC 7807-compliant body with
the fields: type, title, status, detail.
"""
import os

import pytest
from fastapi.testclient import TestClient

from buildtovalue.api.app import app

pytestmark = pytest.mark.security


@pytest.fixture(scope="module")
def client_no_follow():
    """TestClient that does NOT follow redirects — needed to assert 301 Location."""
    with TestClient(app, follow_redirects=False) as c:
        yield c


@pytest.fixture(scope="module")
def client_auth():
    """TestClient with API-key auth enabled so unauthenticated requests → 401."""
    os.environ["BTV_API_KEYS"] = "btv_passo11_key"
    from buildtovalue.api.auth import init_auth

    init_auth()
    with TestClient(app, follow_redirects=False) as c:
        yield c
    os.environ.pop("BTV_API_KEYS", None)


class TestLegacyApiV1Redirect:
    """/api/v1/* must 301-redirect to /v1/* (§1.4 item 7)."""

    def test_api_v1_trust_returns_301(self, client_no_follow):
        res = client_no_follow.get("/api/v1/trust/sess-001")
        assert res.status_code == 301, (
            f"GET /api/v1/trust/... must return 301 (got {res.status_code})"
        )

    def test_api_v1_redirect_location_points_to_canonical(self, client_no_follow):
        res = client_no_follow.get("/api/v1/trust/sess-001")
        location = res.headers.get("location", "")
        assert "/v1/trust/sess-001" in location, (
            f"301 Location must include /v1/trust/sess-001 (got {location!r})"
        )

    def test_api_v1_appeals_returns_301(self, client_no_follow):
        res = client_no_follow.get("/api/v1/appeals")
        assert res.status_code == 301, (
            f"GET /api/v1/appeals must return 301 (got {res.status_code})"
        )

    def test_api_v1_preserves_query_string_in_redirect(self, client_no_follow):
        res = client_no_follow.get("/api/v1/appeals?page=2&limit=10")
        location = res.headers.get("location", "")
        assert "page=2" in location, (
            "301 Location must preserve query string (page=2 missing)"
        )
        assert "limit=10" in location, (
            "301 Location must preserve query string (limit=10 missing)"
        )


class TestRfc7807ProblemDetails:
    """All 4xx/5xx errors → Content-Type: application/problem+json + RFC 7807 body."""

    def test_401_content_type_is_problem_json(self, client_auth):
        res = client_auth.get("/v1/trust/sess-x")
        assert res.status_code == 401
        ct = res.headers.get("content-type", "")
        assert "application/problem+json" in ct, (
            f"RFC 7807: 401 must return application/problem+json (got {ct!r})"
        )

    def test_401_body_has_all_rfc7807_fields(self, client_auth):
        res = client_auth.get("/v1/trust/sess-x")
        body = res.json()
        for field in ("type", "title", "status", "detail"):
            assert field in body, f"RFC 7807: missing field {field!r} in 401 body"
        assert body["status"] == 401
        assert body["title"] == "Unauthorized"

    def test_404_content_type_is_problem_json(self, client_no_follow):
        res = client_no_follow.get("/v1/route-does-not-exist-passo11")
        assert res.status_code == 404
        ct = res.headers.get("content-type", "")
        assert "application/problem+json" in ct, (
            f"RFC 7807: 404 must return application/problem+json (got {ct!r})"
        )

    def test_404_body_has_all_rfc7807_fields(self, client_no_follow):
        res = client_no_follow.get("/v1/route-does-not-exist-passo11")
        body = res.json()
        for field in ("type", "title", "status", "detail"):
            assert field in body, f"RFC 7807: missing field {field!r} in 404 body"
        assert body["status"] == 404
        assert body["title"] == "Not Found"
