"""RED tests — CRITICO-04: security headers must be applied on every response.

Plan: Passo 4. The SecurityHeadersMiddleware exists but is bound to an isolated
FastAPI() and never registered on the main app, so these headers are absent.
"""
import pytest
from fastapi.testclient import TestClient

from buildtovalue.api.app import app

pytestmark = pytest.mark.security


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


REQUIRED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "strict-transport-security": None,   # presence only
    "content-security-policy": None,     # presence only
}


@pytest.mark.parametrize("header", sorted(REQUIRED_HEADERS))
def test_security_header_present_on_health(client, header):
    res = client.get("/health")
    assert header in {k.lower() for k in res.headers}, (
        f"missing security header {header!r}")
