"""Shared fixtures for the security/V&V RED suite (Passo 0).

These tests encode the BDD scenarios from the approved development plan
(`ETAPA 3 §3.3`). They assert the **post-fix** behaviour and are therefore
expected to FAIL until the corresponding remediation step lands (RED phase of
TDD). Each test is tagged with the reason it should currently fail.
"""
import os
import time

import jwt
import pytest

# The admin password is mandatory post-fix (CRITICO-02). Provide a strong
# default for the suite so the app can seed/boot; individual tests override it.
os.environ.setdefault("BTV_ADMIN_PASSWORD", "Sup3r-Str0ng-Admin-2026")
os.environ.setdefault("BTV_ENV", "development")
os.environ.setdefault("BTV_JWT_SECRET", "ci-test-jwt-secret-32bytes-padding!!")


def make_jwt(role: str = "admin", username: str = "tester", expires_in: int = 3600) -> str:
    """Sign a JWT with the same secret the app uses (HS256)."""
    secret = os.environ["BTV_JWT_SECRET"]
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "tenant_id": "acme",
        "iat": now,
        "exp": now + expires_in,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


@pytest.fixture
def bearer():
    """Return a callable producing an Authorization header for a given role."""
    def _factory(role: str = "admin") -> dict:
        return {"Authorization": f"Bearer {make_jwt(role=role)}"}
    return _factory


@pytest.fixture
def client_with_api_key(tmp_path):
    """TestClient with API-key auth ENABLED, isolated DBs in tmp_path."""
    os.environ["BTV_API_KEYS"] = "btv_test_key_1,btv_test_key_2"
    os.environ["BTV_ENV"] = "development"
    os.environ["BTV_APPEALS_DB"] = str(tmp_path / "appeals.db")
    os.environ["BTV_USERS_DB"] = str(tmp_path / "users.db")

    import buildtovalue.api.app as app_module
    app_module._contestability_loop = None

    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as c:
        yield c

    for k in ("BTV_API_KEYS", "BTV_APPEALS_DB", "BTV_USERS_DB"):
        os.environ.pop(k, None)
    app_module._contestability_loop = None
