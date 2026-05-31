"""RED test — HIGH-04: _resolve_role must return the caller's real role.

Plan: Passo 2. Today _resolve_role(session_id) ignores input and always
returns "anonymous", so role-based authorization is inert.
"""
import os
import time

import jwt
import pytest

from buildtovalue.api import _decide_helpers

pytestmark = pytest.mark.security


def make_jwt(role: str = "admin") -> str:
    secret = os.environ["BTV_JWT_SECRET"]
    now = int(time.time())
    return jwt.encode(
        {"sub": "tester", "role": role, "tenant_id": "acme",
         "iat": now, "exp": now + 3600},
        secret, algorithm="HS256",
    )


class _FakeRequest:
    """Minimal stand-in carrying an Authorization header."""
    def __init__(self, token: str):
        self.headers = {"Authorization": f"Bearer {token}"}


def test_resolve_role_extracts_role_from_valid_jwt():
    request = _FakeRequest(make_jwt(role="admin"))
    # Post-fix the function inspects request/claims rather than a bare session id.
    assert _decide_helpers._resolve_role(request) == "admin"


def test_resolve_role_defaults_anonymous_without_token():
    assert _decide_helpers._resolve_role(_FakeRequest("")) == "anonymous"
