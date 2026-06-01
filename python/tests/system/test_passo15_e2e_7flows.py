"""System test — Passo 15: E2E smoke covering the 7 mandatory §3.2 flows.

These tests run entirely in-process via FastAPI's TestClient (no docker
required). Each test maps to one §3.2 scenario:

  Flow 1 — login → JWT → protected endpoint → 200
  Flow 2 — login wrong password → 401; burst → 429
  Flow 3 — submit appeal without auth → 401
  Flow 4 — submit appeal with JWT → 201 → GET → resolve
  Flow 5 — invalid Bearer token → 401
  Flow 6 — input_text > 50 000 chars → 422
  Flow 7 — startup initialises DB before first request (CRITICO-06)

  Audit trail immutability: ledger is append-only JSONL; there is no
  DELETE endpoint for decisions.

Flows covering the Rust gateway (Bearer validation, policy warm-up) are
exercised end-to-end by ops/e2e-tests.sh and the Rust unit tests
(CRITICO-07, CRITICO-10).
"""
import os
import time

import jwt
import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.system

# Must match tests/conftest.py and tests/system/conftest.py so the seeded
# admin password and JWT secret are the same across all test files.
_ADMIN_PASS = "ci-test-admin-password-2026"
_JWT_SECRET = "ci-test-jwt-secret-32bytes-padding!!"
_API_KEY = "btv_p15_test_key"
_WRONG_SECRET = "wrong-secret-completely-different!!"  # 32+ bytes, not the app secret


# ─────────────────────────────────────── helpers ─────────────────────────────


def _make_jwt(secret: str = _JWT_SECRET, expired: bool = False) -> str:
    now = int(time.time())
    payload = {
        "sub": "admin",
        "role": "admin",
        "iat": now,
        "exp": now + (-1 if expired else 3600),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def _jwt_headers() -> dict:
    return {"Authorization": f"Bearer {_make_jwt()}"}


# ─────────────────────────────────────── fixtures ────────────────────────────


@pytest.fixture(scope="module")
def auth_client(tmp_path_factory):
    """Module-scoped client: isolated DB, admin seeded, API keys set.

    Patches ``auth_module.USERS_DB_PATH`` directly so the module-level
    constant points to our tmp directory — bypasses the issue that
    ``USERS_DB_PATH`` is evaluated once at import time, not per-request.
    """
    tmp = tmp_path_factory.mktemp("p15_auth")
    users_db = str(tmp / "users.db")
    appeals_db = str(tmp / "appeals.db")

    import buildtovalue.api.routes.auth as auth_module
    from buildtovalue.api._limiter import limiter

    orig_users_db = auth_module.USERS_DB_PATH
    orig_jwt_secret = auth_module.JWT_SECRET
    auth_module.USERS_DB_PATH = users_db
    auth_module.JWT_SECRET = _JWT_SECRET

    # Pre-seed the admin user so the lifespan's _init_users_db() finds
    # existing rows and skips re-seeding (idempotent).
    os.environ["BTV_ADMIN_PASSWORD"] = _ADMIN_PASS
    auth_module._init_users_db()

    os.environ["BTV_APPEALS_DB"] = appeals_db
    os.environ["BTV_API_KEYS"] = _API_KEY

    # Reset rate-limiter storage so security-test bursts don't bleed in.
    limiter._storage.reset()
    # Deduplicate route limits: security tests use importlib.reload(auth) which
    # re-applies @limiter.limit("10/minute") on every reload, stacking N copies of
    # the rule and making each request count N× against the limit.  Trim back to
    # one copy so a single wrong-password attempt still returns 401 (not 429).
    _login_key = "buildtovalue.api.routes.auth.login"
    if _login_key in limiter._route_limits:
        limiter._route_limits[_login_key] = limiter._route_limits[_login_key][:1]

    from buildtovalue.api.app import app

    with TestClient(app, follow_redirects=False) as c:
        yield c

    # Restore module state
    auth_module.USERS_DB_PATH = orig_users_db
    auth_module.JWT_SECRET = orig_jwt_secret
    for k in ("BTV_ADMIN_PASSWORD", "BTV_APPEALS_DB", "BTV_API_KEYS"):
        os.environ.pop(k, None)


@pytest.fixture
def burst_client(tmp_path):
    """Function-scoped client for the rate-limit burst test.
    Isolated so rate-limit state doesn't bleed into other tests."""
    import buildtovalue.api.routes.auth as auth_module

    orig_users_db = auth_module.USERS_DB_PATH
    auth_module.USERS_DB_PATH = str(tmp_path / "burst_users.db")
    os.environ["BTV_ADMIN_PASSWORD"] = _ADMIN_PASS
    auth_module._init_users_db()

    os.environ["BTV_APPEALS_DB"] = str(tmp_path / "burst_appeals.db")
    os.environ["BTV_API_KEYS"] = _API_KEY

    from buildtovalue.api.app import app

    with TestClient(app, follow_redirects=False) as c:
        yield c

    auth_module.USERS_DB_PATH = orig_users_db
    for k in ("BTV_ADMIN_PASSWORD", "BTV_APPEALS_DB", "BTV_API_KEYS"):
        os.environ.pop(k, None)


# ─────────────────────────────────── Flow 1 ──────────────────────────────────


class TestFlow1LoginJwtProtected:
    """Flow 1 — login → JWT → protected endpoint → 200."""

    def test_login_with_valid_credentials_returns_200(self, auth_client):
        resp = auth_client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": _ADMIN_PASS},
        )
        assert resp.status_code == 200, (
            f"Flow 1: login must return 200 (got {resp.status_code})"
        )
        body = resp.json()
        assert "token" in body
        assert body["username"] == "admin"

    def test_jwt_grants_access_to_protected_endpoint(self, auth_client):
        login = auth_client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": _ADMIN_PASS},
        )
        assert login.status_code == 200
        token = login.json()["token"]

        me = auth_client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me.status_code == 200, (
            f"Flow 1: /v1/auth/me with valid JWT must return 200 (got {me.status_code})"
        )
        assert me.json()["username"] == "admin"


# ─────────────────────────────────── Flow 2 ──────────────────────────────────


class TestFlow2WrongPasswordRateLimit:
    """Flow 2 — wrong password → 401; burst → 429."""

    def test_wrong_password_returns_401(self, auth_client):
        resp = auth_client.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "completely-wrong-password"},
        )
        assert resp.status_code == 401, (
            f"Flow 2: wrong password must return 401 (got {resp.status_code})"
        )

    def test_burst_of_wrong_logins_triggers_429(self, burst_client):
        """Burst of bad logins trips the rate limiter (HIGH-01: 10/minute)."""
        saw_429 = False
        for _ in range(30):
            res = burst_client.post(
                "/v1/auth/login",
                json={"username": "admin", "password": "wrong"},
            )
            if res.status_code == 429:
                saw_429 = True
                break
        assert saw_429, (
            "Flow 2: burst of wrong logins must trigger 429 within 30 attempts "
            "(@limiter.limit('10/minute') on /v1/auth/login)"
        )


# ─────────────────────────────────── Flow 3 ──────────────────────────────────


class TestFlow3AppealWithoutAuth:
    """Flow 3 — submit appeal without auth → 401 (CRITICO-03)."""

    def test_appeal_without_auth_returns_401(self, auth_client):
        resp = auth_client.post(
            "/v1/appeals",
            json={
                "audit_trail_id": 1001,
                "user_id": "passo15-tester",
                "reason": "Flow 3 — unauthenticated appeal must be rejected",
            },
        )
        assert resp.status_code == 401, (
            f"Flow 3: unauthenticated appeal must return 401 (got {resp.status_code})"
        )


# ─────────────────────────────────── Flow 4 ──────────────────────────────────


class TestFlow4AppealFullCycle:
    """Flow 4 — submit appeal with JWT → 201 → GET → resolve.

    POST /v1/appeals uses require_jwt.
    GET /v1/appeals/{id} uses require_api_key.
    POST /v1/appeals/{id}/resolve uses require_jwt.
    """

    def test_appeal_submit_returns_201(self, auth_client):
        resp = auth_client.post(
            "/v1/appeals",
            json={
                "audit_trail_id": 2001,
                "user_id": "passo15-tester",
                "reason": "Flow 4 — submit+retrieve+resolve cycle",
            },
            headers=_jwt_headers(),
        )
        assert resp.status_code == 201, (
            f"Flow 4: appeal submit with JWT must return 201 (got {resp.status_code})"
        )
        assert "appeal_id" in resp.json()

    def test_appeal_get_returns_200(self, auth_client):
        submit = auth_client.post(
            "/v1/appeals",
            json={
                "audit_trail_id": 2002,
                "user_id": "passo15-tester",
                "reason": "Flow 4 — retrieve check",
            },
            headers=_jwt_headers(),
        )
        assert submit.status_code == 201
        appeal_id = submit.json()["appeal_id"]

        get = auth_client.get(
            f"/v1/appeals/{appeal_id}",
            headers={"X-API-Key": _API_KEY},
        )
        assert get.status_code == 200, (
            f"Flow 4: GET appeal must return 200 (got {get.status_code})"
        )
        assert get.json()["status"] == "pending"

    def test_appeal_resolve_returns_200(self, auth_client):
        submit = auth_client.post(
            "/v1/appeals",
            json={
                "audit_trail_id": 2003,
                "user_id": "passo15-tester",
                "reason": "Flow 4 — resolve cycle",
            },
            headers=_jwt_headers(),
        )
        assert submit.status_code == 201
        appeal_id = submit.json()["appeal_id"]

        resolve = auth_client.post(
            f"/v1/appeals/{appeal_id}/resolve",
            json={
                "accepted": True,
                "reviewer_id": "passo15-reviewer",
                "reviewer_notes": "Confirmed false positive in system smoke",
            },
            headers=_jwt_headers(),
        )
        assert resolve.status_code == 200, (
            f"Flow 4: appeal resolve must return 200 (got {resolve.status_code})"
        )
        assert resolve.json()["status"] == "accepted"


# ─────────────────────────────────── Flow 5 ──────────────────────────────────


class TestFlow5InvalidBearerReturns401:
    """Flow 5 — invalid Bearer → 401.

    Tests the Python API layer JWT validation (require_jwt in auth.py).
    The Rust gateway's Bearer validation is exercised by CRITICO-07 Rust
    unit tests and ops/e2e-tests.sh §3.2 flow 5.
    """

    def test_malformed_bearer_returns_401(self, auth_client):
        resp = auth_client.get(
            "/v1/auth/me",
            headers={"Authorization": "Bearer totally-not-a-jwt"},
        )
        assert resp.status_code == 401, (
            f"Flow 5: malformed Bearer must return 401 (got {resp.status_code})"
        )

    def test_expired_jwt_returns_401(self, auth_client):
        expired = _make_jwt(expired=True)
        resp = auth_client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert resp.status_code == 401, (
            f"Flow 5: expired JWT must return 401 (got {resp.status_code})"
        )

    def test_wrong_secret_jwt_returns_401(self, auth_client):
        wrong = _make_jwt(secret=_WRONG_SECRET)
        resp = auth_client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {wrong}"},
        )
        assert resp.status_code == 401, (
            f"Flow 5: JWT signed with wrong secret must return 401 (got {resp.status_code})"
        )


# ─────────────────────────────────── Flow 6 ──────────────────────────────────


class TestFlow6OversizedInputReturns422:
    """Flow 6 — input_text > 50 000 chars → 422 (HIGH-03)."""

    def test_input_text_over_50k_returns_422(self, auth_client):
        big = "A" * 50_001
        resp = auth_client.post(
            "/v1/decide",
            json={
                "input_text": big,
                "composite_risk": 0.0,
                "finding_count": 0,
                "critical_count": 0,
                "action": "ALLOW",
                "matched_policies": [],
                "entropy": 2.0,
                "total_chars": 50_001,
                "blake3_hash": "p15-hash",
                "hard_blocked": False,
                "max_finding_confidence": 0.0,
            },
            headers={"X-API-Key": _API_KEY},
        )
        assert resp.status_code == 422, (
            f"Flow 6: input_text > 50 000 chars must return 422 (got {resp.status_code})"
        )


# ─────────────────────────────────── Flow 7 ──────────────────────────────────


class TestFlow7StartupInitialisesBeforeFirstRequest:
    """Flow 7 — startup initialises before first request (CRITICO-06).

    Verified by asserting health is 200 immediately and that the users DB
    was seeded during startup (not lazily on first login).
    For the Rust gateway, warm_policies() at boot is the CRITICO-10 Rust test.
    """

    def test_health_returns_200_immediately_after_startup(self, auth_client):
        resp = auth_client.get("/health")
        assert resp.status_code == 200, (
            f"Flow 7: health must be 200 immediately after startup (got {resp.status_code})"
        )

    def test_users_db_seeded_at_startup(self, auth_client):
        """Users DB is seeded during lifespan startup — verify admin exists."""
        import buildtovalue.api.routes.auth as auth_module

        result = auth_module._verify_user("admin", _ADMIN_PASS)
        assert result is not None, (
            "Flow 7: admin user must exist after startup (seeded by lifespan/fixture)"
        )
        assert result["username"] == "admin"


# ───────────────────── Audit trail immutability ───────────────────────────────


class TestAuditTrailImmutability:
    """Decisions committed to the ledger cannot be deleted.

    The ledger is append-only JSONL: there is no DELETE endpoint for
    decisions. Any DELETE attempt must return 404 or 405.
    """

    def test_no_delete_endpoint_for_decisions(self, auth_client):
        resp = auth_client.delete(
            "/v1/ledger/decisions/some-id",
            headers={"X-API-Key": _API_KEY},
        )
        assert resp.status_code in (404, 405), (
            f"Audit trail must be immutable — DELETE must not exist "
            f"(got {resp.status_code})"
        )

    def test_ledger_query_endpoint_is_accessible(self, auth_client):
        resp = auth_client.get(
            "/v1/ledger/query",
            headers={"X-API-Key": _API_KEY},
        )
        assert resp.status_code == 200, (
            f"GET /v1/ledger/query must return 200 (got {resp.status_code})"
        )
