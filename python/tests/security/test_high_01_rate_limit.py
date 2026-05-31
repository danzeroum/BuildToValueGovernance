"""RED test — HIGH-01: the Python API must rate-limit abusive callers.

Plan: Passo 4. No limiter is configured today, so a burst never yields 429.
"""
import pytest

pytestmark = pytest.mark.security


def test_login_burst_eventually_returns_429(client_with_api_key):
    """A burst of bad logins from one client must trip a 429 within 30 tries."""
    saw_429 = False
    for _ in range(30):
        res = client_with_api_key.post(
            "/v1/auth/login",
            json={"username": "admin", "password": "definitely-wrong"},
        )
        if res.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "expected a 429 once the login rate limit is exceeded"
