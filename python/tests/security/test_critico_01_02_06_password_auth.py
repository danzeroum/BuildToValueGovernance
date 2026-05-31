"""RED tests — CRITICO-01 (bcrypt), CRITICO-02 (no default pw), CRITICO-06 (init once).

Plan: Passo 1. These assert post-fix behaviour and FAIL today because
`routes/auth.py` still uses SHA-256, defaults the admin password to "admin",
and calls `_init_users_db()` on every login.
"""
import importlib
import os

import pytest

pytestmark = pytest.mark.security


# ── CRITICO-01: passwords stored with bcrypt, not SHA-256 ──────────────────

def test_admin_seed_uses_bcrypt_hash(tmp_path, monkeypatch):
    """Seeded admin hash must be bcrypt ($2b$/$2a$), not a 64-char SHA-256 hex."""
    monkeypatch.setenv("BTV_USERS_DB", str(tmp_path / "users.db"))
    monkeypatch.setenv("BTV_ADMIN_PASSWORD", "Sup3r-Str0ng-Admin-2026")

    auth = importlib.reload(__import__("buildtovalue.api.routes.auth",
                                       fromlist=["_init_users_db"]))
    auth._init_users_db()

    from buildtovalue.security import sqlite_connect_wal
    conn = sqlite_connect_wal(os.environ["BTV_USERS_DB"])
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username='admin'").fetchone()
    conn.close()

    stored = row[0]
    assert stored.startswith(("$2b$", "$2a$")), (
        f"expected bcrypt hash, got {stored[:12]!r} (SHA-256 still in use)")


def test_password_verification_accepts_correct_rejects_wrong(tmp_path, monkeypatch):
    monkeypatch.setenv("BTV_USERS_DB", str(tmp_path / "users.db"))
    monkeypatch.setenv("BTV_ADMIN_PASSWORD", "Sup3r-Str0ng-Admin-2026")
    auth = importlib.reload(__import__("buildtovalue.api.routes.auth",
                                       fromlist=["_init_users_db"]))
    auth._init_users_db()

    assert auth._verify_user("admin", "Sup3r-Str0ng-Admin-2026") is not None
    assert auth._verify_user("admin", "wrong-password") is None


# ── CRITICO-02: no "admin" default; require strong BTV_ADMIN_PASSWORD ──────

def test_seed_without_admin_password_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("BTV_USERS_DB", str(tmp_path / "users.db"))
    monkeypatch.delenv("BTV_ADMIN_PASSWORD", raising=False)
    auth = importlib.reload(__import__("buildtovalue.api.routes.auth",
                                       fromlist=["_init_users_db"]))
    with pytest.raises(RuntimeError):
        auth._init_users_db()


def test_seed_rejects_short_admin_password(tmp_path, monkeypatch):
    monkeypatch.setenv("BTV_USERS_DB", str(tmp_path / "users.db"))
    monkeypatch.setenv("BTV_ADMIN_PASSWORD", "short")  # < 12 chars
    auth = importlib.reload(__import__("buildtovalue.api.routes.auth",
                                       fromlist=["_init_users_db"]))
    with pytest.raises(RuntimeError):
        auth._init_users_db()


# ── CRITICO-06: init runs at startup, not on every login ───────────────────

def test_login_does_not_initialise_users_db(monkeypatch, tmp_path):
    """login() must NOT call _init_users_db (it belongs in the lifespan).

    Exercised via the real HTTP path: the lifespan seeds the DB once at
    startup, then login requests must not trigger _init_users_db again.
    """
    monkeypatch.setenv("BTV_USERS_DB", str(tmp_path / "u.db"))
    monkeypatch.setenv("BTV_ADMIN_PASSWORD", "ci-test-admin-password-2026")
    monkeypatch.delenv("BTV_API_KEYS", raising=False)

    import buildtovalue.api.routes.auth as auth
    import buildtovalue.api.app as app_module
    from fastapi.testclient import TestClient

    app_module._contestability_loop = None
    with TestClient(app_module.app) as client:
        # Startup has already seeded once; count any further calls from logins.
        calls = {"n": 0}
        monkeypatch.setattr(
            auth, "_init_users_db", lambda: calls.__setitem__("n", calls["n"] + 1)
        )
        for _ in range(3):
            client.post("/v1/auth/login", json={"username": "x", "password": "wrong"})
        assert calls["n"] == 0, "login still calls _init_users_db per request"
