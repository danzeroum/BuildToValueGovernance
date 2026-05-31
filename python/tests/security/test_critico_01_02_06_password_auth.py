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

def test_login_does_not_initialise_users_db(monkeypatch):
    """login() must NOT call _init_users_db (it belongs in the lifespan)."""
    auth = importlib.reload(__import__("buildtovalue.api.routes.auth",
                                       fromlist=["login"]))
    calls = {"n": 0}
    monkeypatch.setattr(auth, "_init_users_db", lambda: calls.__setitem__("n", calls["n"] + 1))
    monkeypatch.setattr(auth, "_verify_user", lambda u, p: None)

    from fastapi import HTTPException
    for _ in range(3):
        with pytest.raises(HTTPException):
            auth.login(auth.LoginRequest(username="x", password="y"))

    assert calls["n"] == 0, "login still calls _init_users_db per request"
