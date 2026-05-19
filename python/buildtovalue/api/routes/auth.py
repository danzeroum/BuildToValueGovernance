"""
JWT Authentication Routes — Feature 2.4
Login, refresh, and user info endpoints for the React dashboard.
Keeps backward compatibility with API key auth for SDK/programmatic access.
"""

import hashlib
import logging
import os
import sqlite3  # noqa: F401 — kept for type compatibility

from buildtovalue.security import sqlite_connect_wal
import time
from typing import Optional

import jwt
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/auth", tags=["auth"])

JWT_SECRET = os.environ.get("BTV_JWT_SECRET", "btv-dev-jwt-secret-NOT-FOR-PRODUCTION")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 3600 * 8  # 8 hours
REFRESH_EXPIRY_SECONDS = 3600 * 24 * 7  # 7 days

USERS_DB_PATH = os.environ.get("BTV_USERS_DB", "data/users.db")

bearer_scheme = HTTPBearer(auto_error=False)


# ── Models ──────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    token: str
    refresh_token: str
    username: str
    role: str
    expires_in: int


class UserInfo(BaseModel):
    username: str
    role: str


# ── User Store (SQLite) ────────────────────────────────────

def _init_users_db():
    conn = sqlite_connect_wal(USERS_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    # Seed default admin if no users exist
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        default_pw = os.environ.get("BTV_ADMIN_PASSWORD", "admin")
        pw_hash = hashlib.sha256(default_pw.encode()).hexdigest()
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", pw_hash, "admin"),
        )
        logger.info("Seeded default admin user (change password in production!)")
    conn.commit()
    conn.close()


def _verify_user(username: str, password: str) -> Optional[dict]:
    conn = sqlite_connect_wal(USERS_DB_PATH)
    row = conn.execute(
        "SELECT username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if row[1] != pw_hash:
        return None
    return {"username": row[0], "role": row[2]}


def _create_token(username: str, role: str, expiry: int) -> str:
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + expiry,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── FastAPI Dependency ──────────────────────────────────────

async def require_jwt(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    """FastAPI dependency — validates JWT Bearer token, returns user info."""
    if creds is None:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    payload = _decode_token(creds.credentials)
    return {"username": payload["sub"], "role": payload["role"]}


# ── Routes ──────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    _init_users_db()
    user = _verify_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = _create_token(user["username"], user["role"], JWT_EXPIRY_SECONDS)
    refresh = _create_token(user["username"], user["role"], REFRESH_EXPIRY_SECONDS)
    return LoginResponse(
        token=token,
        refresh_token=refresh,
        username=user["username"],
        role=user["role"],
        expires_in=JWT_EXPIRY_SECONDS,
    )


@router.post("/refresh", response_model=LoginResponse)
def refresh(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if creds is None:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    payload = _decode_token(creds.credentials)
    token = _create_token(payload["sub"], payload["role"], JWT_EXPIRY_SECONDS)
    refresh = _create_token(payload["sub"], payload["role"], REFRESH_EXPIRY_SECONDS)
    return LoginResponse(
        token=token,
        refresh_token=refresh,
        username=payload["sub"],
        role=payload["role"],
        expires_in=JWT_EXPIRY_SECONDS,
    )


@router.get("/me", response_model=UserInfo)
def get_me(user: dict = Depends(require_jwt)):
    return UserInfo(username=user["username"], role=user["role"])
