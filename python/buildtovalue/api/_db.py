"""Camada SQLite de persistência de trust (ADR-0093 Phase 2, Passo 3).

Extraída de `app.py` para que routers e o lifespan acessem o DB sem import
reverso de `app.py`. Usa exclusivamente `sqlite_connect_wal` (G1: nenhum
`sqlite3.connect` direto). `DB_PATH` resolve de `BTV_DB_PATH`.
"""
from __future__ import annotations

import os
from typing import Dict

from buildtovalue.security import sqlite_connect_wal

DB_PATH = os.environ.get("BTV_DB_PATH", "data/trust.db")


def init_db() -> None:
    conn = sqlite_connect_wal(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            trust_score REAL NOT NULL DEFAULT 0.5,
            offenses INTEGER NOT NULL DEFAULT 0,
            total_requests INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    # Colunas v1.9: post-penalty analysis (ADR-039)
    for _col in [
        "ALTER TABLE sessions ADD COLUMN last_entropy REAL NOT NULL DEFAULT 0.0",
        "ALTER TABLE sessions ADD COLUMN last_action TEXT NOT NULL DEFAULT ''",
    ]:
        try:
            conn.execute(_col)
        except Exception:
            pass
    # C3: agent public keys table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_pubkeys (
            agent_id TEXT PRIMARY KEY,
            public_key_hex TEXT NOT NULL,
            registered_at TEXT NOT NULL DEFAULT (datetime('now')),
            revoked_at TEXT,
            registration_proof TEXT
        )
    """)
    conn.commit()
    conn.close()


def db_get_session(session_id: str) -> Dict[str, object]:
    conn = sqlite_connect_wal(DB_PATH)
    row = conn.execute(
        "SELECT trust_score, offenses, total_requests, last_entropy, last_action "
        "FROM sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    conn.close()
    if row:
        return {"trust_score": row[0], "offenses": row[1], "total_requests": row[2],
                "last_entropy": row[3], "last_action": row[4]}
    return {"trust_score": 0.5, "offenses": 0, "total_requests": 0,
            "last_entropy": 0.0, "last_action": ""}


def db_update_session_state(
    session_id: str, last_entropy: float, last_action: str
) -> None:
    """Persiste last_entropy e last_action (ADR-039 post-penalty analysis)."""
    conn = sqlite_connect_wal(DB_PATH)
    conn.execute(
        "UPDATE sessions SET last_entropy=?, last_action=? WHERE session_id=?",
        (last_entropy, last_action, session_id),
    )
    conn.commit()
    conn.close()


def db_update_session(
    session_id: str, trust_score: float, offense_delta: int
) -> None:
    conn = sqlite_connect_wal(DB_PATH)
    existing = conn.execute(
        "SELECT session_id FROM sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE sessions SET trust_score = ?, offenses = offenses + ?, "
            "total_requests = total_requests + 1, updated_at = datetime('now') "
            "WHERE session_id = ?",
            (trust_score, offense_delta, session_id),
        )
    else:
        conn.execute(
            "INSERT INTO sessions (session_id, trust_score, offenses, total_requests) "
            "VALUES (?, ?, ?, 1)",
            (session_id, trust_score, offense_delta),
        )
    conn.commit()
    conn.close()
