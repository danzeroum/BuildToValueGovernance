"""
Intelligence Hub v1.0
Threat feed management — ingest, query, and enrich threat intelligence.
MISP/STIX compatible format.
"""

import time
import hashlib
import sqlite3  # noqa: F401 — kept for type compatibility

from buildtovalue.security import sqlite_connect_wal
import os
import json
from typing import List, Optional, Dict
from dataclasses import dataclass, field


DB_PATH = os.environ.get("BTV_THREATS_DB", "data/threats.db")


def init_threats_db():
    conn = sqlite_connect_wal(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            threat_type TEXT NOT NULL,
            severity INTEGER NOT NULL,
            source TEXT NOT NULL,
            indicators TEXT NOT NULL,
            description TEXT DEFAULT '',
            mitre_id TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            hash TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON threats(threat_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON threats(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON threats(source)")
    conn.commit()
    conn.close()


def compute_hash(threat_id: str, threat_type: str, severity: int, indicators: list) -> str:
    payload = f"{threat_id}:{threat_type}:{severity}:{','.join(indicators)}"
    return hashlib.blake2b(payload.encode(), digest_size=32).hexdigest()


def ingest_threat(
    threat_id: str,
    threat_type: str,
    severity: int,
    source: str,
    indicators: list,
    description: str = "",
    mitre_id: str = "",
) -> dict:
    h = compute_hash(threat_id, threat_type, severity, indicators)
    conn = sqlite_connect_wal(DB_PATH)
    try:
        conn.execute("""
            INSERT OR REPLACE INTO threats (id, threat_type, severity, source, indicators, description, mitre_id, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (threat_id, threat_type, severity, source, json.dumps(indicators), description, mitre_id, h))
        conn.commit()
    finally:
        conn.close()
    return {"id": threat_id, "hash": h, "status": "ingested"}


def query_threats(
    threat_type: Optional[str] = None,
    min_severity: int = 0,
    source: Optional[str] = None,
    limit: int = 50,
) -> list:
    conn = sqlite_connect_wal(DB_PATH)
    query = "SELECT id, threat_type, severity, source, indicators, description, mitre_id, created_at, hash FROM threats WHERE 1=1"
    params = []
    if threat_type:
        query += " AND threat_type = ?"
        params.append(threat_type)
    if min_severity > 0:
        query += " AND severity >= ?"
        params.append(min_severity)
    if source:
        query += " AND source = ?"
        params.append(source)
    query += " ORDER BY severity DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [
        {
            "id": r[0], "threat_type": r[1], "severity": r[2], "source": r[3],
            "indicators": json.loads(r[4]), "description": r[5], "mitre_id": r[6],
            "created_at": r[7], "hash": r[8],
        }
        for r in rows
    ]


def get_threat(threat_id: str) -> Optional[dict]:
    conn = sqlite_connect_wal(DB_PATH)
    row = conn.execute(
        "SELECT id, threat_type, severity, source, indicators, description, mitre_id, created_at, hash FROM threats WHERE id = ?",
        (threat_id,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0], "threat_type": row[1], "severity": row[2], "source": row[3],
        "indicators": json.loads(row[4]), "description": row[5], "mitre_id": row[6],
        "created_at": row[7], "hash": row[8],
    }


def get_stats() -> dict:
    conn = sqlite_connect_wal(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    by_type = conn.execute("SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type").fetchall()
    by_source = conn.execute("SELECT source, COUNT(*) FROM threats GROUP BY source").fetchall()
    avg_severity = conn.execute("SELECT AVG(severity) FROM threats").fetchone()[0] or 0
    conn.close()
    return {
        "total_threats": total,
        "by_type": {r[0]: r[1] for r in by_type},
        "by_source": {r[0]: r[1] for r in by_source},
        "avg_severity": round(avg_severity, 2),
    }