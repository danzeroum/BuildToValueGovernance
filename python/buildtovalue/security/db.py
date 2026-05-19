"""SQLite connection helper with WAL semantics applied uniformly (S-04).

Background:
    Previously each call site set PRAGMA journal_mode=WAL ad-hoc — or omitted
    it entirely. SQLite stores ``journal_mode`` per database file, not per
    connection, but the first connection after a process restart determines
    the effective mode. If the first connection forgets the PRAGMA, the file
    silently falls back to DELETE mode and concurrent reads serialize on a
    coarse lock. Under FastAPI/uvicorn ``--workers N`` this manifests as
    sporadic ``database is locked`` errors that are hard to diagnose.

    Centralizing the PRAGMA application removes the "first connection wins"
    foot-gun: every connection from this helper applies WAL + synchronous=
    NORMAL + a 30s busy_timeout, so any of them can be the "first" safely.

Usage:
    from buildtovalue.security.db import sqlite_connect_wal

    with sqlite_connect_wal("data/trust.db") as conn:
        conn.execute("...")

A flake8 / pre-commit rule (tracked in docs/status.md) forbids direct
``sqlite3.connect()`` outside this module.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Union

PathLike = Union[str, Path, os.PathLike]


def sqlite_connect_wal(
    path: PathLike,
    *,
    timeout: float = 30.0,
    check_same_thread: bool = True,
) -> sqlite3.Connection:
    """Open a SQLite connection with WAL + sane concurrency defaults.

    Args:
        path: Filesystem path to the database (parent directories created
            if missing — convenience for ``data/foo.db`` patterns).
        timeout: ``sqlite3.connect`` busy timeout in seconds (default 30).
        check_same_thread: Pass-through to ``sqlite3.connect``; set to
            ``False`` only when explicitly serializing access yourself.

    Returns:
        A ``sqlite3.Connection`` with the following PRAGMAs applied:
            - ``journal_mode=WAL`` (concurrent reads, durable writes)
            - ``synchronous=NORMAL`` (sync at WAL checkpoint, not every commit)
            - ``busy_timeout=30000`` (30s; matches ``timeout`` parameter)
    """
    p = Path(path)
    parent = p.parent
    if parent and str(parent) not in (".", ""):
        parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        str(p),
        timeout=timeout,
        check_same_thread=check_same_thread,
    )
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
    return conn
