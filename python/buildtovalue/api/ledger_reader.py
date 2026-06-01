"""
LedgerReader v1.0
Reads and filters the append-only decisions.jsonl written by Rust gateway.

This module is READ-ONLY. It never modifies the ledger file.
The JSONL format is defined by rust/gateway/src/routes/validate.rs.

ADR: 0024-ledger-query-api.md
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("btv.ledger.reader")

# Fields written by Rust gateway (validate.rs)
REQUIRED_FIELDS = {
    "ts", "session", "profile", "policy_action",
    "final_action", "mercy", "risk", "findings",
    "critical", "hard_blocked", "verdict_id", "latency_ms",
}

DEFAULT_LIMIT = 20
MAX_LIMIT = 1000
MIN_LIMIT = 1


@dataclass(frozen=True)
class LedgerQuery:
    """Immutable query parameters for ledger search."""

    session_id: Optional[str] = None
    verdict_id: Optional[str] = None
    action: Optional[str] = None
    start_ts: Optional[int] = None
    end_ts: Optional[int] = None
    page: int = 1
    limit: int = DEFAULT_LIMIT

    def __post_init__(self) -> None:
        if self.page < 1:
            object.__setattr__(self, "page", 1)
        clamped = max(MIN_LIMIT, min(MAX_LIMIT, self.limit))
        object.__setattr__(self, "limit", clamped)


@dataclass(frozen=True)
class LedgerResult:
    """Immutable result of a ledger query."""

    data: List[Dict]
    total: int
    page: int
    limit: int
    pages: int
    ledger_file: str

    def to_dict(self) -> Dict:
        return {
            "data": self.data,
            "pagination": {
                "page": self.page,
                "limit": self.limit,
                "total": self.total,
                "pages": self.pages,
            },
            "ledger_file": self.ledger_file,
        }


class LedgerReader:
    """
    Read-only reader for the Rust gateway's decisions.jsonl.

    Never modifies the ledger. Fail-secure: missing file returns
    empty results, not errors.
    """

    def __init__(self, ledger_path: str = "data/ledger/decisions.jsonl") -> None:
        self._path = Path(ledger_path)

    @property
    def ledger_path(self) -> str:
        return str(self._path)

    def exists(self) -> bool:
        return self._path.is_file()

    def entry_count(self) -> int:
        """Total lines in ledger (O(n) scan)."""
        if not self.exists():
            return 0
        count = 0
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count

    def query(self, q: LedgerQuery) -> LedgerResult:
        """
        Execute query against ledger with filters and pagination.

        Fail-secure: missing/corrupt file → empty result.
        """
        if not self.exists():
            return self._empty_result(q)

        matched: List[Dict] = []

        try:
            with open(self._path, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        entry = json.loads(stripped)
                    except json.JSONDecodeError:
                        logger.warning(
                            "Corrupt line %d in ledger, skipping",
                            line_num,
                        )
                        continue

                    if self._matches(entry, q):
                        matched.append(entry)

        except OSError as exc:
            logger.error("Failed to read ledger: %s", exc)
            return self._empty_result(q)

        total = len(matched)
        pages = max(1, (total + q.limit - 1) // q.limit)
        start = (q.page - 1) * q.limit
        end = start + q.limit
        page_data = matched[start:end]

        return LedgerResult(
            data=page_data,
            total=total,
            page=q.page,
            limit=q.limit,
            pages=pages,
            ledger_file=str(self._path),
        )

    def _matches(self, entry: Dict, q: LedgerQuery) -> bool:
        """Check if entry matches all active filters."""
        if q.session_id and entry.get("session") != q.session_id:
            return False
        if q.verdict_id and entry.get("verdict_id") != q.verdict_id:
            return False
        if q.action and entry.get("final_action") != q.action:
            return False
        if q.start_ts and entry.get("ts", 0) < q.start_ts:
            return False
        if q.end_ts and entry.get("ts", 0) > q.end_ts:
            return False
        return True

    def _empty_result(self, q: LedgerQuery) -> LedgerResult:
        return LedgerResult(
            data=[],
            total=0,
            page=q.page,
            limit=q.limit,
            pages=0,
            ledger_file=str(self._path),
        )