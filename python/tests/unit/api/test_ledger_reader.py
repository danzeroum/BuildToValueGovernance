"""
Tests for LedgerReader v1.0 (ADR-025).

Covers: query filters, pagination, corrupt lines, missing file,
        entry count, stats endpoint compatibility.
"""

import json
import os

import pytest

from buildtovalue.api.ledger_reader import (
    LedgerQuery,
    LedgerReader,
    LedgerResult,
)


def _write_entries(path: str, entries: list) -> None:
    """Write entries as JSONL (same format as Rust gateway)."""
    with open(path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def _make_entry(
    ts: int = 1739812345678,
    session: str = "sess_001",
    profile: str = "default",
    policy_action: str = "BLOCK",
    final_action: str = "BLOCK",
    mercy: bool = False,
    risk: float = 0.85,
    findings: int = 2,
    critical: int = 1,
    hard_blocked: bool = False,
    verdict_id: str = "verd_abc",
    latency_ms: float = 12.5,
) -> dict:
    return {
        "ts": ts,
        "session": session,
        "profile": profile,
        "policy_action": policy_action,
        "final_action": final_action,
        "mercy": mercy,
        "risk": risk,
        "findings": findings,
        "critical": critical,
        "hard_blocked": hard_blocked,
        "verdict_id": verdict_id,
        "latency_ms": latency_ms,
    }


@pytest.fixture
def ledger_file(tmp_path):
    return str(tmp_path / "decisions.jsonl")


@pytest.fixture
def populated_ledger(ledger_file):
    """Ledger with 5 diverse entries."""
    entries = [
        _make_entry(ts=1000, session="s1", final_action="ALLOW", verdict_id="v1"),
        _make_entry(ts=2000, session="s1", final_action="EDUCATE", verdict_id="v2", mercy=True),
        _make_entry(ts=3000, session="s2", final_action="BLOCK", verdict_id="v3", critical=2),
        _make_entry(ts=4000, session="s2", final_action="BLOCK", verdict_id="v4", hard_blocked=True),
        _make_entry(ts=5000, session="s3", final_action="LOG", verdict_id="v5"),
    ]
    _write_entries(ledger_file, entries)
    return LedgerReader(ledger_path=ledger_file)


class TestMissingLedger:
    """Fail-secure: missing file returns empty, not error."""

    def test_missing_file_returns_empty(self, tmp_path):
        reader = LedgerReader(str(tmp_path / "nonexistent.jsonl"))
        result = reader.query(LedgerQuery())
        assert result.total == 0
        assert result.data == []

    def test_exists_false(self, tmp_path):
        reader = LedgerReader(str(tmp_path / "nope.jsonl"))
        assert reader.exists() is False

    def test_entry_count_zero(self, tmp_path):
        reader = LedgerReader(str(tmp_path / "nope.jsonl"))
        assert reader.entry_count() == 0


class TestNoFilters:
    """Query all entries without filters."""

    def test_returns_all(self, populated_ledger):
        result = populated_ledger.query(LedgerQuery())
        assert result.total == 5
        assert len(result.data) == 5

    def test_entry_count(self, populated_ledger):
        assert populated_ledger.entry_count() == 5


class TestFilterBySession:

    def test_filter_s1(self, populated_ledger):
        q = LedgerQuery(session_id="s1")
        result = populated_ledger.query(q)
        assert result.total == 2
        assert all(e["session"] == "s1" for e in result.data)

    def test_filter_nonexistent(self, populated_ledger):
        q = LedgerQuery(session_id="s_nope")
        result = populated_ledger.query(q)
        assert result.total == 0


class TestFilterByVerdict:

    def test_exact_verdict(self, populated_ledger):
        q = LedgerQuery(verdict_id="v3")
        result = populated_ledger.query(q)
        assert result.total == 1
        assert result.data[0]["verdict_id"] == "v3"


class TestFilterByAction:

    def test_block_only(self, populated_ledger):
        q = LedgerQuery(action="BLOCK")
        result = populated_ledger.query(q)
        assert result.total == 2
        assert all(e["final_action"] == "BLOCK" for e in result.data)

    def test_educate_only(self, populated_ledger):
        q = LedgerQuery(action="EDUCATE")
        result = populated_ledger.query(q)
        assert result.total == 1


class TestFilterByTimestamp:

    def test_start_ts(self, populated_ledger):
        q = LedgerQuery(start_ts=3000)
        result = populated_ledger.query(q)
        assert result.total == 3
        assert all(e["ts"] >= 3000 for e in result.data)

    def test_end_ts(self, populated_ledger):
        q = LedgerQuery(end_ts=2000)
        result = populated_ledger.query(q)
        assert result.total == 2
        assert all(e["ts"] <= 2000 for e in result.data)

    def test_range(self, populated_ledger):
        q = LedgerQuery(start_ts=2000, end_ts=4000)
        result = populated_ledger.query(q)
        assert result.total == 3


class TestCombinedFilters:

    def test_session_plus_action(self, populated_ledger):
        q = LedgerQuery(session_id="s2", action="BLOCK")
        result = populated_ledger.query(q)
        assert result.total == 2

    def test_session_plus_time(self, populated_ledger):
        q = LedgerQuery(session_id="s1", end_ts=1500)
        result = populated_ledger.query(q)
        assert result.total == 1
        assert result.data[0]["verdict_id"] == "v1"


class TestPagination:

    def test_limit_fits_all(self, populated_ledger):
        q = LedgerQuery(limit=10)
        result = populated_ledger.query(q)
        assert len(result.data) == 5  # only 5 entries, fits in 1 page
        assert result.pages == 1

    def test_pagination_with_many_entries(self, ledger_file):
        """Test real pagination with enough entries."""
        entries = [
            _make_entry(ts=i * 1000, verdict_id=f"v{i}")
            for i in range(25)
        ]
        _write_entries(ledger_file, entries)
        reader = LedgerReader(ledger_path=ledger_file)

        q1 = LedgerQuery(page=1, limit=10)
        r1 = reader.query(q1)
        assert len(r1.data) == 10
        assert r1.total == 25
        assert r1.pages == 3

        q2 = LedgerQuery(page=2, limit=10)
        r2 = reader.query(q2)
        assert len(r2.data) == 10

        q3 = LedgerQuery(page=3, limit=10)
        r3 = reader.query(q3)
        assert len(r3.data) == 5  # last page partial

    def test_beyond_last_page(self, populated_ledger):
        q = LedgerQuery(page=99, limit=10)
        result = populated_ledger.query(q)
        assert len(result.data) == 0

    def test_limit_clamped_min(self):
        q = LedgerQuery(limit=0)
        assert q.limit == 1

    def test_limit_clamped_max(self):
        q = LedgerQuery(limit=9999)
        assert q.limit == 1000

class TestCorruptLines:
    """Resilience against malformed JSONL."""

    def test_skip_corrupt_lines(self, ledger_file):
        with open(ledger_file, "w") as f:
            f.write(json.dumps(_make_entry(verdict_id="good1")) + "\n")
            f.write("THIS IS NOT JSON\n")
            f.write("{broken json\n")
            f.write("\n")
            f.write(json.dumps(_make_entry(verdict_id="good2")) + "\n")

        reader = LedgerReader(ledger_path=ledger_file)
        result = reader.query(LedgerQuery())
        assert result.total == 2
        ids = [e["verdict_id"] for e in result.data]
        assert "good1" in ids
        assert "good2" in ids

    def test_empty_file(self, ledger_file):
        with open(ledger_file, "w") as f:
            f.write("")
        reader = LedgerReader(ledger_path=ledger_file)
        result = reader.query(LedgerQuery())
        assert result.total == 0


class TestResultSerialization:

    def test_to_dict_structure(self, populated_ledger):
        result = populated_ledger.query(LedgerQuery())
        d = result.to_dict()
        assert "data" in d
        assert "pagination" in d
        assert "ledger_file" in d
        pg = d["pagination"]
        for field in ("page", "limit", "total", "pages"):
            assert field in pg, f"pagination must have '{field}'"
        assert pg["total"] == 5
        assert pg["page"] == 1