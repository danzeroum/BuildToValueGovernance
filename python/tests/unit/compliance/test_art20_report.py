"""Tests for Art. 20 Report Generator (LGPD, ADR-048)."""

import pytest
from unittest.mock import MagicMock

from buildtovalue.compliance.ledger_analytics import (
    LedgerAnalytics,
    DecisionRecord,
)
from buildtovalue.compliance.art20_report import (
    Art20ReportGenerator,
    Art20Report,
    Art20Summary,
)


def _mock_records() -> list:
    return [
        DecisionRecord(
            verdict_id="verd_001",
            timestamp=1700000000000,
            action="BLOCK",
            final_action="BLOCK",
            risk=0.85,
            findings=3,
            critical=1,
            mercy=False,
            hard_blocked=False,
            session="sess_001",
            profile="default",
            latency_ms=5.2,
        ),
        DecisionRecord(
            verdict_id="verd_002",
            timestamp=1700000001000,
            action="BLOCK",
            final_action="EDUCATE",
            risk=0.6,
            findings=2,
            critical=0,
            mercy=True,
            hard_blocked=False,
            session="sess_002",
            profile="default",
            latency_ms=3.1,
        ),
        DecisionRecord(
            verdict_id="verd_003",
            timestamp=1700000002000,
            action="ALLOW",
            final_action="ALLOW",
            risk=0.1,
            findings=0,
            critical=0,
            mercy=False,
            hard_blocked=False,
            session="sess_003",
            profile="default",
            latency_ms=1.5,
        ),
    ]


class TestArt20Summary:
    def test_to_dict(self):
        s = Art20Summary(
            total_decisions=100,
            automated_decisions=100,
            block_decisions=10,
            allow_decisions=80,
            mercy_applied=5,
        )
        d = s.to_dict()
        assert d["total_decisions"] == 100
        assert d["block_decisions"] == 10


class TestArt20Report:
    def test_to_dict(self):
        report = Art20Report(
            period_start="2026-01-01",
            period_end="2026-03-20",
            summary=Art20Summary(total_decisions=3),
            decisions=[{"verdict_id": "v1"}],
            methodology="Test methodology",
            bias_declarations=[],
            generated_at="2026-03-20T00:00:00",
        )
        d = report.to_dict()
        assert d["document_type"] == "LGPD_ART20_REPORT"
        assert d["total_decisions_in_report"] == 1


class TestArt20ReportGenerator:
    def test_generate_creates_report(self):
        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.get_decision_records.return_value = _mock_records()

        generator = Art20ReportGenerator(analytics)
        report = generator.generate()

        assert isinstance(report, Art20Report)
        assert report.summary.total_decisions == 3
        assert report.summary.block_decisions == 1
        assert report.summary.mercy_applied == 1
        assert len(report.decisions) == 3

    def test_summary_calculations(self):
        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.get_decision_records.return_value = _mock_records()

        generator = Art20ReportGenerator(analytics)
        report = generator.generate()

        assert report.summary.allow_decisions == 1
        assert report.summary.educate_decisions == 1
        assert abs(report.summary.avg_risk - 0.5167) < 0.01
        assert report.summary.avg_latency_ms > 0

    def test_methodology_not_empty(self):
        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.get_decision_records.return_value = []

        generator = Art20ReportGenerator(analytics)
        report = generator.generate()

        assert len(report.methodology) > 100
        assert "HMAC-SHA256" in report.methodology

    def test_bias_declarations_present(self):
        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.get_decision_records.return_value = []

        generator = Art20ReportGenerator(analytics)
        report = generator.generate()

        assert len(report.bias_declarations) >= 2

    def test_exclude_decisions(self):
        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.get_decision_records.return_value = []

        generator = Art20ReportGenerator(analytics)
        report = generator.generate(include_decisions=False)

        assert report.decisions == []

    def test_serializable(self):
        import json

        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.get_decision_records.return_value = _mock_records()

        generator = Art20ReportGenerator(analytics)
        report = generator.generate()

        serialized = json.dumps(report.to_dict())
        assert len(serialized) > 100
