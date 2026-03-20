"""Tests for ROPA Generator (LGPD Art. 37, ADR-048)."""

import pytest
from unittest.mock import MagicMock, patch

from buildtovalue.compliance.ledger_analytics import (
    LedgerAnalytics,
    LedgerAggregation,
)
from buildtovalue.compliance.ropa_generator import (
    ROPAGenerator,
    ROPAEntry,
    ROPADocument,
)


def _mock_aggregation() -> LedgerAggregation:
    """Create a realistic mock aggregation."""
    agg = LedgerAggregation()
    agg.total_decisions = 1000
    agg.period_start_ts = 1700000000000
    agg.period_end_ts = 1700100000000
    agg.action_counts = {"ALLOW": 800, "BLOCK": 100, "EDUCATE": 70, "REDACT": 30}
    agg.risk_distribution = {"low": 600, "medium": 250, "high": 100, "critical": 50}
    agg.pii_types_detected = {"CPF": 150, "EMAIL": 200, "CREDIT_CARD": 50}
    agg.mercy_count = 40
    agg.block_count = 100
    agg.hard_block_count = 20
    agg.total_risk_sum = 350.0
    return agg


class TestROPAEntry:
    def test_to_dict(self):
        entry = ROPAEntry(
            activity_name="Test Activity",
            purpose="Testing",
            legal_basis="Art. 7, IX",
            data_categories=["CPF", "Email"],
            data_subjects="Test users",
            recipients="None",
            retention_period="90 days",
            security_measures="HMAC-SHA256",
            cross_border_transfer=False,
            record_count=100,
        )
        d = entry.to_dict()
        assert d["activity_name"] == "Test Activity"
        assert d["cross_border_transfer"] is False
        assert d["record_count"] == 100


class TestROPADocument:
    def test_to_dict(self):
        doc = ROPADocument(
            controller="Test Corp",
            dpo_name="DPO Name",
            dpo_contact="dpo@test.com",
            entries=[],
            generated_at="2026-03-20T00:00:00",
            ledger_hash="abc123",
            total_records_processed=1000,
            period_covered="2026-01 a 2026-03",
        )
        d = doc.to_dict()
        assert d["document_type"] == "ROPA"
        assert d["legal_basis"] == "LGPD Art. 37"
        assert d["controller"] == "Test Corp"


class TestROPAGenerator:
    def test_generate_creates_document(self):
        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.aggregate.return_value = _mock_aggregation()

        generator = ROPAGenerator(analytics)
        ropa = generator.generate(
            controller="Empresa XYZ",
            dpo_name="Maria Silva",
            dpo_contact="dpo@empresa.com",
        )

        assert isinstance(ropa, ROPADocument)
        assert ropa.controller == "Empresa XYZ"
        assert ropa.total_records_processed == 1000
        assert len(ropa.entries) >= 1
        assert ropa.ledger_hash  # Non-empty hash

    def test_entries_have_real_data(self):
        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.aggregate.return_value = _mock_aggregation()

        generator = ROPAGenerator(analytics)
        ropa = generator.generate(
            controller="Test",
            dpo_name="DPO",
            dpo_contact="dpo@test.com",
        )

        primary_entry = ropa.entries[0]
        assert primary_entry.record_count == 1000
        assert primary_entry.block_count == 100
        assert primary_entry.mercy_count == 40
        assert primary_entry.cross_border_transfer is False

    def test_data_categories_inferred(self):
        analytics = MagicMock(spec=LedgerAnalytics)
        agg = _mock_aggregation()
        analytics.aggregate.return_value = agg

        generator = ROPAGenerator(analytics)
        ropa = generator.generate("C", "D", "e@f.com")

        categories = ropa.entries[0].data_categories
        assert any("CPF" in c or "CNPJ" in c for c in categories)
        assert any("email" in c.lower() for c in categories)

    def test_empty_ledger(self):
        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.aggregate.return_value = LedgerAggregation()

        generator = ROPAGenerator(analytics)
        ropa = generator.generate("C", "D", "e@f.com")

        assert ropa.total_records_processed == 0
        assert len(ropa.entries) >= 1  # Still creates structure

    def test_to_dict_serializable(self):
        import json

        analytics = MagicMock(spec=LedgerAnalytics)
        analytics.aggregate.return_value = _mock_aggregation()

        generator = ROPAGenerator(analytics)
        ropa = generator.generate("C", "D", "e@f.com")

        # Should not raise
        serialized = json.dumps(ropa.to_dict())
        assert len(serialized) > 100
