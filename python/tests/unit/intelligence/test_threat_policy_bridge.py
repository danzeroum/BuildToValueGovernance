"""
Tests for ThreatPolicyBridge v2.1 (ADR-024).

Covers: sync flow, deduplication, atomic write, severity mapping,
        human-in-the-loop invariant, circuit breaker.
"""

import os
import tempfile

import pytest
import yaml

from buildtovalue.intelligence.misp_ingestor import (
    MispIngestor,
    ThreatEvent,
)
from buildtovalue.intelligence.threat_classifier import ThreatClassifier
from buildtovalue.intelligence.threat_policy_bridge import (
    MAX_POLICIES_PER_SYNC,
    ThreatPolicyBridge,
    BridgeSyncResult,
)


@pytest.fixture
def tmp_policies_dir(tmp_path):
    d = tmp_path / "auto-generated"
    d.mkdir()
    return str(d)


@pytest.fixture
def populated_ingestor():
    """Ingestor with representative threat events."""
    ing = MispIngestor()
    events = [
        ThreatEvent(
            id="t-001",
            threat_type="prompt_injection",
            severity=9,
            source="OWASP",
            indicators=["pattern:ignore_previous"],
        ),
        ThreatEvent(
            id="t-002",
            threat_type="pii_leakage",
            severity=8,
            source="MISP",
            indicators=["cpf", "email"],
        ),
        ThreatEvent(
            id="t-003",
            threat_type="denial_of_service",
            severity=6,
            source="STIX",
        ),
        ThreatEvent(
            id="t-004",
            threat_type="social_engineering",
            severity=4,
            source="manual",
        ),
    ]
    for e in events:
        ing.ingest(e)
    return ing


@pytest.fixture
def bridge(populated_ingestor, tmp_policies_dir):
    return ThreatPolicyBridge(
        ingestor=populated_ingestor,
        policies_dir=tmp_policies_dir,
    )


class TestBridgeSync:
    """Core sync flow tests."""

    def test_sync_generates_policies(self, bridge, tmp_policies_dir):
        result = bridge.sync()
        assert isinstance(result, BridgeSyncResult)
        assert result.threats_processed == 4
        assert result.policies_generated > 0
        assert result.all_require_review is True

        # Verify files on disk
        yamls = list(
            p for p in os.listdir(tmp_policies_dir)
            if p.endswith(".yaml")
        )
        assert len(yamls) == result.policies_generated

    def test_all_policies_disabled(self, bridge, tmp_policies_dir):
        """Rawls invariant: no auto-generated policy is enabled."""
        bridge.sync()
        for path in os.listdir(tmp_policies_dir):
            if not path.endswith(".yaml"):
                continue
            with open(os.path.join(tmp_policies_dir, path)) as f:
                doc = yaml.safe_load(f)
            assert doc["enabled"] is False, (
                f"Policy {path} is enabled — violates Rawls invariant"
            )
            assert doc["requires_review"] is True

    def test_all_policies_have_required_fields(
        self, bridge, tmp_policies_dir
    ):
        bridge.sync()
        required = {
            "id", "name", "enabled", "requires_review",
            "severity", "conditions", "action", "source",
            "auto_generated", "source_threat_id", "generated_at",
        }
        for path in os.listdir(tmp_policies_dir):
            if not path.endswith(".yaml"):
                continue
            with open(os.path.join(tmp_policies_dir, path)) as f:
                doc = yaml.safe_load(f)
            missing = required - set(doc.keys())
            assert not missing, (
                f"Policy {path} missing fields: {missing}"
            )


class TestSeverityMapping:
    """Jonas: proportional response to threat severity."""

    def test_critical_maps_to_block(self, bridge):
        assert bridge._action_for_severity(9) == "BLOCK"
        assert bridge._action_for_severity(10) == "BLOCK"
        assert bridge._action_for_severity(8) == "BLOCK"

    def test_medium_maps_to_escalate(self, bridge):
        assert bridge._action_for_severity(5) == "ESCALATE"
        assert bridge._action_for_severity(7) == "ESCALATE"

    def test_low_maps_to_monitor(self, bridge):
        assert bridge._action_for_severity(1) == "MONITOR_ONLY"
        assert bridge._action_for_severity(4) == "MONITOR_ONLY"


class TestDeduplication:
    """Prevents redundant policy generation."""

    def test_second_sync_deduplicates(
        self, bridge, tmp_policies_dir
    ):
        r1 = bridge.sync()
        r2 = bridge.sync()
        assert r2.policies_generated == 0, (
            "Second sync should generate 0 (all deduped)"
        )
        assert r2.policies_deduplicated > 0

    def test_higher_severity_replaces(self, tmp_policies_dir):
        """A higher-severity threat for same type should generate."""
        ing = MispIngestor()
        ing.ingest(ThreatEvent(
            id="t-low", threat_type="pii_leakage",
            severity=5, source="X",
        ))
        bridge = ThreatPolicyBridge(
            ingestor=ing, policies_dir=tmp_policies_dir,
        )
        r1 = bridge.sync()
        assert r1.policies_generated == 1

        # Now ingest higher severity
        ing.ingest(ThreatEvent(
            id="t-high", threat_type="pii_leakage",
            severity=9, source="X",
        ))
        r2 = bridge.sync()
        assert r2.policies_generated == 1, (
            "Higher severity should generate new policy"
        )


class TestCircuitBreaker:
    """MAX_POLICIES_PER_SYNC limit."""

    def test_circuit_breaker_limits_output(self, tmp_policies_dir):
        ing = MispIngestor()
        for i in range(MAX_POLICIES_PER_SYNC + 20):
            ing.ingest(ThreatEvent(
                id=f"t-{i:04d}",
                threat_type=f"threat_type_{i}",
                severity=8,
                source="bulk",
            ))
        bridge = ThreatPolicyBridge(
            ingestor=ing, policies_dir=tmp_policies_dir,
        )
        result = bridge.sync()
        assert result.policies_generated <= MAX_POLICIES_PER_SYNC


class TestPendingReview:
    """Review tracking."""

    def test_pending_count_after_sync(
        self, bridge, tmp_policies_dir
    ):
        bridge.sync()
        count = bridge.pending_review_count()
        assert count > 0

    def test_pending_decreases_on_approve(
        self, bridge, tmp_policies_dir
    ):
        bridge.sync()
        before = bridge.pending_review_count()

        # Simulate human approval (enable first policy)
        for path in os.listdir(tmp_policies_dir):
            if path.endswith(".yaml"):
                fpath = os.path.join(tmp_policies_dir, path)
                with open(fpath) as f:
                    doc = yaml.safe_load(f)
                doc["enabled"] = True
                with open(fpath, "w") as f:
                    yaml.dump(doc, f)
                break

        after = bridge.pending_review_count()
        assert after == before - 1


class TestLastSync:
    """Status tracking."""

    def test_last_sync_none_before_first(self, bridge):
        assert bridge.last_sync is None

    def test_last_sync_populated_after(self, bridge):
        bridge.sync()
        assert bridge.last_sync is not None
        assert bridge.last_sync.threats_processed > 0

    def test_to_dict_serializable(self, bridge):
        bridge.sync()
        d = bridge.last_sync.to_dict()
        assert isinstance(d, dict)
        assert "synced_at" in d
        assert "policies_generated" in d