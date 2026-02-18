"""
E2E Tests: Threat→Policy Bridge (ADR-024)

Full HTTP flow:
  POST /v1/intelligence/ingest (feed threats via HTTP)
  → POST /v1/intelligence/bridge/sync (trigger generation)
  → GET /v1/intelligence/bridge/status (verify result)
  → Disk verification (YAML files exist, disabled, require review)

With Gap #8 unification, /v1/intelligence/ingest now feeds both
SQLite (persistence) and MispIngestor (bridge source). This test
exercises the real HTTP surface end-to-end.

Invariants validated:
  1. Rawls: All auto-generated policies born disabled
  2. Jonas: Severity maps to proportional action
  3. Levinas: Drafts, not sentences (requires_review=true)
  4. Deduplication: second sync generates 0 new policies
  5. Atomic write: no partial YAML files on disk
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from buildtovalue.api.app import app, startup


# ═══════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def _policies_dir():
    """Temporary auto-generated policies dir."""
    d = tempfile.mkdtemp(prefix="btv_e2e_bridge_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def client(_policies_dir):
    """TestClient with auth disabled, bridge→temp dir."""
    os.environ.pop("BTV_API_KEYS", None)
    os.environ["BTV_ENV"] = "development"
    startup()

    from buildtovalue.api.routes import intelligence as intel_mod
    intel_mod._bridge._policies_dir = Path(_policies_dir)
    intel_mod._bridge._existing_policies.clear()
    # Clear ingestor so only our test threats are present
    intel_mod._ingestor._events.clear()
    intel_mod._ingestor._index_by_type.clear()
    intel_mod._ingestor._index_by_severity.clear()

    return TestClient(app)


@pytest.fixture(scope="module")
def policies_dir(_policies_dir):
    return _policies_dir


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

THREAT_PAYLOADS = [
    {
        "id": "e2e-t-001", "threat_type": "prompt_injection",
        "severity": 9, "source": "OWASP",
        "indicators": ["ignore previous", "system prompt"],
    },
    {
        "id": "e2e-t-002", "threat_type": "pii_leakage",
        "severity": 8, "source": "MISP",
        "indicators": ["cpf", "rg", "email"],
    },
    {
        "id": "e2e-t-003", "threat_type": "denial_of_service",
        "severity": 6, "source": "STIX",
        "indicators": [],
    },
    {
        "id": "e2e-t-004", "threat_type": "social_engineering",
        "severity": 3, "source": "manual",
        "indicators": ["urgency", "authority"],
    },
]


def _ingest_via_http(client, threats=None):
    """Ingest threats via real HTTP endpoint."""
    threats = threats or THREAT_PAYLOADS
    for t in threats:
        res = client.post("/v1/intelligence/ingest", json=t)
        assert res.status_code == 200, f"Ingest failed: {res.text}"


def _list_yamls(d: str):
    return [f for f in os.listdir(d) if f.endswith(".yaml")]


def _read_policy(d: str, f: str) -> dict:
    with open(os.path.join(d, f)) as fh:
        return yaml.safe_load(fh)


# ═══════════════════════════════════════════════════════════════
# SCENARIO 1: Full Happy Path (HTTP→Sync→Disk)
# ═══════════════════════════════════════════════════════════════

class TestE2EHappyPath:

    def test_step1_ingest_threats_via_http(self, client):
        """POST /v1/intelligence/ingest feeds both SQLite and bridge."""
        _ingest_via_http(client)

    def test_step2_sync_generates_policies(self, client, policies_dir):
        """POST /sync generates disabled policy YAMLs from ingested threats."""
        res = client.post("/v1/intelligence/bridge/sync")
        assert res.status_code == 200

        result = res.json()["result"]
        assert result["threats_processed"] == 4
        assert result["policies_generated"] > 0
        assert result["all_require_review"] is True

        yamls = _list_yamls(policies_dir)
        assert len(yamls) == result["policies_generated"]

    def test_step3_all_policies_disabled(self, policies_dir):
        """Rawls: every policy born disabled."""
        for fname in _list_yamls(policies_dir):
            doc = _read_policy(policies_dir, fname)
            assert doc["enabled"] is False
            assert doc["requires_review"] is True

    def test_step4_required_fields(self, policies_dir):
        """All mandatory fields present."""
        required = {
            "id", "name", "enabled", "requires_review",
            "severity", "conditions", "action", "source",
            "auto_generated", "source_threat_id", "generated_at",
        }
        for fname in _list_yamls(policies_dir):
            doc = _read_policy(policies_dir, fname)
            missing = required - set(doc.keys())
            assert not missing, f"{fname} missing: {missing}"

    def test_step5_severity_mapping(self, policies_dir):
        """Jonas: proportional response."""
        for fname in _list_yamls(policies_dir):
            doc = _read_policy(policies_dir, fname)
            sev = doc["conditions"]["min_severity"]
            action = doc["action"]
            if sev >= 8:
                assert action == "BLOCK"
            elif sev >= 5:
                assert action == "ESCALATE"
            else:
                assert action == "MONITOR_ONLY"

    def test_step6_status_after_sync(self, client):
        """GET /status reflects completed sync."""
        res = client.get("/v1/intelligence/bridge/status")
        assert res.status_code == 200
        data = res.json()
        assert data["last_sync"] is not None
        assert data["last_sync"]["policies_generated"] > 0
        assert data["pending_review"] > 0


# ═══════════════════════════════════════════════════════════════
# SCENARIO 2: Deduplication
# ═══════════════════════════════════════════════════════════════

class TestE2EDeduplication:

    def test_second_sync_zero_new(self, client):
        """Same threats → 0 new policies."""
        res = client.post("/v1/intelligence/bridge/sync")
        assert res.status_code == 200
        result = res.json()["result"]
        assert result["policies_generated"] == 0
        assert result["policies_deduplicated"] > 0


# ═══════════════════════════════════════════════════════════════
# SCENARIO 3: Severity Escalation via HTTP
# ═══════════════════════════════════════════════════════════════

class TestE2ESeverityEscalation:

    def test_escalation_via_http(self, client, policies_dir):
        """Ingest higher severity via HTTP → sync → upgraded policy."""
        res = client.post("/v1/intelligence/ingest", json={
            "id": "e2e-t-005-escalated",
            "threat_type": "social_engineering",
            "severity": 9,
            "source": "CERT",
            "indicators": ["deepfake", "voice_clone"],
        })
        assert res.status_code == 200

        res = client.post("/v1/intelligence/bridge/sync")
        assert res.status_code == 200

        result = res.json()["result"]
        assert result["policies_generated"] >= 1

        # Verify the social_engineering policy now maps to BLOCK
        found = False
        for fname in _list_yamls(policies_dir):
            doc = _read_policy(policies_dir, fname)
            if doc.get("conditions", {}).get("threat_type") == "social_engineering":
                if doc["conditions"]["min_severity"] >= 9:
                    assert doc["action"] == "BLOCK"
                    found = True
        assert found, "No escalated social_engineering policy found"


# ═══════════════════════════════════════════════════════════════
# SCENARIO 4: Atomic Write
# ═══════════════════════════════════════════════════════════════

class TestE2EAtomicWrite:

    def test_no_temp_files(self, client, policies_dir):
        client.post("/v1/intelligence/bridge/sync")
        tmp = [f for f in os.listdir(policies_dir) if f.endswith(".tmp")]
        assert len(tmp) == 0


# ═══════════════════════════════════════════════════════════════
# SCENARIO 5: Min Severity Filter
# ═══════════════════════════════════════════════════════════════

class TestE2EMinSeverityFilter:

    def test_high_severity_only(self):
        """Isolated bridge: min_severity=8 skips low threats."""
        from buildtovalue.intelligence.misp_ingestor import MispIngestor, ThreatEvent
        from buildtovalue.intelligence.threat_policy_bridge import ThreatPolicyBridge

        with tempfile.TemporaryDirectory() as td:
            ing = MispIngestor()
            for t in THREAT_PAYLOADS:
                ing.ingest(ThreatEvent(**{
                    k: v for k, v in t.items()
                    if k in ("id", "threat_type", "severity", "source", "indicators")
                }))

            bridge = ThreatPolicyBridge(ingestor=ing, policies_dir=td)
            result = bridge.sync(min_severity=8)
            assert result.policies_generated <= 2

            for fname in _list_yamls(td):
                doc = _read_policy(td, fname)
                assert doc["conditions"]["min_severity"] >= 8


# ═══════════════════════════════════════════════════════════════
# SCENARIO 6: Empty State
# ═══════════════════════════════════════════════════════════════

class TestE2EEmptyState:

    def test_empty_ingestor(self):
        from buildtovalue.intelligence.misp_ingestor import MispIngestor
        from buildtovalue.intelligence.threat_policy_bridge import ThreatPolicyBridge

        with tempfile.TemporaryDirectory() as td:
            bridge = ThreatPolicyBridge(ingestor=MispIngestor(), policies_dir=td)
            result = bridge.sync()
            assert result.threats_processed == 0
            assert result.policies_generated == 0
            assert len(result.errors) == 0