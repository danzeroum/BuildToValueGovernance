"""
Tests for SectorLoader v1.0 (Gap #4).

Coverage:
- Index loading
- Sector loading + cache
- Whitelist matching (hit/miss)
- ProfileManager integration
"""

import pytest
from pathlib import Path
from buildtovalue.governance.sector_loader import SectorLoader


# ═══════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════


@pytest.fixture
def sectors_dir(tmp_path):
    """Create test sector YAML files."""
    d = tmp_path / "sectors"
    d.mkdir()

    (d / "_index.yaml").write_text("""
_metadata:
  version: "1.0.0"
sectors:
  healthcare:
    file: healthcare.yaml
    risk_classification: high_risk
  fintech:
    file: fintech.yaml
    risk_classification: high_risk
  general:
    file: null
    risk_classification: minimal_risk
  orphan:
    file: missing.yaml
    risk_classification: high_risk
""")

    (d / "healthcare.yaml").write_text("""
_metadata:
  sector_id: healthcare
  version: "1.0.0"
safe_patterns:
  "medical diagnosis":
    keywords: ["pii", "personal data", "health data"]
    rationale: "Diagnosis requires patient PII access"
  "patient assessment":
    keywords: ["pii", "personal data"]
    rationale: "Clinical assessment requires records"
  "verify patient identity":
    keywords: ["passport", "ssn"]
    rationale: "Patient ID prevents wrong-patient events"
""")

    (d / "fintech.yaml").write_text("""
_metadata:
  sector_id: fintech
  version: "1.0.0"
safe_patterns:
  "credit score":
    keywords: ["credit card", "credit"]
    rationale: "Credit scoring is regulated activity"
  "kyc compliance":
    keywords: ["passport", "ssn", "pii"]
    rationale: "KYC is legally mandated"
""")

    return d


@pytest.fixture
def loader(sectors_dir):
    """SectorLoader with test data."""
    return SectorLoader(sectors_dir)


# ═══════════════════════════════════════════════════════════════
# INDEX LOADING
# ═══════════════════════════════════════════════════════════════


class TestIndexLoading:

    def test_index_loaded(self, loader):
        """Should load all sectors from _index.yaml."""
        assert "healthcare" in loader._index
        assert "fintech" in loader._index
        assert "general" in loader._index
        assert "orphan" in loader._index

    def test_index_missing(self, tmp_path):
        """Should handle missing _index.yaml gracefully."""
        empty = tmp_path / "empty"
        empty.mkdir()
        loader = SectorLoader(empty)
        assert loader._index == {}

    def test_metrics(self, loader):
        """Should report correct metrics."""
        m = loader.get_metrics()
        assert m["sectors_indexed"] == 4
        assert m["sectors_cached"] == 0


# ═══════════════════════════════════════════════════════════════
# SECTOR LOADING
# ═══════════════════════════════════════════════════════════════


class TestSectorLoading:

    def test_load_healthcare(self, loader):
        """Should load healthcare patterns."""
        sector = loader.load_sector("healthcare")
        assert sector is not None
        assert sector.sector_id == "healthcare"
        assert sector.risk_classification == "high_risk"
        assert sector.risk_multiplier == 0.7
        assert "medical diagnosis" in sector.patterns
        assert "pii" in sector.patterns["medical diagnosis"]

    def test_load_fintech(self, loader):
        """Should load fintech patterns."""
        sector = loader.load_sector("fintech")
        assert sector is not None
        assert "credit score" in sector.patterns
        assert "credit card" in sector.patterns["credit score"]

    def test_load_general_returns_none(self, loader):
        """General has file: null — returns None."""
        assert loader.load_sector("general") is None

    def test_load_unknown_returns_none(self, loader):
        """Unknown sector not in index — returns None."""
        assert loader.load_sector("unknown") is None

    def test_load_orphan_returns_none(self, loader):
        """Sector with missing YAML file — returns None."""
        assert loader.load_sector("orphan") is None

    def test_cache_hit(self, loader):
        """Second load should return cached instance."""
        s1 = loader.load_sector("healthcare")
        s2 = loader.load_sector("healthcare")
        assert s1 is s2
        assert loader.get_metrics()["sectors_cached"] == 1

    def test_patterns_lowercased(self, loader):
        """Triggers and keywords should be lowercased."""
        sector = loader.load_sector("healthcare")
        for trigger, keywords in sector.patterns.items():
            assert trigger == trigger.lower()
            for kw in keywords:
                assert kw == kw.lower()


# ═══════════════════════════════════════════════════════════════
# WHITELIST MATCHING
# ═══════════════════════════════════════════════════════════════


class TestWhitelistMatching:

    def test_match_healthcare_pii(self, loader):
        """Trigger + keyword match → reduced risk."""
        m = loader.apply_whitelist(
            input_text="medical diagnosis for patient with CPF",
            findings=["PII_DETECTED", "CPF_PATTERN_DETECTED"],
            sector_id="healthcare",
        )
        assert m == 0.7

    def test_match_fintech_kyc(self, loader):
        """KYC trigger with PII finding → reduced risk."""
        m = loader.apply_whitelist(
            input_text="kyc compliance check for customer",
            findings=["PII_DETECTED", "PASSPORT_DETECTED"],
            sector_id="fintech",
        )
        assert m == 0.7

    def test_no_trigger_match(self, loader):
        """No trigger in text → no reduction."""
        m = loader.apply_whitelist(
            input_text="random text about weather",
            findings=["PII_DETECTED"],
            sector_id="healthcare",
        )
        assert m == 1.0

    def test_trigger_but_no_keyword_match(self, loader):
        """Trigger found but findings don't match keywords."""
        m = loader.apply_whitelist(
            input_text="medical diagnosis needed",
            findings=["SQL_INJECTION_DETECTED"],
            sector_id="healthcare",
        )
        assert m == 1.0

    def test_general_sector_no_reduction(self, loader):
        """General sector has no patterns → 1.0."""
        m = loader.apply_whitelist(
            input_text="medical diagnosis for patient",
            findings=["PII_DETECTED"],
            sector_id="general",
        )
        assert m == 1.0

    def test_unknown_sector_no_reduction(self, loader):
        """Unknown sector → 1.0."""
        m = loader.apply_whitelist(
            input_text="anything",
            findings=["PII_DETECTED"],
            sector_id="nonexistent",
        )
        assert m == 1.0

    def test_case_insensitive_matching(self, loader):
        """Should match regardless of case."""
        m = loader.apply_whitelist(
            input_text="MEDICAL DIAGNOSIS for Patient",
            findings=["pii_detected"],
            sector_id="healthcare",
        )
        assert m == 0.7

    def test_empty_input(self, loader):
        """Empty input → no trigger match → 1.0."""
        m = loader.apply_whitelist(
            input_text="",
            findings=["PII_DETECTED"],
            sector_id="healthcare",
        )
        assert m == 1.0

    def test_empty_findings(self, loader):
        """No findings → no keyword match → 1.0."""
        m = loader.apply_whitelist(
            input_text="medical diagnosis test",
            findings=[],
            sector_id="healthcare",
        )
        assert m == 1.0


# ═══════════════════════════════════════════════════════════════
# PROFILE → SECTOR INTEGRATION
# ═══════════════════════════════════════════════════════════════


class TestProfileIntegration:

    def test_full_flow(self, loader, tmp_path):
        """ProfileManager → sector_id → whitelist → reduced risk."""
        from buildtovalue.governance.profile_manager import (
            ProfileManager,
        )

        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir()

        (profiles_dir / "medical.yaml").write_text("""
id: medical
name: Medical Profile
description: Medical agent profile
parent_id: null
version: 1.0.0
created_at: "2026-02-17"
updated_at: "2026-02-17"
rules:
  - id: ALLOW_CPF_MEDICAL
    name: Allow CPF in medical
    description: CPF allowed in medical context
    action: EDUCATE
    priority: 200
domain_config:
  healthcare:
    risk_multiplier: 0.7
    allowed_findings:
      - CPF_PATTERN_DETECTED
    education_message: "Medical context"
""")

        pm = ProfileManager(profiles_dir)
        profile = pm.load_profile("medical")

        # Extract sector from domain_config
        domain_keys = [
            k for k in profile.domain_config.keys()
            if k != "general"
        ]
        assert domain_keys == ["healthcare"]

        # Apply whitelist with real text
        sector_id = domain_keys[0]
        m = loader.apply_whitelist(
            input_text="medical diagnosis CPF 111.444.777-05",
            findings=["PII_DETECTED", "CPF_PATTERN_DETECTED"],
            sector_id=sector_id,
        )
        assert m == 0.7

    def test_profile_without_sector(self, loader, tmp_path):
        """Profile with only 'general' domain → no reduction."""
        from buildtovalue.governance.profile_manager import (
            ProfileManager,
        )

        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir()

        (profiles_dir / "basic.yaml").write_text("""
id: basic
name: Basic Profile
description: Basic profile no sector
parent_id: null
version: 1.0.0
created_at: "2026-02-17"
updated_at: "2026-02-17"
rules:
  - id: BLOCK_PII
    name: Block PII
    description: Block all PII
    action: BLOCK
    priority: 100
domain_config:
  general:
    risk_multiplier: 1.0
    education_message: "General context"
""")

        pm = ProfileManager(profiles_dir)
        profile = pm.load_profile("basic")

        domain_keys = [
            k for k in profile.domain_config.keys()
            if k != "general"
        ]
        assert domain_keys == []