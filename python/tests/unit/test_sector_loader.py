"""Tests for SectorLoader v1.0."""

import pytest
from pathlib import Path
from buildtovalue.governance.sector_loader import SectorLoader


@pytest.fixture
def loader(tmp_path):
    """SectorLoader with test data."""
    sectors_dir = tmp_path / "sectors"
    sectors_dir.mkdir()

    # Index
    (sectors_dir / "_index.yaml").write_text("""
_metadata:
  version: "1.0.0"
sectors:
  healthcare:
    file: healthcare.yaml
    risk_classification: high_risk
  general:
    file: null
    risk_classification: minimal_risk
""")

    # Healthcare patterns
    (sectors_dir / "healthcare.yaml").write_text("""
_metadata:
  sector_id: healthcare
  version: "1.0.0"
safe_patterns:
  "medical diagnosis":
    keywords: ["pii", "personal data", "health data"]
  "patient assessment":
    keywords: ["pii", "personal data"]
""")

    return SectorLoader(sectors_dir)


class TestSectorLoader:

    def test_load_index(self, loader):
        """Should load sector index."""
        assert "healthcare" in loader._index
        assert "general" in loader._index

    def test_load_healthcare(self, loader):
        """Should load healthcare patterns."""
        sector = loader.load_sector("healthcare")
        assert sector is not None
        assert sector.sector_id == "healthcare"
        assert "medical diagnosis" in sector.patterns
        assert "pii" in sector.patterns["medical diagnosis"]

    def test_load_general_returns_none(self, loader):
        """General has no file — returns None."""
        assert loader.load_sector("general") is None

    def test_load_unknown_returns_none(self, loader):
        """Unknown sector returns None."""
        assert loader.load_sector("unknown") is None

    def test_cache_hit(self, loader):
        """Second load should use cache."""
        s1 = loader.load_sector("healthcare")
        s2 = loader.load_sector("healthcare")
        assert s1 is s2

    def test_whitelist_match(self, loader):
        """Should reduce risk when trigger+keyword match."""
        multiplier = loader.apply_whitelist(
            input_text="medical diagnosis for patient",
            findings=["PII_DETECTED", "PERSONAL_DATA"],
            sector_id="healthcare",
        )
        assert multiplier < 1.0

    def test_whitelist_no_match(self, loader):
        """No match — returns 1.0."""
        multiplier = loader.apply_whitelist(
            input_text="random text about weather",
            findings=["PII_DETECTED"],
            sector_id="healthcare",
        )
        assert multiplier == 1.0

    def test_whitelist_no_sector(self, loader):
        """General sector — returns 1.0."""
        multiplier = loader.apply_whitelist(
            input_text="medical diagnosis",
            findings=["PII_DETECTED"],
            sector_id="general",
        )
        assert multiplier == 1.0


class TestProfileIntegration:
    """Test ProfileManager + SectorLoader together."""

    def test_profile_to_sector_flow(self, loader, tmp_path):
        """Full flow: profile → sector → whitelist."""
        from buildtovalue.governance.profile_manager import (
            ProfileManager,
        )

        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir()

        (profiles_dir / "medical-agent.yaml").write_text("""
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
    allowed_findings: ["CPF_PATTERN_DETECTED"]
    education_message: "Medical context"
""")

        pm = ProfileManager(profiles_dir)
        profile = pm.load_profile("medical-agent")

        # Extract sector from domain_config
        domain_keys = [
            k for k in profile.domain_config.keys()
            if k != "general"
        ]
        assert domain_keys == ["healthcare"]

        # Apply sector whitelist
        sector_id = domain_keys[0]
        multiplier = loader.apply_whitelist(
            input_text="medical diagnosis CPF check",
            findings=["PII_DETECTED", "CPF_PATTERN_DETECTED"],
            sector_id=sector_id,
        )
        assert multiplier < 1.0