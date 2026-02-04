
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from governance.decision_engine import EthicalContextEngine
from governance.mercy import MercyCalculator
from governance.profile_manager import ProfileManager
from kernel_bindings.types import TechnicalEvidence, Finding, Action

# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def mock_evidence():
    """Mock technical evidence from Rust kernel"""
    return TechnicalEvidence(
        protocol_version=2,
        finding_count=1,
        critical_count=0,
        findings=[
            Finding(
                type="CPF_DETECTED",
                location="offset 10-24",
                value="123.456.789-09",
                confidence=0.95,
                severity="MEDIUM",
                validator="cpf_validator",
            )
        ],
        critical_findings=[],
        statistics={
            "entropy": 4.5,
            "length": 256,
        },
        has_pii=True,
        has_sensitive_data=False,
        evidence_hash="0xabcdef123456...",
    )

@pytest.fixture
def mock_context():
    """Mock contextual information"""
    return {
        "domain": "general",
        "user_role": "end_user",
        "sensitivity": "medium",
    }

@pytest.fixture
def mock_profile():
    """Mock policy profile"""
    return {
        "name": "general",
        "policies": ["cpf_protection_v1"],
        "mercy_threshold": 0.7,
    }

@pytest.fixture
def mock_trust_score():
    """Mock trust score from database"""
    return 0.85

# ═══════════════════════════════════════════════════════════════
# EthicalContextEngine Tests
# ═══════════════════════════════════════════════════════════════

class TestEthicalContextEngine:
    
    def test_decide_block_critical_violation(self, mock_evidence, mock_context, mock_profile, mock_trust_score):
        """Should BLOCK on critical PII violation"""
        # Make finding CRITICAL
        mock_evidence.findings[0].severity = "CRITICAL"
        mock_evidence.critical_count = 1
        
        engine = EthicalContextEngine()
        
        with patch.object(engine, '_get_trust_score', return_value=mock_trust_score):
            verdict = engine.decide(
                evidence=mock_evidence,
                context=mock_context,
                profile=mock_profile,
            )
        
        assert verdict.action == Action.BLOCK
        assert verdict.confidence > 0.9
        assert "CRITICAL" in verdict.rationale.upper()
    
    def test_decide_educate_first_offense(self, mock_evidence, mock_context, mock_profile):
        """Should EDUCATE on first offense (high trust)"""
        engine = EthicalContextEngine()
        
        with patch.object(engine, '_get_trust_score', return_value=0.95):  # High trust
            verdict = engine.decide(
                evidence=mock_evidence,
                context=mock_context,
                profile=mock_profile,
            )
        
        assert verdict.action == Action.EDUCATE
        assert verdict.mercy_applied is True
        assert "first offense" in " ".join(verdict.mercy_factors).lower()
    
    def test_decide_allow_no_violations(self, mock_context, mock_profile, mock_trust_score):
        """Should ALLOW when no violations detected"""
        clean_evidence = TechnicalEvidence(
            protocol_version=2,
            finding_count=0,
            critical_count=0,
            findings=[],
            critical_findings=[],
            statistics={"entropy": 3.0, "length": 100},
            has_pii=False,
            has_sensitive_data=False,
            evidence_hash="0x000000...",
        )
        
        engine = EthicalContextEngine()
        
        with patch.object(engine, '_get_trust_score', return_value=mock_trust_score):
            verdict = engine.decide(
                evidence=clean_evidence,
                context=mock_context,
                profile=mock_profile,
            )
        
        assert verdict.action == Action.ALLOW
        assert verdict.confidence > 0.95
    
    def test_decide_healthcare_context_mercy(self, mock_evidence, mock_profile, mock_trust_score):
        """Should apply mercy in healthcare context"""
        healthcare_context = {
            "domain": "medical_records",
            "user_role": "doctor",
            "sensitivity": "high",
            "purpose": "patient_diagnosis",
        }
        
        engine = EthicalContextEngine()
        
        with patch.object(engine, '_get_trust_score', return_value=mock_trust_score):
            verdict = engine.decide(
                evidence=mock_evidence,
                context=healthcare_context,
                profile=mock_profile,
            )
        
        # Should not block in healthcare context
        assert verdict.action != Action.BLOCK
        assert verdict.mercy_applied is True
    
    def test_decide_low_trust_stricter(self, mock_evidence, mock_context, mock_profile):
        """Should be stricter with low trust score"""
        engine = EthicalContextEngine()
        
        with patch.object(engine, '_get_trust_score', return_value=0.3):  # Low trust
            verdict = engine.decide(
                evidence=mock_evidence,
                context=mock_context,
                profile=mock_profile,
            )
        
        # Low trust → more likely to block
        assert verdict.action in [Action.BLOCK, Action.LOG]
        assert verdict.mercy_applied is False

# ═══════════════════════════════════════════════════════════════
# MercyCalculator Tests
# ═══════════════════════════════════════════════════════════════

class TestMercyCalculator:
    
    def test_calculate_high_uncertainty(self, mock_evidence, mock_context):
        """High uncertainty → more mercy"""
        # Low confidence = high uncertainty
        mock_evidence.findings[0].confidence = 0.6
        
        calculator = MercyCalculator()
        mercy_score = calculator.calculate(
            evidence=mock_evidence,
            context=mock_context,
            trust_score=0.8,
        )
        
        assert mercy_score > 0.7  # High mercy
    
    def test_calculate_high_trust(self, mock_evidence, mock_context):
        """High trust score → more mercy"""
        calculator = MercyCalculator()
        mercy_score = calculator.calculate(
            evidence=mock_evidence,
            context=mock_context,
            trust_score=0.95,  # Very high trust
        )
        
        assert mercy_score > 0.8
    
    def test_calculate_low_harm_potential(self, mock_evidence, mock_context):
        """Low harm potential → more mercy"""
        # Low severity = low harm potential
        mock_evidence.findings[0].severity = "LOW"
        
        calculator = MercyCalculator()
        mercy_score = calculator.calculate(
            evidence=mock_evidence,
            context=mock_context,
            trust_score=0.8,
        )
        
        assert mercy_score > 0.75
    
    def test_calculate_critical_no_mercy(self, mock_evidence, mock_context):
        """Critical violations → no mercy"""
        mock_evidence.findings[0].severity = "CRITICAL"
        mock_evidence.critical_count = 1
        
        calculator = MercyCalculator()
        mercy_score = calculator.calculate(
            evidence=mock_evidence,
            context=mock_context,
            trust_score=0.8,
        )
        
        assert mercy_score < 0.5  # Low mercy
    
    def test_calculate_healthcare_context(self, mock_evidence):
        """Healthcare context → more mercy"""
        healthcare_context = {
            "domain": "medical_records",
            "user_role": "doctor",
        }
        
        calculator = MercyCalculator()
        mercy_score = calculator.calculate(
            evidence=mock_evidence,
            context=healthcare_context,
            trust_score=0.8,
        )
        
        # Healthcare is high-justifiability context
        assert mercy_score > 0.8

# ═══════════════════════════════════════════════════════════════
# ProfileManager Tests
# ═══════════════════════════════════════════════════════════════

class TestProfileManager:
    
    def test_load_profile(self):
        """Should load profile from YAML"""
        manager = ProfileManager(config_dir="config/profiles")
        profile = manager.load_profile("general")
        
        assert profile is not None
        assert profile["name"] == "general"
        assert "policies" in profile
    
    def test_profile_inheritance(self):
        """Child profile should inherit from parent"""
        manager = ProfileManager(config_dir="config/profiles")
        
        # Healthcare inherits from general
        healthcare = manager.load_profile("healthcare")
        general = manager.load_profile("general")
        
        # Should have parent policies + own policies
        assert len(healthcare["policies"]) >= len(general["policies"])
    
    def test_profile_caching(self):
        """Should cache loaded profiles"""
        manager = ProfileManager(config_dir="config/profiles")
        
        # Load twice
        profile1 = manager.load_profile("general")
        profile2 = manager.load_profile("general")
        
        # Should be same object (cached)
        assert profile1 is profile2
    
    @patch("governance.profile_manager.yaml.safe_load")
    def test_profile_not_found(self, mock_yaml):
        """Should raise error if profile not found"""
        mock_yaml.side_effect = FileNotFoundError()
        
        manager = ProfileManager(config_dir="config/profiles")
        
        with pytest.raises(ValueError, match="Profile not found"):
            manager.load_profile("nonexistent")

# ═══════════════════════════════════════════════════════════════
# Property-Based Tests (hypothesis)
# ═══════════════════════════════════════════════════════════════

from hypothesis import given, strategies as st

class TestPropertyBased:
    
    @given(
        confidence=st.floats(min_value=0.0, max_value=1.0),
        trust_score=st.floats(min_value=0.0, max_value=1.0),
    )
    def test_mercy_score_bounded(self, confidence, trust_score):
        """Mercy score should always be between 0 and 1"""
        evidence = TechnicalEvidence(
            protocol_version=2,
            finding_count=1,
            critical_count=0,
            findings=[
                Finding(
                    type="CPF_DETECTED",
                    confidence=confidence,
                    severity="MEDIUM",
                    value="test",
                    location="offset 0",
                    validator="test",
                )
            ],
            critical_findings=[],
            statistics={"entropy": 4.0, "length": 100},
            has_pii=True,
            has_sensitive_data=False,
            evidence_hash="0x000000",
        )
        
        calculator = MercyCalculator()
        mercy_score = calculator.calculate(
            evidence=evidence,
            context={"domain": "general"},
            trust_score=trust_score,
        )
        
        assert 0.0 <= mercy_score <= 1.0
    
    @given(
        finding_count=st.integers(min_value=0, max_value=10),
    )
    def test_no_crash_on_any_finding_count(self, finding_count):
        """Should handle any valid finding count"""
        evidence = TechnicalEvidence(
            protocol_version=2,
            finding_count=finding_count,
            critical_count=0,
            findings=[
                Finding(
                    type="CPF_DETECTED",
                    confidence=0.95,
                    severity="MEDIUM",
                    value=f"finding_{i}",
                    location=f"offset {i}",
                    validator="test",
                )
                for i in range(finding_count)
            ],
            critical_findings=[],
            statistics={"entropy": 4.0, "length": 100},
            has_pii=True,
            has_sensitive_data=False,
            evidence_hash="0x000000",
        )
        
        engine = EthicalContextEngine()
        
        with patch.object(engine, '_get_trust_score', return_value=0.8):
            # Should not crash
            verdict = engine.decide(
                evidence=evidence,
                context={"domain": "general"},
                profile={"name": "general", "policies": []},
            )
        
        assert verdict is not None
        assert verdict.action in Action