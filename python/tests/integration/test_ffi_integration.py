"""
BuildToValue v2.0 - FFI Integration Tests
Tests Rust ↔ Python bridge for LGPD validators

Gate: Day 21 - Compliance Integration
"""

import pytest

pytestmark = pytest.mark.ffi

import time
from buildtovalue.ffi.rust_validators import get_rust_validators, Finding


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def rust_validators():
    """Rust validators FFI instance."""
    return get_rust_validators()


# ═══════════════════════════════════════════════════════════════════════════
# CONSENT VALIDATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestConsentValidatorFFI:
    """Tests consent validator via FFI."""

    def test_missing_consent(self, rust_validators):
        """Test missing consent detection."""
        metadata = {
            'user.has_consent': 'false',
            'processing.requires_consent': 'true',
        }

        findings = rust_validators.validate_consent("", metadata)

        assert len(findings) == 1
        assert findings[0].rule_id == "LGPD_ART7_I_CONSENTIMENTO"
        assert findings[0].title == "MISSING_USER_CONSENT"
        assert findings[0].confidence == 255

        print(f"\n✅ FFI Consent: {findings[0].rule_id}, confidence={findings[0].confidence}")

    def test_consent_with_legal_basis(self, rust_validators):
        """Test consent with alternative legal basis (Art. 7º, IX)."""
        metadata = {
            'user.has_consent': 'false',
            'processing.requires_consent': 'true',
            'processing.legal_basis': 'legitimate_interest',
        }

        findings = rust_validators.validate_consent("", metadata)

        assert len(findings) == 0  # Has alternative legal basis

        print(f"\n✅ FFI Consent (legal basis): No findings (expected)")

    def test_valid_consent(self, rust_validators):
        """Test valid explicit consent."""
        metadata = {
            'user.has_consent': 'true',
            'consent.is_explicit': 'true',
            'processing.requires_consent': 'true',
        }

        findings = rust_validators.validate_consent("", metadata)

        assert len(findings) == 0

        print(f"\n✅ FFI Consent (valid): No findings")


# ═══════════════════════════════════════════════════════════════════════════
# CONSENT REVOCATION VALIDATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestConsentRevocationFFI:
    """Tests consent revocation validator via FFI."""

    def test_revocation_processing_continues(self, rust_validators):
        """Test revocation with processing continues."""
        metadata = {
            'user.consent_revoked': 'true',
            'processing.continues': 'true',
        }

        findings = rust_validators.validate_consent_revocation("", metadata)

        assert len(findings) == 1
        assert findings[0].rule_id == "LGPD_ART8_P5_REVOGACAO"
        assert findings[0].confidence == 255

        print(f"\n✅ FFI Revocation: {findings[0].rule_id}, confidence={findings[0].confidence}")

    def test_revocation_processing_stopped(self, rust_validators):
        """Test revocation with processing stopped (compliant)."""
        metadata = {
            'user.consent_revoked': 'true',
            'processing.continues': 'false',
        }

        findings = rust_validators.validate_consent_revocation("", metadata)

        assert len(findings) == 0

        print(f"\n✅ FFI Revocation (stopped): Compliant")


# ═══════════════════════════════════════════════════════════════════════════
# SENSITIVE DATA VALIDATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestSensitiveDataFFI:
    """Tests sensitive data validator via FFI."""

    def test_health_data_detected(self, rust_validators):
        """Test health data detection."""
        input_text = "Paciente João Silva tem diagnóstico de diabetes tipo 2"

        findings = rust_validators.validate_sensitive_data(input_text)

        assert len(findings) == 1
        assert findings[0].rule_id == "LGPD_ART11_DADOS_SENSIVEIS"
        assert "HEALTH" in findings[0].title

        print(f"\n✅ FFI Sensitive (health): {findings[0].title}, confidence={findings[0].confidence}")

    def test_biometric_data_detected(self, rust_validators):
        """Test biometric data detection."""
        input_text = "Realizar reconhecimento facial do usuário"

        findings = rust_validators.validate_sensitive_data(input_text)

        assert len(findings) == 1
        assert "BIOMETRIC" in findings[0].title

        print(f"\n✅ FFI Sensitive (biometric): {findings[0].title}")

    def test_sensitive_with_consent(self, rust_validators):
        """Test sensitive data with specific consent."""
        input_text = "Paciente tem HIV positivo"
        metadata = {
            'consent.is_specific_for_sensitive': 'true',
        }

        findings = rust_validators.validate_sensitive_data(input_text, metadata)

        assert len(findings) == 0  # Has specific consent

        print(f"\n✅ FFI Sensitive (with consent): Compliant")

    def test_no_sensitive_data(self, rust_validators):
        """Test non-sensitive data."""
        input_text = "Nome: João Silva, Endereço: Rua A, 123"

        findings = rust_validators.validate_sensitive_data(input_text)

        assert len(findings) == 0

        print(f"\n✅ FFI Sensitive (none): No findings")


# ═══════════════════════════════════════════════════════════════════════════
# BATCH VALIDATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestBatchValidation:
    """Tests batch validation (performance)."""

    def test_batch_multiple_validators(self, rust_validators):
        """Test batch with multiple validators."""
        inputs = [
            "CPF: 123.456.789-09",
            "Paciente tem diabetes",
            "Cartão: 4111-1111-1111-1111",
        ]

        metadata = {
            'user.has_consent': 'false',
            'processing.requires_consent': 'true',
        }

        findings = rust_validators.validate_batch(
            validator_names=["consent", "sensitive_data", "cpf", "credit_card"],
            inputs=inputs,
            metadata=metadata
        )

        # Should detect: consent missing, sensitive data, CPF, credit card
        assert len(findings) >= 3

        rule_ids = [f.rule_id for f in findings]
        assert any("CONSENT" in r for r in rule_ids)
        assert any("SENSIVEIS" in r for r in rule_ids)

        print(f"\n✅ FFI Batch: {len(findings)} findings from 3 inputs, 4 validators")

    def test_batch_performance_100_inputs(self, rust_validators):
        """Test batch performance with 100 inputs."""
        inputs = ["Test input " + str(i) for i in range(100)]

        start = time.perf_counter()

        findings = rust_validators.validate_batch(
            validator_names=["consent", "sensitive_data"],
            inputs=inputs,
            metadata={'user.has_consent': 'true'}
        )

        elapsed_ms = (time.perf_counter() - start) * 1000
        avg_ms = elapsed_ms / 100

        assert elapsed_ms < 100, f"Batch 100 inputs took {elapsed_ms:.2f}ms > 100ms"

        print(f"\n✅ FFI Batch Performance: 100 inputs in {elapsed_ms:.2f}ms ({avg_ms:.2f}ms avg)")


# ═══════════════════════════════════════════════════════════════════════════
# INTEGRATION WITH ETHICAL CONTEXT ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class TestFFIWithEthicalEngine:
    """Tests FFI integration with EthicalContextEngine."""

    def test_rust_findings_to_technical_evidence(self, rust_validators):
        """Test converting Rust findings to TechnicalEvidence format."""
        input_text = "Paciente tem câncer de pulmão"

        findings = rust_validators.validate_sensitive_data(input_text)

        # Convert to TechnicalEvidence format (for EthicalContextEngine)
        technical_evidence = {
            'composite_risk': max([f.severity for f in findings]) if findings else 0,
            'findings': [f.to_dict() for f in findings],
            'finding_count': len(findings),
            'critical_count': sum(1 for f in findings if f.severity >= 200),
            'entropy': 3.5,  # Would come from EntropyValidator
            'uncertainty_score': 0.15,
        }

        assert technical_evidence['composite_risk'] == 255
        assert technical_evidence['finding_count'] == 1
        assert technical_evidence['findings'][0]['rule_id'] == "LGPD_ART11_DADOS_SENSIVEIS"

        print(
            f"\n✅ FFI → TechnicalEvidence: {technical_evidence['finding_count']} findings, risk={technical_evidence['composite_risk']}")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
