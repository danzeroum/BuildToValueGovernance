
"""
Integration tests for full validation flow (Rust + Python).

These tests verify the entire pipeline:
  1. Input → Rust Kernel (scan)
  2. Evidence → Python Governance (decide)
  3. Verdict → Response
"""

import pytest
from unittest.mock import patch, MagicMock
import time

from api.validation import ValidationService
from governance.decision_engine import EthicalContextEngine
from governance.profile_manager import ProfileManager
from database.session import SessionManager
from ledger.writer import LedgerWriter

# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def test_db():
    """In-memory test database"""
    from database.connection import create_test_db
    db = create_test_db()
    yield db
    db.close()

@pytest.fixture
def validation_service(test_db):
    """Validation service with real components"""
    return ValidationService(
        engine=EthicalContextEngine(),
        profile_manager=ProfileManager(config_dir="config/profiles"),
        session_manager=SessionManager(db=test_db),
        ledger_writer=LedgerWriter(path="/tmp/test_ledger"),
    )

@pytest.fixture
def test_session(test_db):
    """Create test session with known trust score"""
    session_manager = SessionManager(db=test_db)
    session_id = "test_session_123"
    session_manager.create_session(session_id, trust_score=0.85)
    yield session_id
    session_manager.delete_session(session_id)

# ═══════════════════════════════════════════════════════════════
# Happy Path Tests
# ═══════════════════════════════════════════════════════════════

class TestValidationFlowHappyPath:
    
    def test_validate_clean_input(self, validation_service, test_session):
        """Clean input should be allowed"""
        result = validation_service.validate(
            text="Hello, how are you today?",
            session_id=test_session,
            profile="general",
        )
        
        assert result.action == "ALLOW"
        assert result.confidence > 0.95
        assert result.verdict_id is not None
        assert result.processing_time_ms < 100
    
    def test_validate_cpf_detected(self, validation_service, test_session):
        """CPF in general context should be blocked"""
        result = validation_service.validate(
            text="My CPF is 123.456.789-09",
            session_id=test_session,
            profile="general",
        )
        
        assert result.action in ["BLOCK", "EDUCATE"]  # Depends on trust
        assert result.technical_evidence is not None
        assert result.technical_evidence.finding_count == 1
        assert result.technical_evidence.has_pii is True
    
    def test_validate_healthcare_context(self, validation_service, test_session):
        """CPF in healthcare context should apply mercy"""
        result = validation_service.validate(
            text="Patient CPF: 123.456.789-09",
            session_id=test_session,
            profile="healthcare",
            context={
                "domain": "medical_records",
                "user_role": "doctor",
            },
        )
        
        # Healthcare context → mercy applied
        assert result.mercy_applied is True
        assert result.action != "BLOCK"  # Should not block doctors
        assert "medical" in result.rationale.lower()
    
    def test_validate_multiple_violations(self, validation_service, test_session):
        """Multiple violations should be aggregated"""
        result = validation_service.validate(
            text="CPF: 123.456.789-09, Email: user@example.com, Phone: +55 11 98765-4321",
            session_id=test_session,
            profile="general",
        )
        
        assert result.technical_evidence.finding_count >= 2
        assert result.action == "BLOCK"
        assert result.confidence > 0.9

# ═══════════════════════════════════════════════════════════════
# Trust Score Integration
# ═══════════════════════════════════════════════════════════════

class TestTrustScoreIntegration:
    
    def test_high_trust_gets_mercy(self, validation_service, test_db):
        """High trust score should apply mercy"""
        # Create high-trust session
        session_manager = SessionManager(db=test_db)
        session_id = session_manager.create_session("high_trust", trust_score=0.95)
        
        result = validation_service.validate(
            text="My CPF is 123.456.789-09",
            session_id=session_id,
            profile="general",
        )
        
        # High trust → EDUCATE (not BLOCK)
        assert result.action == "EDUCATE"
        assert result.mercy_applied is True
    
    def test_low_trust_stricter(self, validation_service, test_db):
        """Low trust score should be stricter"""
        # Create low-trust session
        session_manager = SessionManager(db=test_db)
        session_id = session_manager.create_session("low_trust", trust_score=0.3)
        
        result = validation_service.validate(
            text="My CPF is 123.456.789-09",
            session_id=session_id,
            profile="general",
        )
        
        # Low trust → BLOCK
        assert result.action == "BLOCK"
        assert result.mercy_applied is False
    
    def test_trust_score_updated_on_violation(self, validation_service, test_db):
        """Trust score should decrease on violation"""
        session_manager = SessionManager(db=test_db)
        session_id = session_manager.create_session("test", trust_score=0.8)
        
        initial_trust = session_manager.get_trust_score(session_id)
        
        # Trigger violation
        validation_service.validate(
            text="My CPF is 123.456.789-09",
            session_id=session_id,
            profile="general",
        )
        
        final_trust = session_manager.get_trust_score(session_id)
        
        # Trust should decrease
        assert final_trust < initial_trust

# ═══════════════════════════════════════════════════════════════
# Ledger Integration
# ═══════════════════════════════════════════════════════════════

class TestLedgerIntegration:
    
    def test_verdict_logged_to_ledger(self, validation_service, test_session):
        """Every verdict should be logged to ledger"""
        result = validation_service.validate(
            text="Test input",
            session_id=test_session,
            profile="general",
        )
        
        # Check ledger was written
        ledger_writer = validation_service.ledger_writer
        entries = ledger_writer.query(verdict_id=result.verdict_id)
        
        assert len(entries) == 1
        assert entries[0]["verdict_id"] == result.verdict_id
        assert entries[0]["action"] == result.action
    
    def test_ledger_entry_immutable(self, validation_service, test_session):
        """Ledger entries should be immutable (hash-verified)"""
        result = validation_service.validate(
            text="Test input",
            session_id=test_session,
            profile="general",
        )
        
        ledger_writer = validation_service.ledger_writer
        entries = ledger_writer.query(verdict_id=result.verdict_id)
        entry = entries[0]
        
        # Entry should have signature
        assert "signature" in entry
        assert "evidence_hash" in entry
        
        # Verify signature
        is_valid = ledger_writer.verify_signature(entry)
        assert is_valid is True

# ═══════════════════════════════════════════════════════════════
# Performance Tests
# ═══════════════════════════════════════════════════════════════

class TestPerformanceIntegration:
    
    def test_latency_under_50ms(self, validation_service, test_session):
        """p99 latency should be under 50ms"""
        latencies = []
        
        for i in range(100):
            start = time.time()
            
            validation_service.validate(
                text=f"Test message {i}",
                session_id=test_session,
                profile="general",
            )
            
            latencies.append((time.time() - start) * 1000)
        
        # Calculate p99
        latencies.sort()
        p99 = latencies[98]
        
        assert p99 < 50, f"p99 latency: {p99:.2f}ms (expected < 50ms)"
    
    def test_batch_faster_than_individual(self, validation_service, test_session):
        """Batch processing should be faster than individual calls"""
        inputs = [f"Test message {i}" for i in range(100)]
        
        # Individual calls
        start_individual = time.time()
        for text in inputs:
            validation_service.validate(
                text=text,
                session_id=test_session,
                profile="general",
            )
        time_individual = time.time() - start_individual
        
        # Batch call
        start_batch = time.time()
        validation_service.validate_batch(
            inputs=[{"id": str(i), "text": text} for i, text in enumerate(inputs)],
            session_id=test_session,
            profile="general",
        )
        time_batch = time.time() - start_batch
        
        # Batch should be at least 2x faster
        assert time_batch < time_individual / 2

# ═══════════════════════════════════════════════════════════════
# Error Handling
# ═══════════════════════════════════════════════════════════════

class TestErrorHandling:
    
    def test_invalid_session_id(self, validation_service):
        """Invalid session ID should return error"""
        with pytest.raises(ValueError, match="Session not found"):
            validation_service.validate(
                text="Test",
                session_id="nonexistent_session",
                profile="general",
            )
    
    def test_invalid_profile(self, validation_service, test_session):
        """Invalid profile should return error"""
        with pytest.raises(ValueError, match="Profile not found"):
            validation_service.validate(
                text="Test",
                session_id=test_session,
                profile="nonexistent_profile",
            )
    
    def test_kernel_timeout_handled(self, validation_service, test_session):
        """Kernel timeout should be handled gracefully"""
        # Very large input (should timeout)
        huge_input = "A" * 10_000_000  # 10MB
        
        with pytest.raises(TimeoutError):
            validation_service.validate(
                text=huge_input,
                session_id=test_session,
                profile="general",
            )
    
    def test_database_error_handled(self, validation_service, test_session):
        """Database errors should be handled gracefully"""
        with patch.object(validation_service.session_manager, 'get_trust_score', side_effect=Exception("DB error")):
            with pytest.raises(Exception, match="DB error"):
                validation_service.validate(
                    text="Test",
                    session_id=test_session,
                    profile="general",
                )