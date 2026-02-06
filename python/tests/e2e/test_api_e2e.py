
"""
End-to-end tests for BuildToValue API.

These tests run against a real deployment (Docker Compose)
and verify the entire system end-to-end.

Setup:
  docker-compose -f docker-compose.test.yml up -d
  pytest tests/e2e/
"""

import pytest
import requests
import time
from typing import Dict, Any

# ═══════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════

API_BASE_URL = "http://localhost:8000/v2"
API_KEY = "test_api_key_12345"

@pytest.fixture(scope="module")
def api_client():
    """API client with authentication"""
    class APIClient:
        def __init__(self):
            self.base_url = API_BASE_URL
            self.headers = {
                "X-API-Key": API_KEY,
                "Content-Type": "application/json",
            }
        
        def post(self, path: str, json: Dict[str, Any]) -> requests.Response:
            return requests.post(
                f"{self.base_url}{path}",
                headers=self.headers,
                json=json,
                timeout=10,
            )
        
        def get(self, path: str) -> requests.Response:
            return requests.get(
                f"{self.base_url}{path}",
                headers=self.headers,
                timeout=10,
            )
    
    return APIClient()

@pytest.fixture(scope="module", autouse=True)
def wait_for_api():
    """Wait for API to be ready"""
    for _ in range(30):
        try:
            response = requests.get(f"{API_BASE_URL}/health", timeout=2)
            if response.status_code == 200:
                print("\n✅ API is ready")
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    
    pytest.fail("❌ API did not start in time")

# ═══════════════════════════════════════════════════════════════
# Basic Validation E2E
# ═══════════════════════════════════════════════════════════════

class TestValidationE2E:
    
    def test_validate_clean_input_e2e(self, api_client):
        """Clean input should be allowed (E2E)"""
        response = api_client.post("/validate", json={
            "text": "Hello, how are you today?",
            "session_id": "e2e_session_123",
        })
        
        assert response.status_code == 200
        
        data = response.json()
        assert data["action"] == "ALLOW"
        assert data["confidence"] > 0.95
        assert "verdict_id" in data
        assert data["processing_time_ms"] < 100
    
    def test_validate_cpf_blocked_e2e(self, api_client):
        """CPF should be blocked (E2E)"""
        response = api_client.post("/validate", json={
            "text": "My CPF is 123.456.789-09",
            "session_id": "e2e_session_123",
        })
        
        assert response.status_code == 200
        
        data = response.json()
        assert data["action"] in ["BLOCK", "EDUCATE"]
        assert data["technical_evidence"]["finding_count"] == 1
        assert data["technical_evidence"]["has_pii"] is True
    
    def test_validate_healthcare_context_e2e(self, api_client):
        """Healthcare context should apply mercy (E2E)"""
        response = api_client.post("/validate", json={
            "text": "Patient CPF: 123.456.789-09",
            "session_id": "e2e_doctor_456",
            "profile": "healthcare",
            "context": {
                "domain": "medical_records",
                "user_role": "doctor",
            },
        })
        
        assert response.status_code == 200
        
        data = response.json()
        assert data["mercy_applied"] is True
        assert data["action"] != "BLOCK"

# ═══════════════════════════════════════════════════════════════
# Batch Validation E2E
# ═══════════════════════════════════════════════════════════════

class TestBatchValidationE2E:
    
    def test_batch_validate_e2e(self, api_client):
        """Batch validation should process multiple inputs (E2E)"""
        response = api_client.post("/validate/batch", json={
            "inputs": [
                {"id": "msg_001", "text": "Hello"},
                {"id": "msg_002", "text": "My CPF is 123.456.789-09"},
                {"id": "msg_003", "text": "Clean message"},
            ],
            "session_id": "e2e_batch_789",
        })
        
        assert response.status_code == 200
        
        data = response.json()
        assert "batch_id" in data
        assert len(data["results"]) == 3
        
        # Check individual results
        assert data["results"][0]["action"] == "ALLOW"
        assert data["results"]
        assert data["results"]

# ═══════════════════════════════════════════════════════════════
# Appeal Workflow E2E
# ═══════════════════════════════════════════════════════════════

class TestAppealWorkflowE2E:
    
    def test_full_appeal_workflow_e2e(self, api_client):
        """Test complete appeal workflow (E2E)"""
        # 1. Submit input that gets blocked
        validate_response = api_client.post("/validate", json={
            "text": "Test CPF: 123.456.789-09",
            "session_id": "e2e_appeal_test",
        })
        
        assert validate_response.status_code == 200
        verdict_id = validate_response.json()["verdict_id"]
        
        # 2. Submit appeal
        appeal_response = api_client.post("/appeals", json={
            "verdict_id": verdict_id,
            "reason": "This is a test CPF from ABNT standards",
        })
        
        assert appeal_response.status_code == 201
        appeal_id = appeal_response.json()["appeal_id"]
        
        # 3. Check appeal status
        status_response = api_client.get(f"/appeals/{appeal_id}")
        
        assert status_response.status_code == 200
        appeal_data = status_response.json()
        assert appeal_data["status"] in ["pending", "under_review"]
        assert appeal_data["verdict_id"] == verdict_id

# ═══════════════════════════════════════════════════════════════
# Session Management E2E
# ═══════════════════════════════════════════════════════════════

class TestSessionManagementE2E:
    
    def test_session_trust_score_e2e(self, api_client):
        """Trust score should update over time (E2E)"""
        session_id = "e2e_trust_test"
        
        # Get initial session info
        initial_response = api_client.get(f"/sessions/{session_id}")
        if initial_response.status_code == 404:
            # Create session by validating
            api_client.post("/validate", json={
                "text": "Initial message",
                "session_id": session_id,
            })
            initial_response = api_client.get(f"/sessions/{session_id}")
        
        initial_trust = initial_response.json()["trust_score"]
        
        # Trigger violation
        api_client.post("/validate", json={
            "text": "My CPF is 123.456.789-09",
            "session_id": session_id,
        })
        
        # Check trust score decreased
        final_response = api_client.get(f"/sessions/{session_id}")
        final_trust = final_response.json()["trust_score"]
        
        assert final_trust < initial_trust

# ═══════════════════════════════════════════════════════════════
# Performance E2E
# ═══════════════════════════════════════════════════════════════

class TestPerformanceE2E:
    
    def test_latency_slo_e2e(self, api_client):
        """p99 latency should meet SLO (< 50ms) (E2E)"""
        latencies = []
        
        for i in range(100):
            start = time.time()
            
            response = api_client.post("/validate", json={
                "text": f"Test message {i}",
                "session_id": "e2e_perf_test",
            })
            
            assert response.status_code == 200
            
            # Use server-reported latency
            latencies.append(response.json()["processing_time_ms"])
        
        latencies.sort()
        p99 = latencies[98]
        
        assert p99 < 50, f"❌ p99 latency: {p99:.2f}ms (SLO: < 50ms)"
        print(f"\n✅ p99 latency: {p99:.2f}ms (SLO: < 50ms)")
    
    def test_throughput_e2e(self, api_client):
        """System should handle 100 req/s (E2E)"""
        import concurrent.futures
        
        def make_request(i):
            return api_client.post("/validate", json={
                "text": f"Test {i}",
                "session_id": "e2e_throughput",
            })
        
        start = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, i) for i in range(100)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        elapsed = time.time() - start
        throughput = 100 / elapsed
        
        assert all(r.status_code == 200 for r in results)
        assert throughput > 100, f"❌ Throughput: {throughput:.2f} req/s (target: > 100 req/s)"
        print(f"\n✅ Throughput: {throughput:.2f} req/s")

# ═══════════════════════════════════════════════════════════════
# Security E2E
# ═══════════════════════════════════════════════════════════════

class TestSecurityE2E:
    
    def test_invalid_api_key_rejected_e2e(self, api_client):
        """Invalid API key should be rejected (E2E)"""
        response = requests.post(
            f"{API_BASE_URL}/validate",
            headers={
                "X-API-Key": "invalid_key",
                "Content-Type": "application/json",
            },
            json={"text": "Test", "session_id": "test"},
        )
        
        assert response.status_code == 401
    
    def test_rate_limiting_e2e(self, api_client):
        """Rate limiting should be enforced (E2E)"""
        # Make 1000+ requests rapidly
        for i in range(1100):
            response = api_client.post("/validate", json={
                "text": f"Spam {i}",
                "session_id": "e2e_rate_limit",
            })
            
            if response.status_code == 429:
                # Rate limit triggered
                assert "retry_after_seconds" in response.json()
                print(f"\n✅ Rate limit triggered after {i} requests")
                return
        
        pytest.fail("❌ Rate limit not triggered after 1100 requests")
    
    def test_sql_injection_prevented_e2e(self, api_client):
        """SQL injection should be prevented (E2E)"""
        response = api_client.post("/validate", json={
            "text": "'; DROP TABLE users; --",
            "session_id": "e2e_sql_injection",
        })
        
        # Should process normally (not crash)
        assert response.status_code == 200
        
        # Database should still work
        health = api_client.get("/health")
        assert health.status_code == 200
        assert health.json()["components"]["database"] == "healthy"

# ═══════════════════════════════════════════════════════════════
# Chaos Engineering E2E
# ═══════════════════════════════════════════════════════════════

@pytest.mark.chaos
class TestChaosEngineeringE2E:
    
    def test_database_failure_recovery_e2e(self, api_client):
        """System should recover from database failure (E2E)"""
        # TODO: Implement chaos testing with Chaos Mesh
        pytest.skip("Requires Chaos Mesh setup")
    
    def test_pod_kill_recovery_e2e(self, api_client):
        """System should recover from pod kill (E2E)"""
        pytest.skip("Requires Kubernetes setup")