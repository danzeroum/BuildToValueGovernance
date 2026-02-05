"""
Testes para LLM Async Client & Fallback Orchestrator.

Coverage: Circuit breaker, retry logic, async operations.
"""

import pytest
import asyncio
import time
import sys
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch

# Fix imports
sys.path.insert(0, str(Path(__file__).parent))

from python.buildtovalue.intelligence.llm_async_client import (
    LLMAsyncClient,
    LLMRequest,
    LLMResponse,
    CircuitBreaker,
    CircuitState,
    RetryStrategy,
    LLMCircuitOpenError,
    LLMTimeoutError
)
from python.buildtovalue.intelligence.llm_fallback import (
    LLMFallbackOrchestrator,
    FallbackPriority
)

# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def circuit_breaker():
    """Circuit breaker para testes."""
    return CircuitBreaker(failure_threshold=3, timeout=1.0)

@pytest.fixture
def retry_strategy():
    """Retry strategy para testes."""
    return RetryStrategy(max_retries=3, backoff_base=1.5)

@pytest.fixture
async def llm_client(circuit_breaker, retry_strategy):
    """Cliente LLM mock."""
    client = LLMAsyncClient(
        api_key="test_key",
        timeout=5.0,
        circuit_breaker=circuit_breaker,
        retry_strategy=retry_strategy
    )
    yield client
    await client.close()

@pytest.fixture
def sample_request():
    """Request de teste."""
    return LLMRequest(
        prompt="Test prompt",
        max_tokens=50,
        temperature=0.7,
        model="gpt-4"
    )

# ═══════════════════════════════════════════════════════════════════════════
# TESTES CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestCircuitBreaker:
    """Testes do circuit breaker."""

    async def test_circuit_starts_closed(self, circuit_breaker):
        """Circuit deve começar CLOSED."""
        assert circuit_breaker.state == CircuitState.CLOSED

    async def test_circuit_opens_after_threshold(self, circuit_breaker):
        """Circuit abre após threshold de falhas."""
        async def failing_func():
            raise Exception("Simulated failure")

        # Executa até threshold (3 falhas)
        for i in range(3):
            with pytest.raises(Exception):
                await circuit_breaker.call(failing_func)

        # Deve estar OPEN
        assert circuit_breaker.state == CircuitState.OPEN
        assert circuit_breaker.failure_count == 3

    async def test_circuit_rejects_when_open(self, circuit_breaker):
        """Circuit OPEN rejeita requests."""
        # Força para OPEN
        circuit_breaker.state = CircuitState.OPEN
        circuit_breaker.failure_count = 5

        async def dummy_func():
            return "success"

        # Deve rejeitar
        with pytest.raises(LLMCircuitOpenError):
            await circuit_breaker.call(dummy_func)

    async def test_circuit_closes_on_success(self, circuit_breaker):
        """Circuit fecha após sucesso em HALF_OPEN."""
        circuit_breaker.state = CircuitState.HALF_OPEN

        async def success_func():
            return "success"

        await circuit_breaker.call(success_func)

        assert circuit_breaker.state == CircuitState.CLOSED

# ═══════════════════════════════════════════════════════════════════════════
# TESTES RETRY STRATEGY
# ═══════════════════════════════════════════════════════════════════════════

class TestRetryStrategy:
    """Testes da estratégia de retry."""

    def test_should_retry_on_timeout(self, retry_strategy):
        """Deve fazer retry em timeout."""
        assert retry_strategy.should_retry(0, LLMTimeoutError("timeout"))

    def test_should_not_retry_on_circuit_open(self, retry_strategy):
        """Não deve fazer retry se circuit está aberto."""
        assert not retry_strategy.should_retry(
            0,
            LLMCircuitOpenError("circuit open")
        )

    def test_should_not_retry_after_max(self, retry_strategy):
        """Não deve fazer retry após max_retries."""
        assert not retry_strategy.should_retry(
            retry_strategy.max_retries,
            Exception("error")
        )

    def test_exponential_backoff(self, retry_strategy):
        """Delay deve crescer exponencialmente."""
        retry_strategy.jitter = False  # Desabilita jitter para teste determinístico

        delay0 = retry_strategy.get_delay(0)
        delay1 = retry_strategy.get_delay(1)
        delay2 = retry_strategy.get_delay(2)

        # Deve crescer exponencialmente
        assert delay0 == 1.5 ** 0  # 1.0
        assert delay1 == 1.5 ** 1  # 1.5
        assert delay2 == 1.5 ** 2  # 2.25

# ═══════════════════════════════════════════════════════════════════════════
# TESTES SIMPLIFICADOS (Sem HTTP real)
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestLLMAsyncClientSimplified:
    """Testes simplificados do cliente LLM."""

    async def test_client_initialization(self):
        """Cliente deve inicializar corretamente."""
        client = LLMAsyncClient(
            api_key="test_key",
            timeout=5.0
        )

        assert client.api_key == "test_key"
        assert client.timeout == 5.0
        assert client.circuit_breaker is not None

        await client.close()

    async def test_cache_key_generation(self):
        """Cache key deve ser consistente."""
        client = LLMAsyncClient(api_key="test")

        request1 = LLMRequest(prompt="Test", max_tokens=10)
        request2 = LLMRequest(prompt="Test", max_tokens=10)
        request3 = LLMRequest(prompt="Different", max_tokens=10)

        key1 = client._get_cache_key(request1)
        key2 = client._get_cache_key(request2)
        key3 = client._get_cache_key(request3)

        # Mesmos requests devem ter mesma key
        assert key1 == key2
        # Requests diferentes devem ter keys diferentes
        assert key1 != key3

        await client.close()

# ═══════════════════════════════════════════════════════════════════════════
# TESTES FALLBACK ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
class TestFallbackOrchestrator:
    """Testes do orchestrator de fallback."""

    async def test_orchestrator_starts_and_stops(self):
        """Orchestrator deve iniciar e parar corretamente."""
        # Mock client
        class MockClient:
            async def complete(self, *args, **kwargs):
                return LLMResponse("test", "mock", 10, 1.0)
            async def close(self):
                pass

        mock_client = MockClient()
        orchestrator = LLMFallbackOrchestrator(
            mock_client,
            worker_count=2
        )

        await orchestrator.start()
        assert orchestrator.running
        assert len(orchestrator.workers) == 2

        await orchestrator.stop()
        assert not orchestrator.running
        assert len(orchestrator.workers) == 0

    async def test_task_submission(self):
        """Deve aceitar tasks."""
        class MockClient:
            async def complete(self, *args, **kwargs):
                return LLMResponse("test", "mock", 10, 1.0)
            async def close(self):
                pass

        mock_client = MockClient()
        orchestrator = LLMFallbackOrchestrator(mock_client)
        await orchestrator.start()

        try:
            request = LLMRequest(prompt="Test", max_tokens=10)
            accepted = await orchestrator.submit_fallback(
                request,
                priority=FallbackPriority.HIGH
            )

            assert accepted
            assert orchestrator.metrics['tasks_submitted'] == 1

        finally:
            await orchestrator.stop()

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
