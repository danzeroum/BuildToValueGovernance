"""
Testes para Timing Attack Protection.

Coverage: Constant-time ops, response normalization, rate limiting.
"""

import pytest
import time
import sys
from pathlib import Path

# Fix import
sys.path.insert(0, str(Path(__file__).parent))

from buildtovalue.governance.timing_protection import (
    ConstantTimeOps,
    ResponseTimeNormalizer,
    ResponseTimeConfig,
    RateLimiter,
    RateLimitConfig,
    TimingSafeErrorHandler,
    add_timing_jitter,
    secure_random_delay
)


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def ct_ops():
    """Constant-time operations."""
    return ConstantTimeOps()


@pytest.fixture
def normalizer():
    """Response time normalizer."""
    config = ResponseTimeConfig(
        min_time_ms=10,
        max_time_ms=50,
        target_time_ms=20,
        jitter_enabled=False  # Desabilita para testes determinísticos
    )
    return ResponseTimeNormalizer(config)


@pytest.fixture
def rate_limiter():
    """Rate limiter."""
    config = RateLimitConfig(
        max_requests=5,
        window_seconds=1,
        jitter_enabled=False
    )
    return RateLimiter(config)


# ═══════════════════════════════════════════════════════════════════════════
# TESTES CONSTANT-TIME OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════

class TestConstantTimeOps:
    """Testes de operações constant-time."""

    def test_compare_strings_equal(self, ct_ops):
        """Compara strings iguais."""
        assert ct_ops.compare_strings("test", "test")
        assert ct_ops.compare_strings("", "")

    def test_compare_strings_different(self, ct_ops):
        """Compara strings diferentes."""
        assert not ct_ops.compare_strings("test", "test2")
        assert not ct_ops.compare_strings("abc", "def")

    def test_compare_strings_different_length(self, ct_ops):
        """Compara strings de tamanho diferente."""
        assert not ct_ops.compare_strings("short", "longer")
        assert not ct_ops.compare_strings("a", "")

    def test_compare_bytes_equal(self, ct_ops):
        """Compara bytes iguais."""
        assert ct_ops.compare_bytes(b"test", b"test")
        assert ct_ops.compare_bytes(b"", b"")

    def test_compare_bytes_different(self, ct_ops):
        """Compara bytes diferentes."""
        assert not ct_ops.compare_bytes(b"test", b"test2")
        assert not ct_ops.compare_bytes(b"abc", b"def")

    def test_select_constant_time(self, ct_ops):
        """Seleção constant-time."""
        assert ct_ops.select_constant_time(True, "yes", "no") == "yes"
        assert ct_ops.select_constant_time(False, "yes", "no") == "no"

    def test_constant_time_range_check(self, ct_ops):
        """Range check constant-time."""
        assert ct_ops.constant_time_range_check(5, 1, 10)
        assert ct_ops.constant_time_range_check(1, 1, 10)
        assert ct_ops.constant_time_range_check(10, 1, 10)
        assert not ct_ops.constant_time_range_check(0, 1, 10)
        assert not ct_ops.constant_time_range_check(11, 1, 10)


    def constant_time_range_check(value: int, min_val: int, max_val: int) -> bool:
        """
        Verifica se valor está em range (constant-time).

        Args:
            value: Valor a verificar
            min_val: Mínimo (inclusivo)
            max_val: Máximo (inclusivo)

        Returns:
            True se value em [min_val, max_val]
        """
        # Evaluate both conditions (no short-circuit)
        above_min = value >= min_val
        below_max = value <= max_val
        # Force both to be evaluated by combining results
        result_a = above_min
        result_b = below_max
        return result_a and result_b


# ═══════════════════════════════════════════════════════════════════════════
# TESTES RESPONSE TIME NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════

class TestResponseTimeNormalization:
    """Testes de normalização de tempo de resposta."""

    def test_normalizer_fast_function(self, normalizer):
        """Normaliza função rápida."""

        @normalizer.normalize
        def fast_func():
            return "result"

        start = time.perf_counter()
        result = fast_func()
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert result == "result"
        # Deve levar ~20ms (target_time_ms)
        assert 18 <= elapsed_ms <= 25  # Tolerância de ±2ms

    def test_normalizer_slow_function(self, normalizer):
        """Normaliza função lenta (não adiciona padding se já passou target)."""

        @normalizer.normalize
        def slow_func():
            time.sleep(0.03)  # 30ms
            return "result"

        start = time.perf_counter()
        result = slow_func()
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert result == "result"
        # Deve levar ~30ms (já ultrapassou target de 20ms)
        assert 28 <= elapsed_ms <= 35

    def test_normalizer_with_exception(self, normalizer):
        """Normaliza função que levanta exceção."""

        @normalizer.normalize
        def failing_func():
            raise ValueError("Test error")

        start = time.perf_counter()
        with pytest.raises(ValueError, match="Test error"):
            failing_func()
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Mesmo com erro, deve normalizar tempo
        assert 18 <= elapsed_ms <= 25

    def test_normalizer_metrics(self, normalizer):
        """Rastreia métricas."""

        @normalizer.normalize
        def func():
            return "ok"

        # Executa 3 vezes
        for _ in range(3):
            func()

        metrics = normalizer.get_metrics()
        assert metrics['requests_normalized'] == 3
        assert metrics['avg_padding_ms'] > 0


# ═══════════════════════════════════════════════════════════════════════════
# TESTES RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════

class TestRateLimiting:
    """Testes de rate limiting."""

    def test_rate_limit_allows_within_limit(self, rate_limiter):
        """Permite requests dentro do limite."""
        key = "test_user"

        # Deve permitir 5 requests (limite)
        for i in range(5):
            assert rate_limiter.check_rate_limit(key), f"Request {i} should be allowed"

    def test_rate_limit_blocks_over_limit(self, rate_limiter):
        """Bloqueia requests acima do limite."""
        key = "test_user"

        # Consome limite (5 requests)
        for _ in range(5):
            rate_limiter.check_rate_limit(key)

        # Sexto request deve ser bloqueado
        assert not rate_limiter.check_rate_limit(key)

    def test_rate_limit_resets_after_window(self, rate_limiter):
        """Reset após window expirar."""
        key = "test_user"

        # Consome limite
        for _ in range(5):
            rate_limiter.check_rate_limit(key)

        # Aguarda window expirar
        time.sleep(1.1)

        # Deve permitir novamente
        assert rate_limiter.check_rate_limit(key)

    def test_rate_limit_per_key(self, rate_limiter):
        """Rate limit é por chave."""
        # User 1 consome limite
        for _ in range(5):
            rate_limiter.check_rate_limit("user1")

        # User 2 ainda pode fazer requests
        assert rate_limiter.check_rate_limit("user2")

    def test_retry_after(self, rate_limiter):
        """Calcula retry-after corretamente."""
        key = "test_user"

        # Consome limite
        for _ in range(5):
            rate_limiter.check_rate_limit(key)

        # Retry-after deve ser ~1s (window size)
        retry_after = rate_limiter.get_retry_after(key)
        assert 0 <= retry_after <= 1.1

    def test_rate_limit_metrics(self, rate_limiter):
        """Rastreia métricas."""
        # 3 permitidos + 2 bloqueados
        for _ in range(3):
            rate_limiter.check_rate_limit("user1")

        for _ in range(5):
            rate_limiter.check_rate_limit("user2")

        for _ in range(2):
            rate_limiter.check_rate_limit("user2")  # Bloqueados

        metrics = rate_limiter.get_metrics()
        assert metrics['requests_allowed'] == 8
        assert metrics['requests_denied'] == 2


# ═══════════════════════════════════════════════════════════════════════════
# TESTES TIMING-SAFE ERROR HANDLER
# ═══════════════════════════════════════════════════════════════════════════

class TestTimingSafeErrorHandler:
    """Testes de error handler timing-safe."""

    def test_handle_error_generic_response(self):
        """Retorna resposta genérica."""
        handler = TimingSafeErrorHandler()

        error = ValueError("Sensitive error details")
        response = handler.handle_error(error)

        assert not response['success']
        assert 'Sensitive' not in response['error']  # Não vaza detalhes
        assert response['error'] == "Operation failed"

    def test_handle_error_timing(self):
        """Erros levam tempo similar."""
        handler = TimingSafeErrorHandler()

        # Erro 1
        start1 = time.perf_counter()
        handler.handle_error(ValueError("Error 1"))
        time1 = time.perf_counter() - start1

        # Erro 2 (diferente)
        start2 = time.perf_counter()
        handler.handle_error(KeyError("Different error"))
        time2 = time.perf_counter() - start2

        # Tempos devem ser similares (±50% tolerância)
        time_diff = abs(time1 - time2) / max(time1, time2)
        assert time_diff < 0.5


# ═══════════════════════════════════════════════════════════════════════════
# TESTES UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

class TestUtilities:
    """Testes de funções utilitárias."""

    def test_add_timing_jitter(self):
        """Adiciona jitter ao delay."""
        base = 100.0

        # Executa 10 vezes
        delays = [add_timing_jitter(base, 0.2) for _ in range(10)]

        # Todos devem estar em ±20% do base
        for delay in delays:
            assert 80 <= delay <= 120

        # Devem ser diferentes (não todos iguais)
        assert len(set(delays)) > 1

    def test_secure_random_delay(self):
        """Delay aleatório seguro."""
        start = time.perf_counter()
        secure_random_delay(10, 20)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Deve estar entre 10-20ms
        assert 8 <= elapsed_ms <= 25  # Tolerância para ambiente de teste


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
