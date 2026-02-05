"""
LLM Async Client v2.0 - Non-blocking LLM fallback.

Implementa:
- Async HTTP client (httpx)
- Circuit breaker pattern
- Retry logic com exponential backoff
- Streaming support
- Zero blocking no hot path

Security Level: HIGH
Gate: G2 (Async Safety Review)
"""

import asyncio
import logging
import time
from typing import Optional, Dict, Any, List, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import httpx

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT = 5.0  # 5 segundos
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_BASE = 2.0  # Exponential backoff base
CIRCUIT_BREAKER_THRESHOLD = 5  # Falhas consecutivas para abrir circuito
CIRCUIT_BREAKER_TIMEOUT = 60  # Segundos até tentar novamente


# ═══════════════════════════════════════════════════════════════════════════
# TIPOS
# ═══════════════════════════════════════════════════════════════════════════

class CircuitState(Enum):
    """Estado do circuit breaker."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class LLMRequest:
    """Request para LLM."""
    prompt: str
    max_tokens: int = 100
    temperature: float = 0.7
    model: str = "gpt-4"
    stream: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Response do LLM."""
    content: str
    model: str
    tokens_used: int
    latency_ms: float
    cached: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CircuitBreakerStats:
    """Estatísticas do circuit breaker."""
    state: CircuitState
    failure_count: int
    success_count: int
    last_failure_time: Optional[float]
    last_state_change: float
    total_requests: int


# ═══════════════════════════════════════════════════════════════════════════
# EXCEÇÕES
# ═══════════════════════════════════════════════════════════════════════════

class LLMError(Exception):
    """Erro base LLM."""
    pass


class LLMTimeoutError(LLMError):
    """Timeout na chamada LLM."""
    pass


class LLMCircuitOpenError(LLMError):
    """Circuit breaker aberto."""
    pass


class LLMRateLimitError(LLMError):
    """Rate limit excedido."""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════════════════

class CircuitBreaker:
    """
    Circuit Breaker pattern para LLM calls.

    States:
    - CLOSED: Normal operation
    - OPEN: Too many failures, rejecting requests
    - HALF_OPEN: Testing if service recovered
    """

    def __init__(
            self,
            failure_threshold: int = CIRCUIT_BREAKER_THRESHOLD,
            timeout: float = CIRCUIT_BREAKER_TIMEOUT
    ):
        """
        Inicializa circuit breaker.

        Args:
            failure_threshold: Falhas consecutivas para abrir
            timeout: Segundos até tentar HALF_OPEN
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.last_state_change = time.time()
        self.total_requests = 0

    async def call(self, func, *args, **kwargs):
        """
        Executa função através do circuit breaker.

        Args:
            func: Função async a executar
            *args, **kwargs: Argumentos para função

        Returns:
            Resultado da função

        Raises:
            LLMCircuitOpenError: Se circuito está aberto
        """
        self.total_requests += 1

        # Verifica estado
        if self.state == CircuitState.OPEN:
            # Verifica se timeout expirou
            if self._should_attempt_reset():
                logger.info("Circuit breaker: OPEN → HALF_OPEN (attempting recovery)")
                self.state = CircuitState.HALF_OPEN
                self.last_state_change = time.time()
            else:
                raise LLMCircuitOpenError(
                    f"Circuit breaker is OPEN (failures: {self.failure_count})"
                )

        try:
            # Executa função
            result = await func(*args, **kwargs)

            # Sucesso
            self._on_success()
            return result

        except Exception as e:
            # Falha
            self._on_failure()
            raise

    def _on_success(self):
        """Callback de sucesso."""
        self.success_count += 1

        if self.state == CircuitState.HALF_OPEN:
            # Recuperado!
            logger.info("Circuit breaker: HALF_OPEN → CLOSED (service recovered)")
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_state_change = time.time()

        # Reset failure count no estado CLOSED
        if self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def _on_failure(self):
        """Callback de falha."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.state == CircuitState.HALF_OPEN:
            # Falhou no teste, volta para OPEN
            logger.warning("Circuit breaker: HALF_OPEN → OPEN (recovery failed)")
            self.state = CircuitState.OPEN
            self.last_state_change = time.time()

        elif self.state == CircuitState.CLOSED:
            # Verifica threshold
            if self.failure_count >= self.failure_threshold:
                logger.error(
                    f"Circuit breaker: CLOSED → OPEN "
                    f"(threshold {self.failure_threshold} reached)"
                )
                self.state = CircuitState.OPEN
                self.last_state_change = time.time()

    def _should_attempt_reset(self) -> bool:
        """Verifica se deve tentar reset (OPEN → HALF_OPEN)."""
        if self.last_failure_time is None:
            return False

        elapsed = time.time() - self.last_failure_time
        return elapsed >= self.timeout

    def get_stats(self) -> CircuitBreakerStats:
        """Retorna estatísticas."""
        return CircuitBreakerStats(
            state=self.state,
            failure_count=self.failure_count,
            success_count=self.success_count,
            last_failure_time=self.last_failure_time,
            last_state_change=self.last_state_change,
            total_requests=self.total_requests
        )

    def reset(self):
        """Reset manual (para testes)."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_state_change = time.time()


# ═══════════════════════════════════════════════════════════════════════════
# RETRY LOGIC
# ═══════════════════════════════════════════════════════════════════════════

class RetryStrategy:
    """
    Estratégia de retry com exponential backoff.

    Formula: delay = base^attempt * (1 + jitter)
    """

    def __init__(
            self,
            max_retries: int = DEFAULT_MAX_RETRIES,
            backoff_base: float = DEFAULT_BACKOFF_BASE,
            max_delay: float = 30.0,
            jitter: bool = True
    ):
        """
        Inicializa estratégia de retry.

        Args:
            max_retries: Máximo de tentativas
            backoff_base: Base exponencial (default: 2.0)
            max_delay: Delay máximo em segundos
            jitter: Adicionar jitter para evitar thundering herd
        """
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.max_delay = max_delay
        self.jitter = jitter

    def should_retry(self, attempt: int, exception: Exception) -> bool:
        """
        Decide se deve fazer retry.

        Args:
            attempt: Número da tentativa (0-indexed)
            exception: Exceção que ocorreu

        Returns:
            True se deve tentar novamente
        """
        # Não retry se excedeu max_retries
        if attempt >= self.max_retries:
            return False

        # Não retry em erros não-transientes
        if isinstance(exception, (LLMCircuitOpenError, ValueError)):
            return False

        # Retry em timeouts e rate limits
        if isinstance(exception, (LLMTimeoutError, LLMRateLimitError, httpx.TimeoutException)):
            return True

        # Retry em erros HTTP 5xx
        if isinstance(exception, httpx.HTTPStatusError):
            return 500 <= exception.response.status_code < 600

        # Default: retry em erros de rede
        if isinstance(exception, (httpx.NetworkError, httpx.ConnectError)):
            return True

        return False

    def get_delay(self, attempt: int) -> float:
        """
        Calcula delay antes do próximo retry.

        Args:
            attempt: Número da tentativa (0-indexed)

        Returns:
            Delay em segundos
        """
        # Exponential backoff
        delay = self.backoff_base ** attempt

        # Adiciona jitter (±25%)
        if self.jitter:
            import random
            jitter_factor = 1.0 + (random.random() - 0.5) * 0.5
            delay *= jitter_factor

        # Limita ao max_delay
        return min(delay, self.max_delay)


# ═══════════════════════════════════════════════════════════════════════════
# LLM ASYNC CLIENT
# ═══════════════════════════════════════════════════════════════════════════

class LLMAsyncClient:
    """
    Cliente assíncrono para LLM com circuit breaker e retry.

    Features:
    - Async HTTP (httpx)
    - Circuit breaker pattern
    - Exponential backoff retry
    - Streaming support
    - Request/response caching
    - Timeout configurável
    """

    def __init__(
            self,
            api_key: str,
            base_url: str = "https://api.openai.com/v1",
            timeout: float = DEFAULT_TIMEOUT,
            max_retries: int = DEFAULT_MAX_RETRIES,
            circuit_breaker: Optional[CircuitBreaker] = None,
            retry_strategy: Optional[RetryStrategy] = None
    ):
        """
        Inicializa cliente LLM.

        Args:
            api_key: API key
            base_url: Base URL da API
            timeout: Timeout padrão em segundos
            max_retries: Máximo de retries
            circuit_breaker: Circuit breaker customizado (opcional)
            retry_strategy: Estratégia de retry customizada (opcional)
        """
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout

        # Circuit breaker
        self.circuit_breaker = circuit_breaker or CircuitBreaker()

        # Retry strategy
        self.retry_strategy = retry_strategy or RetryStrategy(max_retries=max_retries)

        # HTTP client (async)
        self.client = httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(timeout),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
        )

        # Cache simples (LRU em produção)
        self._cache: Dict[str, LLMResponse] = {}

        # Métricas
        self.metrics = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_failed': 0,
            'requests_cached': 0,
            'retries_total': 0,
            'circuit_breaks': 0,
        }

    async def complete(
            self,
            request: LLMRequest,
            use_cache: bool = True
    ) -> LLMResponse:
        """
        Executa completion (non-streaming).

        Args:
            request: LLM request
            use_cache: Usar cache (default: True)

        Returns:
            LLM response

        Raises:
            LLMError: Em caso de falha
        """
        start_time = time.perf_counter()
        self.metrics['requests_total'] += 1

        # Verifica cache
        if use_cache:
            cache_key = self._get_cache_key(request)
            if cache_key in self._cache:
                logger.debug(f"Cache hit: {cache_key[:16]}...")
                self.metrics['requests_cached'] += 1
                cached_response = self._cache[cache_key]
                cached_response.cached = True
                return cached_response

        # Executa com circuit breaker e retry
        try:
            response = await self._execute_with_retry(request)

            # Adiciona ao cache
            if use_cache:
                self._cache[cache_key] = response

            self.metrics['requests_success'] += 1
            return response

        except LLMCircuitOpenError:
            self.metrics['circuit_breaks'] += 1
            raise

        except Exception as e:
            self.metrics['requests_failed'] += 1
            logger.error(f"LLM request failed: {e}")
            raise LLMError(f"Request failed: {e}") from e

    async def complete_stream(
            self,
            request: LLMRequest
    ) -> AsyncIterator[str]:
        """
        Executa completion com streaming.

        Args:
            request: LLM request

        Yields:
            Chunks de texto
        """
        request.stream = True

        # Streaming não usa cache
        async for chunk in self._execute_stream_with_retry(request):
            yield chunk

    async def _execute_with_retry(self, request: LLMRequest) -> LLMResponse:
        """Executa request com retry logic."""
        attempt = 0
        last_exception = None

        while attempt <= self.retry_strategy.max_retries:
            try:
                # Executa através do circuit breaker
                return await self.circuit_breaker.call(
                    self._execute_request,
                    request
                )

            except Exception as e:
                last_exception = e

                # Decide se faz retry
                if not self.retry_strategy.should_retry(attempt, e):
                    logger.warning(f"Not retrying: {type(e).__name__}")
                    raise

                # Calcula delay
                delay = self.retry_strategy.get_delay(attempt)

                logger.warning(
                    f"Retry {attempt + 1}/{self.retry_strategy.max_retries} "
                    f"after {delay:.2f}s (error: {type(e).__name__})"
                )

                self.metrics['retries_total'] += 1

                # Aguarda antes do próximo retry
                await asyncio.sleep(delay)
                attempt += 1

        # Excedeu max retries
        raise LLMError(
            f"Max retries exceeded ({self.retry_strategy.max_retries})"
        ) from last_exception

    async def _execute_request(self, request: LLMRequest) -> LLMResponse:
        """Executa request HTTP (sem retry)."""
        start_time = time.perf_counter()

        # Prepara payload
        payload = {
            "model": request.model,
            "messages": [{"role": "user", "content": request.prompt}],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "stream": False
        }

        try:
            # Executa request
            response = await self.client.post("/chat/completions", json=payload)
            response.raise_for_status()

            # Parse response
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            tokens_used = data["usage"]["total_tokens"]

            latency_ms = (time.perf_counter() - start_time) * 1000

            return LLMResponse(
                content=content,
                model=request.model,
                tokens_used=tokens_used,
                latency_ms=latency_ms,
                metadata={"response_id": data.get("id")}
            )

        except httpx.TimeoutException as e:
            raise LLMTimeoutError(f"Request timeout after {self.timeout}s") from e

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise LLMRateLimitError("Rate limit exceeded") from e
            raise LLMError(f"HTTP {e.response.status_code}") from e

    async def _execute_stream_with_retry(
            self,
            request: LLMRequest
    ) -> AsyncIterator[str]:
        """Executa streaming com retry."""
        attempt = 0

        while attempt <= self.retry_strategy.max_retries:
            try:
                async for chunk in self._execute_stream_request(request):
                    yield chunk
                return  # Sucesso

            except Exception as e:
                if not self.retry_strategy.should_retry(attempt, e):
                    raise

                delay = self.retry_strategy.get_delay(attempt)
                logger.warning(f"Retry stream {attempt + 1} after {delay:.2f}s")
                await asyncio.sleep(delay)
                attempt += 1

        raise LLMError("Max retries exceeded for stream")

    async def _execute_stream_request(
            self,
            request: LLMRequest
    ) -> AsyncIterator[str]:
        """Executa streaming request."""
        payload = {
            "model": request.model,
            "messages": [{"role": "user", "content": request.prompt}],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "stream": True
        }

        async with self.client.stream("POST", "/chat/completions", json=payload) as response:
            response.raise_for_status()

            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data_str = line[6:]  # Remove "data: "

                    if data_str.strip() == "[DONE]":
                        break

                    try:
                        import json
                        data = json.loads(data_str)
                        delta = data["choices"][0]["delta"]

                        if "content" in delta:
                            yield delta["content"]
                    except (json.JSONDecodeError, KeyError):
                        continue

    def _get_cache_key(self, request: LLMRequest) -> str:
        """Gera chave de cache para request."""
        import hashlib

        # Hash do prompt + parâmetros
        content = f"{request.prompt}|{request.model}|{request.max_tokens}|{request.temperature}"

        # Usa blake2b (disponível no Python padrão)
        # BLAKE3 requer biblioteca externa: pip install blake3
        return hashlib.blake2b(content.encode()).hexdigest()

    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas."""
        return {
            **self.metrics,
            'circuit_breaker': self.circuit_breaker.get_stats().__dict__,
            'success_rate': (
                    self.metrics['requests_success'] /
                    max(self.metrics['requests_total'], 1)
            ),
            'cache_hit_rate': (
                    self.metrics['requests_cached'] /
                    max(self.metrics['requests_total'], 1)
            )
        }

    async def close(self):
        """Fecha client HTTP."""
        await self.client.aclose()

    async def __aenter__(self):
        """Context manager enter."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.close()
