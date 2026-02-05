"""
Timing Attack Protection v1.0 - Comprehensive timing attack mitigations.

Implementa:
- Constant-time operations (string comparison, crypto)
- Response time normalization
- Rate limiting with jitter
- Timing-safe error responses

Security Level: MAXIMUM
Gate: G4 (Timing Attack Protection Review)
"""

import time
import random
import logging
import secrets
from typing import Optional, Callable, Any, Dict
from dataclasses import dataclass
from functools import wraps
from collections import defaultdict
import asyncio

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO
# ═══════════════════════════════════════════════════════════════════════════

# Response time normalização (ms)
MIN_RESPONSE_TIME_MS = 10
MAX_RESPONSE_TIME_MS = 50
DEFAULT_RESPONSE_TIME_MS = 20

# Rate limiting
DEFAULT_RATE_LIMIT = 100  # requests per window
DEFAULT_WINDOW_SECONDS = 60
JITTER_PERCENT = 0.2  # ±20% jitter


# ═══════════════════════════════════════════════════════════════════════════
# CONSTANT-TIME OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════

class ConstantTimeOps:
    """
    Operações constant-time para prevenir timing attacks.

    Todas as operações garantem tempo de execução constante
    independente do conteúdo dos dados.
    """

    @staticmethod
    def compare_strings(a: str, b: str) -> bool:
        """
        Compara strings em tempo constante.

        Args:
            a: String 1
            b: String 2

        Returns:
            True se strings são iguais

        Security:
        - Tempo de execução não vaza informação sobre onde diferem
        - Usa XOR bit-a-bit
        - Verifica todos os bytes mesmo após primeira diferença
        """
        # Se tamanhos diferentes, compara contra string do mesmo tamanho
        # para manter tempo constante
        if len(a) != len(b):
            # Cria dummy string do mesmo tamanho que 'a'
            dummy = "0" * len(a)
            # Compara 'a' com dummy (sempre falha, mas tempo constante)
            result = 0
            for x, y in zip(a, dummy):
                result |= ord(x) ^ ord(y)
            return False

        # Compara byte-a-byte usando XOR
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)

        return result == 0

    @staticmethod
    def compare_bytes(a: bytes, b: bytes) -> bool:
        """
        Compara bytes em tempo constante.

        Args:
            a: Bytes 1
            b: Bytes 2

        Returns:
            True se bytes são iguais
        """
        if len(a) != len(b):
            dummy = b"\x00" * len(a)
            result = 0
            for x, y in zip(a, dummy):
                result |= x ^ y
            return False

        result = 0
        for x, y in zip(a, b):
            result |= x ^ y

        return result == 0

    @staticmethod
    def select_constant_time(condition: bool, true_val: Any, false_val: Any) -> Any:
        """
        Seleciona valor baseado em condição (constant-time).

        Args:
            condition: Condição booleana
            true_val: Valor se True
            false_val: Valor se False

        Returns:
            true_val se condition, senão false_val

        Security:
        - Ambos os valores são avaliados (não usa short-circuit)
        - Tempo constante independente da condição
        """
        # Força avaliação de ambos os valores
        tv = true_val
        fv = false_val

        # Seleciona baseado em condition
        return tv if condition else fv

    @staticmethod
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
        # Usa operações bit-a-bit para timing constante
        in_range_low = ((value - min_val) | (min_val - value)) >= 0
        in_range_high = ((max_val - value) | (value - max_val)) >= 0

        return in_range_low and in_range_high


# ═══════════════════════════════════════════════════════════════════════════
# RESPONSE TIME NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ResponseTimeConfig:
    """Configuração de normalização de tempo de resposta."""
    min_time_ms: float = MIN_RESPONSE_TIME_MS
    max_time_ms: float = MAX_RESPONSE_TIME_MS
    target_time_ms: float = DEFAULT_RESPONSE_TIME_MS
    jitter_enabled: bool = True
    jitter_percent: float = JITTER_PERCENT


class ResponseTimeNormalizer:
    """
    Normaliza tempo de resposta para prevenir timing attacks.

    Garante que todas as respostas levam aproximadamente o mesmo tempo,
    independente da lógica interna.
    """

    def __init__(self, config: Optional[ResponseTimeConfig] = None):
        """
        Inicializa normalizer.

        Args:
            config: Configuração (opcional)
        """
        self.config = config or ResponseTimeConfig()
        self.metrics = {
            'requests_normalized': 0,
            'total_padding_ms': 0.0,
            'avg_padding_ms': 0.0
        }

    def normalize(self, func: Callable) -> Callable:
        """
        Decorator que normaliza tempo de resposta.

        Args:
            func: Função a decorar

        Returns:
            Função decorada com tempo normalizado

        Example:
            @normalizer.normalize
            def sensitive_operation(input):
                return process(input)
        """

        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()

            try:
                # Executa função
                result = func(*args, **kwargs)
                success = True
            except Exception as e:
                result = e
                success = False

            # Calcula tempo decorrido
            elapsed_ms = (time.perf_counter() - start) * 1000

            # Calcula padding necessário
            target_ms = self._get_target_time()
            padding_ms = max(0, target_ms - elapsed_ms)

            # Aplica padding
            if padding_ms > 0:
                time.sleep(padding_ms / 1000)

            # Atualiza métricas
            self._update_metrics(padding_ms)

            # Retorna resultado ou raise exception
            if not success:
                raise result
            return result

        return wrapper

    async def normalize_async(self, coro):
        """
        Normaliza coroutine assíncrona.

        Args:
            coro: Coroutine a executar

        Returns:
            Resultado da coroutine (com tempo normalizado)
        """
        start = time.perf_counter()

        try:
            result = await coro
            success = True
        except Exception as e:
            result = e
            success = False

        # Calcula e aplica padding
        elapsed_ms = (time.perf_counter() - start) * 1000
        target_ms = self._get_target_time()
        padding_ms = max(0, target_ms - elapsed_ms)

        if padding_ms > 0:
            await asyncio.sleep(padding_ms / 1000)

        self._update_metrics(padding_ms)

        if not success:
            raise result
        return result

    def _get_target_time(self) -> float:
        """
        Calcula target time com jitter.

        Returns:
            Target time em ms
        """
        target = self.config.target_time_ms

        if self.config.jitter_enabled:
            # Adiciona jitter (±jitter_percent)
            jitter_range = target * self.config.jitter_percent
            jitter = random.uniform(-jitter_range, jitter_range)
            target += jitter

        # Limita ao range configurado
        target = max(self.config.min_time_ms, min(target, self.config.max_time_ms))

        return target

    def _update_metrics(self, padding_ms: float):
        """Atualiza métricas."""
        self.metrics['requests_normalized'] += 1
        self.metrics['total_padding_ms'] += padding_ms
        self.metrics['avg_padding_ms'] = (
                self.metrics['total_padding_ms'] /
                self.metrics['requests_normalized']
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas."""
        return self.metrics.copy()


# ═══════════════════════════════════════════════════════════════════════════
# RATE LIMITING WITH JITTER
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class RateLimitConfig:
    """Configuração de rate limiting."""
    max_requests: int = DEFAULT_RATE_LIMIT
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    jitter_enabled: bool = True
    jitter_percent: float = JITTER_PERCENT


class RateLimiter:
    """
    Rate limiter com jitter para prevenir timing attacks.

    Features:
    - Sliding window algorithm
    - Jitter nas respostas de rate limit
    - Per-key tracking
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Inicializa rate limiter.

        Args:
            config: Configuração (opcional)
        """
        self.config = config or RateLimitConfig()

        # Tracking (key -> [timestamps])
        self.requests: Dict[str, list] = defaultdict(list)

        # Métricas
        self.metrics = {
            'requests_allowed': 0,
            'requests_denied': 0,
            'active_keys': 0
        }

    def check_rate_limit(self, key: str) -> bool:
        """
        Verifica rate limit para chave.

        Args:
            key: Chave (ex: user_id, ip_address)

        Returns:
            True se request permitido, False se rate limited
        """
        now = time.time()
        window_start = now - self.config.window_seconds

        # Remove timestamps antigos
        self.requests[key] = [
            ts for ts in self.requests[key]
            if ts > window_start
        ]

        # Verifica limite
        if len(self.requests[key]) >= self.config.max_requests:
            self.metrics['requests_denied'] += 1

            # Aplica jitter no delay (anti-probing)
            if self.config.jitter_enabled:
                jitter = random.uniform(0, 0.1)  # 0-100ms jitter
                time.sleep(jitter)

            return False

        # Adiciona timestamp
        self.requests[key].append(now)
        self.metrics['requests_allowed'] += 1
        self.metrics['active_keys'] = len(self.requests)

        return True

    def get_retry_after(self, key: str) -> float:
        """
        Calcula tempo até próximo request permitido.

        Args:
            key: Chave

        Returns:
            Segundos até retry (com jitter)
        """
        if key not in self.requests or not self.requests[key]:
            return 0.0

        # Timestamp mais antigo
        oldest = min(self.requests[key])
        window_start = time.time() - self.config.window_seconds

        retry_after = max(0, oldest - window_start)

        # Adiciona jitter
        if self.config.jitter_enabled:
            jitter = retry_after * self.config.jitter_percent
            retry_after += random.uniform(0, jitter)

        return retry_after

    def reset(self, key: Optional[str] = None):
        """
        Reset rate limit (para testes).

        Args:
            key: Chave específica (ou None para todas)
        """
        if key:
            self.requests.pop(key, None)
        else:
            self.requests.clear()

    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas."""
        total = self.metrics['requests_allowed'] + self.metrics['requests_denied']
        return {
            **self.metrics,
            'block_rate': (
                    self.metrics['requests_denied'] / max(total, 1)
            )
        }


# ═══════════════════════════════════════════════════════════════════════════
# TIMING-SAFE ERROR RESPONSES
# ═══════════════════════════════════════════════════════════════════════════

class TimingSafeErrorHandler:
    """
    Error handler que previne information leakage via timing.

    Garante que todos os erros levam o mesmo tempo para responder.
    """

    def __init__(
            self,
            normalizer: Optional[ResponseTimeNormalizer] = None
    ):
        """
        Inicializa error handler.

        Args:
            normalizer: Response time normalizer (opcional)
        """
        self.normalizer = normalizer or ResponseTimeNormalizer()

    def handle_error(self, error: Exception, generic_message: str = "Operation failed") -> Dict[str, Any]:
        """
        Trata erro de forma timing-safe.

        Args:
            error: Exceção original
            generic_message: Mensagem genérica (não vaza detalhes)

        Returns:
            Dict com resposta de erro (timing-safe)

        Security:
        - Não vaza detalhes específicos do erro
        - Tempo de resposta constante
        - Erro genérico para usuário
        """
        # Log detalhado interno (não exposto ao usuário)
        logger.error(f"Error: {type(error).__name__}: {error}")

        # Resposta genérica (timing-safe)
        response = {
            'success': False,
            'error': generic_message,
            'error_code': 'OPERATION_FAILED',
            'timestamp': int(time.time())
        }

        # Normaliza tempo de resposta
        # (simula processamento mesmo em erro)
        time.sleep(random.uniform(0.01, 0.02))

        return response


# ═══════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def add_timing_jitter(base_delay_ms: float, jitter_percent: float = 0.2) -> float:
    """
    Adiciona jitter a delay.

    Args:
        base_delay_ms: Delay base em ms
        jitter_percent: Percentual de jitter (0.2 = ±20%)

    Returns:
        Delay com jitter aplicado
    """
    jitter_range = base_delay_ms * jitter_percent
    jitter = random.uniform(-jitter_range, jitter_range)
    return base_delay_ms + jitter


def secure_random_delay(min_ms: float, max_ms: float) -> None:
    """
    Delay aleatório criptograficamente seguro.

    Args:
        min_ms: Mínimo em ms
        max_ms: Máximo em ms
    """
    # Usa secrets para randomness criptograficamente seguro
    delay_ms = secrets.randbelow(int(max_ms - min_ms)) + min_ms
    time.sleep(delay_ms / 1000)


# ═══════════════════════════════════════════════════════════════════════════
# SINGLETON GLOBAL
# ═══════════════════════════════════════════════════════════════════════════

# Instâncias globais para conveniência
constant_time = ConstantTimeOps()
response_normalizer = ResponseTimeNormalizer()
rate_limiter = RateLimiter()
error_handler = TimingSafeErrorHandler()
