"""
LLM Fallback v2.0 - Async fallback orchestrator.

CHANGELOG v2.0:
- [ASYNC] Non-blocking fallback usando asyncio
- [PATTERN] Circuit breaker integration
- [PERF] Task queue com prioridade
- [MONITOR] Metrics & observability

Gate: G2 (Async Safety Review)
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum
import time

from buildtovalue.intelligence.llm_async_client import (
    LLMAsyncClient,
    LLMRequest,
    LLMResponse,
    LLMError,
    CircuitBreaker
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# TIPOS
# ═══════════════════════════════════════════════════════════════════════════

class FallbackPriority(Enum):
    """Prioridade de fallback."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class FallbackTask:
    """Task de fallback assíncrona."""
    request: LLMRequest
    priority: FallbackPriority
    timestamp: float
    retry_count: int = 0

    def __lt__(self, other):
        """Comparação para priority queue."""
        # Maior prioridade primeiro
        if self.priority != other.priority:
            return self.priority.value > other.priority.value
        # Se prioridade igual, mais antigo primeiro
        return self.timestamp < other.timestamp


# ═══════════════════════════════════════════════════════════════════════════
# ASYNC FALLBACK ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════

class LLMFallbackOrchestrator:
    """
    Orquestrador assíncrono de fallback LLM.

    Features:
    - Non-blocking task queue
    - Priority-based scheduling
    - Circuit breaker integration
    - Metrics & monitoring
    """

    def __init__(
            self,
            llm_client: LLMAsyncClient,
            max_queue_size: int = 1000,
            worker_count: int = 5,
            circuit_breaker: Optional[CircuitBreaker] = None
    ):
        """
        Inicializa orchestrator.

        Args:
            llm_client: Cliente LLM assíncrono
            max_queue_size: Tamanho máximo da queue
            worker_count: Número de workers concorrentes
            circuit_breaker: Circuit breaker (opcional)
        """
        self.llm_client = llm_client
        self.max_queue_size = max_queue_size
        self.worker_count = worker_count
        self.circuit_breaker = circuit_breaker or CircuitBreaker()

        # Task queue (priority queue)
        self.task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue(
            maxsize=max_queue_size
        )

        # Workers
        self.workers: List[asyncio.Task] = []
        self.running = False

        # Métricas
        self.metrics = {
            'tasks_submitted': 0,
            'tasks_completed': 0,
            'tasks_failed': 0,
            'tasks_dropped': 0,
            'queue_full_count': 0,
        }

    async def start(self):
        """Inicia workers."""
        if self.running:
            logger.warning("Orchestrator already running")
            return

        self.running = True

        # Inicia workers
        for i in range(self.worker_count):
            worker = asyncio.create_task(self._worker(i))
            self.workers.append(worker)

        logger.info(f"Started {self.worker_count} async workers")

    async def stop(self):
        """Para workers."""
        if not self.running:
            return

        self.running = False

        # Aguarda queue esvaziar (timeout 10s)
        try:
            await asyncio.wait_for(self.task_queue.join(), timeout=10.0)
        except asyncio.TimeoutError:
            logger.warning("Queue did not empty in time")

        # Cancela workers
        for worker in self.workers:
            worker.cancel()

        # Aguarda workers terminarem
        await asyncio.gather(*self.workers, return_exceptions=True)

        self.workers.clear()
        logger.info("Stopped all workers")

    async def submit_fallback(
            self,
            request: LLMRequest,
            priority: FallbackPriority = FallbackPriority.NORMAL
    ) -> bool:
        """
        Submete task de fallback (non-blocking).

        Args:
            request: LLM request
            priority: Prioridade da task

        Returns:
            True se task foi aceita
        """
        self.metrics['tasks_submitted'] += 1

        # Cria task
        task = FallbackTask(
            request=request,
            priority=priority,
            timestamp=time.time()
        )

        try:
            # Adiciona à queue (non-blocking)
            self.task_queue.put_nowait(task)
            return True

        except asyncio.QueueFull:
            logger.warning(
                f"Task queue full ({self.max_queue_size}), "
                f"dropping task (priority: {priority.name})"
            )
            self.metrics['tasks_dropped'] += 1
            self.metrics['queue_full_count'] += 1
            return False

    async def _worker(self, worker_id: int):
        """
        Worker que processa tasks.

        Args:
            worker_id: ID do worker
        """
        logger.info(f"Worker {worker_id} started")

        while self.running:
            try:
                # Pega próxima task (blocking com timeout)
                task = await asyncio.wait_for(
                    self.task_queue.get(),
                    timeout=1.0
                )

                # Processa task
                await self._process_task(worker_id, task)

                # Marca como done
                self.task_queue.task_done()

            except asyncio.TimeoutError:
                # Timeout esperando task (continua loop)
                continue

            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")

        logger.info(f"Worker {worker_id} stopped")

    async def _process_task(self, worker_id: int, task: FallbackTask):
        """
        Processa uma task de fallback.

        Args:
            worker_id: ID do worker
            task: Task a processar
        """
        logger.debug(
            f"Worker {worker_id} processing task "
            f"(priority: {task.priority.name}, age: {time.time() - task.timestamp:.2f}s)"
        )

        try:
            # Executa através do circuit breaker
            response = await self.circuit_breaker.call(
                self.llm_client.complete,
                task.request,
                use_cache=True
            )

            # Sucesso
            self.metrics['tasks_completed'] += 1

            logger.info(
                f"Worker {worker_id} completed task "
                f"(latency: {response.latency_ms:.2f}ms, "
                f"tokens: {response.tokens_used})"
            )

        except Exception as e:
            self.metrics['tasks_failed'] += 1

            logger.error(
                f"Worker {worker_id} failed task: {e} "
                f"(retries: {task.retry_count})"
            )

            # Re-enqueue com retry (se não excedeu limite)
            if task.retry_count < 3:
                task.retry_count += 1

                # Re-submete com prioridade reduzida
                try:
                    await asyncio.sleep(2 ** task.retry_count)  # Exponential backoff
                    self.task_queue.put_nowait(task)
                    logger.info(f"Task re-queued (retry {task.retry_count})")
                except asyncio.QueueFull:
                    logger.warning("Cannot re-queue task (queue full)")

    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas."""
        return {
            **self.metrics,
            'queue_size': self.task_queue.qsize(),
            'workers_active': len(self.workers),
            'success_rate': (
                    self.metrics['tasks_completed'] /
                    max(self.metrics['tasks_submitted'], 1)
            ),
            'drop_rate': (
                    self.metrics['tasks_dropped'] /
                    max(self.metrics['tasks_submitted'], 1)
            ),
            'circuit_breaker': self.circuit_breaker.get_stats().__dict__
        }

    async def __aenter__(self):
        """Context manager enter."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.stop()
