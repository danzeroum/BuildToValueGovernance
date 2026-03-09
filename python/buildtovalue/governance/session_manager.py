"""
SessionManager v1.0 — Gaps 1, 5, 9, 17 (Sprint 5)

Gerenciamento unificado de sessões com LRU + TTL.
Usado por GoalDriftSentinel e SessionSensitivityAccumulator.

Garantias:
  - O(1) amortizado por operação (OrderedDict + amostragem 10%)
  - cap max_sessions: eviccão LRU do mais antigo quando cheio
  - cap TTL: eviccão amortizada a cada 100 ops (sem scan total)
  - touch() retorna lista de session_ids evictados
    → chamador limpa dados associados (sem acoplamento)
  - Fail-secure: nunca lança exceção (exceto construção inválida)

Filosofia:
  Jonas: responsabilidade de não acumular estado indefinidamente.
  Rawls: limite igualitário — nenhuma sessão ocupa espaço para sempre.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import List

SESSION_MAX_DEFAULT: int = 10_000
SESSION_TTL_DEFAULT: int = 1800  # 30 min — alinhado com SessionTracker Rust
_EVICT_SAMPLE_EVERY: int = 100   # amortiza varredura de TTL
_EVICT_SAMPLE_PCT:   int = 10    # % das sessões mais antigas a verificar


class SessionManager:
    """
    LRU + TTL manager para sessões de governança.

    Uso típico (dono dos dados):
        evicted = mgr.touch(session_id)
        for sid in evicted:
            del my_data[sid]        # limpar dados associados
        ...
        mgr.evict(session_id)       # ao resetar sessão
    """

    def __init__(
        self,
        max_sessions: int = SESSION_MAX_DEFAULT,
        ttl_s: int = SESSION_TTL_DEFAULT,
    ) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions deve ser >= 1")
        if ttl_s < 1:
            raise ValueError("ttl_s deve ser >= 1")
        self._last_seen: OrderedDict[str, float] = OrderedDict()
        self._max = max_sessions
        self._ttl = ttl_s
        self._op_counter: int = 0
        self.evictions: int = 0  # contador auditável (exposto para métricas)

    # ── Public API ────────────────────────────────────────────────────────────

    def touch(self, session_id: str) -> List[str]:
        """
        Marca sessão como ativa agora (move para o fim do LRU).

        Retorna lista de session_ids evictados durante esta operação:
          - por TTL (amortizado a cada _EVICT_SAMPLE_EVERY ops)
          - por cap (LRU: mais antigo quando acima de max_sessions)

        O chamador é responsável por limpar dados associados.
        """
        self._last_seen.pop(session_id, None)
        self._last_seen[session_id] = time.time()

        evicted: List[str] = self._amortized_ttl_evict()

        while len(self._last_seen) > self._max:
            oldest, _ = self._last_seen.popitem(last=False)
            evicted.append(oldest)
            self.evictions += 1

        return evicted

    def is_expired(self, session_id: str) -> bool:
        """
        Retorna True se sessão não existe ou não foi tocada em > ttl_s.
        Não modifica estado (idempotente).
        """
        ts = self._last_seen.get(session_id)
        if ts is None:
            return True
        return (time.time() - ts) > self._ttl

    def evict(self, session_id: str) -> None:
        """Remove sessão explicitamente (ex: reset por contestação aceita)."""
        self._last_seen.pop(session_id, None)

    def size(self) -> int:
        """Número de sessões ativas rastreadas."""
        return len(self._last_seen)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _amortized_ttl_evict(self) -> List[str]:
        """
        A cada _EVICT_SAMPLE_EVERY operações, verifica os
        _EVICT_SAMPLE_PCT% mais antigos (início do OrderedDict).
        Custo distribuído: O(1) amortizado.
        """
        self._op_counter += 1
        if self._op_counter < _EVICT_SAMPLE_EVERY:
            return []
        self._op_counter = 0

        now = time.time()
        to_check = max(1, len(self._last_seen) * _EVICT_SAMPLE_PCT // 100)
        expired: List[str] = []

        for sid, ts in self._last_seen.items():
            if to_check <= 0:
                break
            if now - ts > self._ttl:
                expired.append(sid)
            to_check -= 1

        for sid in expired:
            del self._last_seen[sid]
            self.evictions += 1

        return expired
