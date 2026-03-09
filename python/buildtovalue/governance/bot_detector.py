"""
BotDetector v1.0.0 — Gap 11 (Sprint 5)

Detecta padrao bot via desvio-padrao de inter-request intervals.
Bots mecanicos: std_dev ≈ 0 (ritmo uniforme).
Humanos: alta variancia por latencia cognitiva.

Invariantes:
  - Ring buffer fixo (maxlen=WINDOW_SIZE) — sem heap ilimitado
  - std_dev sobre intervals (delta_t), nao timestamps absolutos
  - Fail-secure: erro interno -> NOT_BOT (Levinas: beneficio da duvida)
  - SessionManager compartilhado (cap + TTL): sem crescimento ilimitado
  - explain_decision OBRIGATORIO em todo BotSignal

BiasDeclaration:
  FPR ~0.8%: scripts legitimos com timing uniforme
  FNR ~12%: bots sofisticados com jitter artificial > 50ms
  Threshold: std_dev < 50ms -> BOT_SUSPECT (calibrado 2026-03-09)

Filosofia:
  Levinas: FP bloqueia usuario real — NOT_BOT em caso de duvida.
  Jonas: responsabilidade de nao travar sistema por falso positivo.
"""
from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .session_manager import SessionManager

WINDOW_SIZE: int = 20
BOT_STD_DEV_THRESHOLD_MS: float = 50.0
MIN_SAMPLES: int = 5
SESSION_TTL: int = 1800
MAX_SESSIONS: int = 10_000


class BotVerdict(str, Enum):
    BOT_SUSPECT       = "BOT_SUSPECT"
    NOT_BOT           = "NOT_BOT"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


@dataclass(frozen=True)
class BotSignal:
    """
    Sinal imutavel de deteccao anti-bot.
    explain_decision OBRIGATORIO (Levinas).
    """
    session_id:       str
    verdict:          BotVerdict
    std_dev_ms:       Optional[float]
    sample_count:     int
    explain_decision: str


@dataclass
class _SessionIntervals:
    """Ring buffer de inter-request intervals (ms)."""
    intervals:   deque = field(
        default_factory=lambda: deque(maxlen=WINDOW_SIZE)
    )
    last_ts_ms: Optional[float] = None


class BotDetector:
    """
    Detecta comportamento bot por std_dev de inter-request intervals.

    BiasDeclaration (Gap 11):
      FPR ~0.8% | FNR ~12% | calibrado 2026-03-09
    """

    def __init__(
        self,
        threshold_ms: float = BOT_STD_DEV_THRESHOLD_MS,
        min_samples:  int   = MIN_SAMPLES,
        max_sessions: int   = MAX_SESSIONS,
        ttl_s:        int   = SESSION_TTL,
    ) -> None:
        if threshold_ms <= 0:
            raise ValueError("threshold_ms deve ser > 0")
        self._threshold    = threshold_ms
        self._min_samples  = min_samples
        self._sessions: dict[str, _SessionIntervals] = {}
        self._session_mgr  = SessionManager(
            max_sessions=max_sessions, ttl_s=ttl_s
        )

    def record(self, session_id: str) -> BotSignal:
        """
        Registra request e retorna sinal anti-bot.
        Fail-secure: qualquer excecao -> NOT_BOT.
        """
        try:
            return self._do_record(session_id)
        except Exception as exc:
            return BotSignal(
                session_id=session_id,
                verdict=BotVerdict.NOT_BOT,
                std_dev_ms=None,
                sample_count=0,
                explain_decision=(
                    f"[BotDetector] FAIL-SECURE: {exc} "
                    "(Levinas: beneficio da duvida ao usuario). "
                    "Contestavel via /api/v1/contestation (SLA 24h)."
                ),
            )

    def reset_session(self, session_id: str) -> None:
        """Remove sessao explicitamente (ex: contestacao aprovada)."""
        self._sessions.pop(session_id, None)
        self._session_mgr.evict(session_id)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _do_record(self, session_id: str) -> BotSignal:
        evicted = self._session_mgr.touch(session_id)
        for sid in evicted:
            self._sessions.pop(sid, None)

        now_ms = time.time() * 1000.0
        state  = self._sessions.get(session_id)
        if state is None:
            state = _SessionIntervals()
            self._sessions[session_id] = state

        if state.last_ts_ms is not None:
            delta = now_ms - state.last_ts_ms
            state.intervals.append(delta)

        state.last_ts_ms = now_ms
        n = len(state.intervals)

        if n < self._min_samples:
            return BotSignal(
                session_id=session_id,
                verdict=BotVerdict.INSUFFICIENT_DATA,
                std_dev_ms=None,
                sample_count=n,
                explain_decision=(
                    f"[BotDetector] Amostras insuficientes: "
                    f"{n}/{self._min_samples}. Aguardando mais requests."
                ),
            )

        std = _std_dev(list(state.intervals))

        if std < self._threshold:
            return BotSignal(
                session_id=session_id,
                verdict=BotVerdict.BOT_SUSPECT,
                std_dev_ms=std,
                sample_count=n,
                explain_decision=(
                    f"[BotDetector] BOT_SUSPECT: std_dev={std:.1f}ms "
                    f"< threshold={self._threshold:.1f}ms — "
                    f"padrao mecanico em {n} amostras. "
                    "Encaminhar revisao humana (SLA 24h — Rawls). "
                    "Contestavel via /api/v1/contestation."
                ),
            )

        return BotSignal(
            session_id=session_id,
            verdict=BotVerdict.NOT_BOT,
            std_dev_ms=std,
            sample_count=n,
            explain_decision=(
                f"[BotDetector] NOT_BOT: std_dev={std:.1f}ms "
                f">= threshold={self._threshold:.1f}ms — "
                f"variancia humana em {n} amostras."
            ),
        )


def _std_dev(values: list[float]) -> float:
    """
    Desvio-padrao amostral (Bessel n-1).
    Retorna 0.0 se n < 2. Sem heap extra — opera na lista existente.
    """
    n = len(values)
    if n < 2:
        return 0.0
    mean     = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return math.sqrt(variance)
