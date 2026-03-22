"""AlignmentDegradationTracker — Gap D: Multi-Agent Alignment Degradation Score.

Detecta quando um agente apresenta degradação de alinhamento em contexto
colaborativo versus solo. Endereça o paradoxo de alinhamento multi-agente
documentado no relatório ICLR 2026.

Invariantes:
- Ring buffer por agente (deque maxlen=window) — sem crescimento ilimitado
- Dados insuficientes → score=0.0, check() retorna None (não bloquear sem dados)
- Thread-safe: cada instância deve ser usada por um único thread ou protegida externamente
- Funções ≤ 50 linhas, arquivo ≤ 200 linhas
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional

_SNAPSHOT_WINDOW = 20
_DEGRADATION_THRESHOLD = 0.4
_MIN_SAMPLES = 3

# Verdicts considerados problemáticos para o cálculo de degradação
_PROBLEMATIC_VERDICTS = frozenset({
    "BLOCK", "REFUSE", "ALIGNMENT_DEGRADATION",
})


@dataclass(frozen=True)
class AlignmentSnapshot:
    """Registro pontual de um verdict de agente."""
    agent_id: str
    verdict: str           # "ALLOW" | "BLOCK" | "EDUCATE" | "REFUSE" | ...
    is_collaborative: bool  # True = contexto multi-agente, False = solo
    timestamp: float        # time.time()


class AlignmentDegradationTracker:
    """Rastreia degradação de alinhamento por agente em contextos colaborativos.

    Uso:
        tracker = AlignmentDegradationTracker()
        tracker.record("agent-1", "BLOCK", is_collaborative=True)
        reason = tracker.check("agent-1")
        if reason:
            # emitir CorrelationResult bloqueante com reason
    """

    def __init__(
        self,
        threshold: float = _DEGRADATION_THRESHOLD,
        window: int = _SNAPSHOT_WINDOW,
        min_samples: int = _MIN_SAMPLES,
    ) -> None:
        self._threshold = threshold
        self._window = window
        self._min_samples = min_samples
        self._snapshots: Dict[str, Deque[AlignmentSnapshot]] = {}

    def record(
        self,
        agent_id: str,
        verdict: str,
        is_collaborative: bool,
    ) -> None:
        """Acumula snapshot de verdict para o agente.

        Ring buffer de tamanho _window: entradas antigas são descartadas.
        """
        if agent_id not in self._snapshots:
            self._snapshots[agent_id] = deque(maxlen=self._window)
        self._snapshots[agent_id].append(
            AlignmentSnapshot(
                agent_id=agent_id,
                verdict=verdict,
                is_collaborative=is_collaborative,
                timestamp=time.time(),
            )
        )

    def degradation_score(self, agent_id: str) -> float:
        """Calcula score de degradação para o agente.

        score = (taxa_problematic_collab) - (taxa_problematic_solo)

        Retorna 0.0 se dados insuficientes (< min_samples em qualquer categoria).
        Score positivo indica que o agente se comporta pior em colaboração.
        """
        snaps = list(self._snapshots.get(agent_id, []))
        collab = [s for s in snaps if s.is_collaborative]
        solo = [s for s in snaps if not s.is_collaborative]

        if len(collab) < self._min_samples or len(solo) < self._min_samples:
            return 0.0

        rate_collab = sum(1 for s in collab if s.verdict in _PROBLEMATIC_VERDICTS) / len(collab)
        rate_solo = sum(1 for s in solo if s.verdict in _PROBLEMATIC_VERDICTS) / len(solo)
        return max(0.0, rate_collab - rate_solo)

    def check(self, agent_id: str) -> Optional[str]:
        """Retorna razão de bloqueio se score > threshold, caso contrário None.

        O chamador é responsável por construir o CorrelationResult com a razão.
        """
        score = self.degradation_score(agent_id)
        if score > self._threshold:
            return (
                f"ALIGNMENT_DEGRADATION: agente '{agent_id}' apresenta degradação "
                f"de alinhamento em contexto colaborativo "
                f"(score={score:.2f} > threshold={self._threshold:.2f})"
            )
        return None

    def snapshots(self, agent_id: str) -> List[AlignmentSnapshot]:
        """Retorna cópia dos snapshots atuais do agente (para auditoria)."""
        return list(self._snapshots.get(agent_id, []))
