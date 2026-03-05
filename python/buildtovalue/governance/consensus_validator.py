"""
ConsensusValidator — PROP-032 (ADR-0050)

Protecao contra reasoning collapse em decisoes irreversiveis (paper 235).

Invariantes:
  N=3 fixo, hard-cap 40ms, timeout->ESCALATE_HUMAN (fail-secure)
  explain_decision obrigatorio, HMAC-SHA256 na ConsensusDecision
  Ativado exclusivamente em: Irreversible AND confidence < THRESHOLD
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac as hmac_mod
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, Awaitable, Optional, Tuple

from .types import ActionType

logger = logging.getLogger(__name__)

# ─── Constantes imutaveis (ADR-0050) ─────────────────────────────────────────
CONSENSUS_N:          int   = 3
CONSENSUS_THRESHOLD:  int   = 2       # ceil(N/2)+1
HARD_CAP_MS:          float = 40.0
CONFIDENCE_THRESHOLD: float = 0.75


# ─── Enums ────────────────────────────────────────────────────────────────────

class Reversibility(Enum):
    REVERSIBLE   = "reversible"
    IRREVERSIBLE = "irreversible"


class ConsensusOutcome(Enum):
    UNANIMOUS_BLOCK  = "unanimous_block"
    MAJORITY_BLOCK   = "majority_block"
    UNANIMOUS_ALLOW  = "unanimous_allow"
    DIVERGENT        = "divergent"   # -> ESCALATE_HUMAN
    TIMEOUT          = "timeout"     # -> ESCALATE_HUMAN (fail-secure)
    FAST_PATH        = "fast_path"   # single-judge, nao ativou consensus


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RolloutResult:
    """Resultado de uma unica inferencia (rollout)."""
    run_index:   int
    action:      ActionType
    confidence:  float
    rationale:   str
    duration_ms: float


@dataclass(frozen=True)
class ConsensusDecision:
    """
    Decisao de consenso assinada.

    rollout_results preservados para explain_decision (Levinas).
    hmac_sha256 garante integridade para o Ledger (Jonas).
    """
    outcome:             ConsensusOutcome
    final_action:        ActionType
    rollout_results:     Tuple[RolloutResult, ...]
    consensus_time_ms:   float
    divergence_detected: bool
    escalation_reason:   Optional[str]
    hmac_sha256:         str
    decided_at_iso:      str
    n_runs:              int = CONSENSUS_N

    @property
    def block_vote_count(self) -> int:
        return sum(1 for r in self.rollout_results if r.action == ActionType.BLOCK)

    @property
    def was_fast_path(self) -> bool:
        return self.outcome == ConsensusOutcome.FAST_PATH

    def to_explain_dict(self) -> dict:
        """Formato obrigatorio para explain_decision (ADR-0050)."""
        return {
            "outcome":             self.outcome.value,
            "final_action":        self.final_action.value,
            "consensus_time_ms":   self.consensus_time_ms,
            "divergence_detected": self.divergence_detected,
            "block_vote_count":    self.block_vote_count,
            "n_runs":              self.n_runs,
            "escalation_reason":   self.escalation_reason,
            "decided_at":          self.decided_at_iso,
            "rollouts": [
                {
                    "run":         r.run_index,
                    "action":      r.action.value,
                    "confidence":  r.confidence,
                    "rationale":   r.rationale[:120],
                    "duration_ms": r.duration_ms,
                }
                for r in self.rollout_results
            ],
        }


# ─── JudgeFn Protocol ─────────────────────────────────────────────────────────

# Callable que retorna (ActionType, confidence, rationale)
JudgeFn = Callable[[], Awaitable[Tuple[ActionType, float, str]]]


# ─── ConsensusValidator ───────────────────────────────────────────────────────

class ConsensusValidator:
    """
    Valida decisoes irreversiveis com N=3 rollouts paralelos (ADR-0050).

    Uso:
        validator = ConsensusValidator(judge_fn=my_judge, hmac_key=key)
        decision  = await validator.validate(reversibility, confidence)
    """

    def __init__(self, judge_fn: JudgeFn, hmac_key: bytes) -> None:
        self._judge_fn = judge_fn
        self._hmac_key = hmac_key
        self._metrics: dict = {
            "total_calls":          0,
            "fast_path_calls":      0,
            "consensus_calls":      0,
            "divergent_count":      0,
            "timeout_count":        0,
            "block_majority_count": 0,
        }

    # ── API principal ─────────────────────────────────────────────────────────

    async def validate(
        self,
        reversibility: Reversibility,
        confidence:    float,
    ) -> ConsensusDecision:
        """
        Ponto de entrada. Fast path se REVERSIBLE ou confidence >= THRESHOLD.

        Raises: nunca — timeout e divergencia sao capturados como ConsensusDecision.
        """
        self._metrics["total_calls"] += 1

        if reversibility != Reversibility.IRREVERSIBLE or confidence >= CONFIDENCE_THRESHOLD:
            return await self._fast_path()

        self._metrics["consensus_calls"] += 1
        return await self._run_consensus()

    # ── Fast path ─────────────────────────────────────────────────────────────

    async def _fast_path(self) -> ConsensusDecision:
        """Single judge — chamado para REVERSIBLE ou alta confianca."""
        self._metrics["fast_path_calls"] += 1
        start = time.perf_counter()
        action, confidence, rationale = await self._judge_fn()
        duration_ms = (time.perf_counter() - start) * 1000

        rollout = RolloutResult(
            run_index=0, action=action, confidence=confidence,
            rationale=rationale, duration_ms=duration_ms,
        )
        now_iso = datetime.utcnow().isoformat() + "Z"
        return ConsensusDecision(
            outcome             = ConsensusOutcome.FAST_PATH,
            final_action        = action,
            rollout_results     = (rollout,),
            consensus_time_ms   = duration_ms,
            divergence_detected = False,
            escalation_reason   = None,
            hmac_sha256         = self._sign(ConsensusOutcome.FAST_PATH, action, now_iso),
            decided_at_iso      = now_iso,
            n_runs              = 1,
        )

    # ── Consensus path ────────────────────────────────────────────────────────

    async def _run_consensus(self) -> ConsensusDecision:
        """N=3 rollouts paralelos com hard-cap 40ms (ADR-0050)."""
        start    = time.perf_counter()
        now_iso  = datetime.utcnow().isoformat() + "Z"

        try:
            raw = await asyncio.wait_for(
                asyncio.gather(*[self._timed_run(i) for i in range(CONSENSUS_N)]),
                timeout = HARD_CAP_MS / 1000.0,
            )
            rollouts: Tuple[RolloutResult, ...] = tuple(raw)
        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - start) * 1000
            self._metrics["timeout_count"] += 1
            logger.warning("ConsensusValidator: timeout %.1fms > %.1fms -> ESCALATE_HUMAN",
                           elapsed, HARD_CAP_MS)
            return self._timeout_decision(elapsed, now_iso)

        elapsed = (time.perf_counter() - start) * 1000
        return self._build_decision(rollouts, elapsed, now_iso)

    async def _timed_run(self, index: int) -> RolloutResult:
        """Executa uma inferencia e registra duracao."""
        start = time.perf_counter()
        action, confidence, rationale = await self._judge_fn()
        return RolloutResult(
            run_index   = index,
            action      = action,
            confidence  = confidence,
            rationale   = rationale,
            duration_ms = (time.perf_counter() - start) * 1000,
        )

    # ── Logica de consenso ────────────────────────────────────────────────────

    def _build_decision(
        self,
        rollouts:   Tuple[RolloutResult, ...],
        elapsed_ms: float,
        now_iso:    str,
    ) -> ConsensusDecision:
        """Aplica regras ADR-0050: maioria BLOCK > divergente > unanime."""
        block_votes  = sum(1 for r in rollouts if r.action == ActionType.BLOCK)
        unique_votes = len({r.action for r in rollouts})
        divergent    = unique_votes > 1

        if block_votes >= CONSENSUS_THRESHOLD:
            outcome      = (ConsensusOutcome.UNANIMOUS_BLOCK if block_votes == CONSENSUS_N
                            else ConsensusOutcome.MAJORITY_BLOCK)
            final_action = ActionType.BLOCK
            reason       = None
            self._metrics["block_majority_count"] += 1
        elif divergent:
            outcome      = ConsensusOutcome.DIVERGENT
            final_action = ActionType.ESCALATE_HUMAN
            reason       = (f"Divergencia: {block_votes}/{CONSENSUS_N} votos BLOCK. "
                            "Revisao humana obrigatoria (Rawls, SLA 24h).")
            self._metrics["divergent_count"] += 1
        else:
            outcome      = ConsensusOutcome.UNANIMOUS_ALLOW
            final_action = rollouts[0].action
            reason       = None

        return ConsensusDecision(
            outcome             = outcome,
            final_action        = final_action,
            rollout_results     = rollouts,
            consensus_time_ms   = elapsed_ms,
            divergence_detected = divergent,
            escalation_reason   = reason,
            hmac_sha256         = self._sign(outcome, final_action, now_iso),
            decided_at_iso      = now_iso,
        )

    def _timeout_decision(self, elapsed_ms: float, now_iso: str) -> ConsensusDecision:
        """ESCALATE_HUMAN em timeout — fail-secure (ADR-0001, ADR-0050)."""
        return ConsensusDecision(
            outcome             = ConsensusOutcome.TIMEOUT,
            final_action        = ActionType.ESCALATE_HUMAN,
            rollout_results     = (),
            consensus_time_ms   = elapsed_ms,
            divergence_detected = False,
            escalation_reason   = (
                f"Timeout {elapsed_ms:.1f}ms > hard-cap {HARD_CAP_MS}ms. "
                "Fail-secure: ESCALATE_HUMAN (ADR-0050)."),
            hmac_sha256         = self._sign(ConsensusOutcome.TIMEOUT,
                                             ActionType.ESCALATE_HUMAN, now_iso),
            decided_at_iso      = now_iso,
        )

    # ── HMAC ──────────────────────────────────────────────────────────────────

    def _sign(
        self,
        outcome:      ConsensusOutcome,
        final_action: ActionType,
        now_iso:      str,
    ) -> str:
        mac = hmac_mod.new(self._hmac_key, digestmod=hashlib.sha256)
        mac.update(outcome.value.encode())
        mac.update(final_action.value.encode())
        mac.update(now_iso.encode())
        return mac.hexdigest()

    # ── Metricas ──────────────────────────────────────────────────────────────

    def get_metrics(self) -> dict:
        """Metricas para Prometheus (consensus_divergence_rate, etc.)."""
        total = max(self._metrics["consensus_calls"], 1)
        return {
            **self._metrics,
            "consensus_divergence_rate": self._metrics["divergent_count"] / total,
            "consensus_timeout_rate":    self._metrics["timeout_count"]   / total,
            "consensus_block_rate":      self._metrics["block_majority_count"] / total,
            "fast_path_rate": (self._metrics["fast_path_calls"]
                                / max(self._metrics["total_calls"], 1)),
        }

    def reset_metrics(self) -> None:
        for k in self._metrics:
            self._metrics[k] = 0
