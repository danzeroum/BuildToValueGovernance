"""LivenessMonitor — Cenário 29: Dead Man's Switch e Hibernação.

Rastreia presença humana e impõe três níveis de autonomia decrescente:
  FULL        — < 7 dias de inatividade: operação normal
  RESTRICTED  — 7–30 dias: ações Irreversible exigem aprovação + appeal automático
  HIBERNATION — > 30 dias: apenas manutenção vital; transferências financeiras BLOQUEADAS

Integração com ContestabilityLoop (Gap 1):
  - RESTRICTED → appeal automático grounds=jonas_responsibility (SLA 24h)
  - HIBERNATION → BLOCK incondicional (usuário reinicia manualmente)

Invariantes:
  - Fail-secure: erro ao ler ledger → retorna 9999 dias (HIBERNATION)
  - explain_decision obrigatório em todo GateResult
  - HMAC-SHA256 em registros de confirmação
  - Funções ≤ 50 linhas
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .agent_pdp import ActionImpact, AgentDecisionRequest, AgentVerdict
from .approval_workflow import ApprovalWorkflow
from .chatbot_gates import GateResult
from .contestability_loop import ContestabilityLoop
from .durable_ledger import DurableLedger

logger = logging.getLogger("btv.governance.liveness_monitor")

_RESTRICTED_DAYS = 7
_HIBERNATION_DAYS = 30
_DEFAULT_KEY = b"btv-liveness-default-key"


class AutonomyLevel(Enum):
    """Nível de autonomia do agente conforme inatividade do usuário."""
    FULL        = "FULL"        # < 7 dias
    RESTRICTED  = "RESTRICTED"  # 7–30 dias
    HIBERNATION = "HIBERNATION" # > 30 dias


@dataclass(frozen=True)
class LivenessStatus:
    """Resultado de uma verificação de liveness."""
    agent_id: str
    days_inactive: int
    autonomy_level: AutonomyLevel
    explain_decision: str


class LivenessMonitor:
    """Monitora presença humana e impõe Dead Man's Switch."""

    def __init__(self, hmac_key: bytes = _DEFAULT_KEY) -> None:
        self._key = hmac_key

    # ------------------------------------------------------------------ #
    # API pública                                                          #
    # ------------------------------------------------------------------ #

    def record_human_confirmation(
        self,
        agent_id: str,
        ledger: DurableLedger,
    ) -> None:
        """Registra confirmação de presença humana no ledger imutável.

        Fail-secure: qualquer erro → loga e propaga (não silencia falha).
        """
        now_iso = _now_iso()
        sig = self._sign(agent_id, now_iso)
        ledger.append({
            "type": "liveness_confirmation",
            "agent_id": agent_id,
            "confirmed_at_iso": now_iso,
            "hmac_signature": sig,
            "explain_decision": (
                f"Confirmação de presença humana registrada para agente {agent_id}"
            ),
        })
        logger.info("Liveness confirmado: agent_id=%s at=%s", agent_id, now_iso)

    def days_since_last_confirmation(
        self,
        agent_id: str,
        ledger: DurableLedger,
    ) -> int:
        """Retorna dias desde a última confirmação.

        Fail-secure: ledger vazio ou erro de leitura → 9999 (HIBERNATION).
        """
        try:
            entries = ledger.entries()
            last_iso: Optional[str] = None
            for entry in reversed(entries):
                payload = entry.payload
                if (
                    payload.get("type") == "liveness_confirmation"
                    and payload.get("agent_id") == agent_id
                ):
                    last_iso = payload.get("confirmed_at_iso")
                    break

            if last_iso is None:
                return 9999  # nunca confirmado → fail-secure

            last_dt = datetime.fromisoformat(last_iso.replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            delta = now_dt - last_dt
            return max(0, delta.days)

        except Exception as exc:  # noqa: BLE001
            logger.error("Erro ao ler liveness do ledger: %s", exc)
            return 9999  # fail-secure

    def autonomy_level(
        self,
        agent_id: str,
        ledger: DurableLedger,
    ) -> AutonomyLevel:
        """Resolve nível de autonomia conforme dias de inatividade."""
        days = self.days_since_last_confirmation(agent_id, ledger)
        if days < _RESTRICTED_DAYS:
            return AutonomyLevel.FULL
        if days < _HIBERNATION_DAYS:
            return AutonomyLevel.RESTRICTED
        return AutonomyLevel.HIBERNATION

    def gate_irreversible(
        self,
        agent_id: str,
        request: AgentDecisionRequest,
        workflow: ApprovalWorkflow,
        contestability: ContestabilityLoop,
        ledger: DurableLedger,
    ) -> GateResult:
        """Portão para ações Irreversible/financeiras conforme autonomia.

        FULL        → pass-through (retorna ALLOW para continuar pipeline).
        RESTRICTED  → cria ticket de aprovação + appeal automático (Jonas).
        HIBERNATION → BLOCK incondicional.
        """
        level = self.autonomy_level(agent_id, ledger)
        days  = self.days_since_last_confirmation(agent_id, ledger)

        if level == AutonomyLevel.FULL:
            return GateResult(
                verdict=AgentVerdict.ALLOW,
                evidence_id=None,
                explain=f"[liveness] FULL — {days}d de inatividade, autonomia total",
                gate="liveness_monitor",
            )

        if level == AutonomyLevel.RESTRICTED:
            return self._handle_restricted(agent_id, request, workflow, contestability, days)

        # HIBERNATION — BLOCK incondicional
        return GateResult(
            verdict=AgentVerdict.BLOCK,
            evidence_id=None,
            explain=(
                f"[liveness] HIBERNATION — {days}d sem confirmação humana. "
                "Ações financeiras/físicas bloqueadas. Retorne para reativar."
            ),
            gate="liveness_monitor",
        )

    # ------------------------------------------------------------------ #
    # Interno                                                              #
    # ------------------------------------------------------------------ #

    def _handle_restricted(
        self,
        agent_id: str,
        request: AgentDecisionRequest,
        workflow: ApprovalWorkflow,
        contestability: ContestabilityLoop,
        days: int,
    ) -> GateResult:
        """Cria ticket HITL e appeal automático para RESTRICTED."""
        try:
            ticket = workflow.request_approval(
                request,
                reason=(
                    f"Dead man's switch — RESTRICTED ({days}d inativo). "
                    "Requer aprovação humana para ação Irreversible."
                ),
            )
            appeal = contestability.submit_appeal(
                audit_trail_id=ticket.ticket_id,
                user_id=agent_id,
                reason=(
                    f"Ação bloqueada por inatividade de {days} dias — "
                    "appeal automático (Jonas)"
                ),
                evidence=f"channel={request.action.metadata.get('channel', 'unknown')}",
            )
            return GateResult(
                verdict=AgentVerdict.PENDING_APPROVAL,
                evidence_id=ticket.ticket_id,
                explain=(
                    f"[liveness] RESTRICTED — appeal {appeal.appeal_id} aberto (SLA 24h). "
                    f"Ticket: {ticket.ticket_id}"
                ),
                gate="liveness_monitor",
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro ao criar appeal RESTRICTED: %s", exc)
            return GateResult(
                verdict=AgentVerdict.BLOCK,
                evidence_id=None,
                explain=(
                    f"[liveness] RESTRICTED — falha ao criar appeal: {exc}. BLOCK fail-secure."
                ),
                gate="liveness_monitor",
            )

    def _sign(self, agent_id: str, iso: str) -> str:
        payload = f"{agent_id}|{iso}".encode()
        return hmac_lib.new(self._key, payload, hashlib.sha256).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Testes unitários
# ---------------------------------------------------------------------------

class TestLivenessMonitor:  # noqa: D101
    """Testes básicos — rodar com: pytest -k LivenessMonitor"""

    def _make_ledger(self) -> DurableLedger:
        return DurableLedger(hmac_key=b"test-key")

    def test_full_level_when_fresh(self) -> None:
        import unittest
        monitor = LivenessMonitor()
        ledger  = self._make_ledger()
        monitor.record_human_confirmation("agent-1", ledger)
        level = monitor.autonomy_level("agent-1", ledger)
        assert level == AutonomyLevel.FULL, f"Expected FULL, got {level}"

    def test_hibernation_when_never_confirmed(self) -> None:
        monitor = LivenessMonitor()
        ledger  = self._make_ledger()
        days = monitor.days_since_last_confirmation("agent-never", ledger)
        assert days == 9999
        level = monitor.autonomy_level("agent-never", ledger)
        assert level == AutonomyLevel.HIBERNATION

    def test_gate_blocks_in_hibernation(self) -> None:
        from unittest.mock import MagicMock
        monitor = LivenessMonitor()
        ledger  = self._make_ledger()
        request = MagicMock()
        request.action.metadata = {}
        workflow = MagicMock()
        contestability = MagicMock()
        # agent sem confirmação → HIBERNATION
        result = monitor.gate_irreversible(
            "agent-never", request, workflow, contestability, ledger
        )
        assert result.verdict == AgentVerdict.BLOCK
        assert "HIBERNATION" in result.explain
