"""
Chatbot Internal LLM — 5 gates BTV (ADR-030).

Gates em ordem de criticidade:
  G1: message_gate      — mensagem CONFIDENTIAL/RESTRICTED → /v1/validate
  G2: indexing_gate     — documento sensível → /v1/validate
  G3: rag_gate          — chunk RAG → /v1/validate (injection detection)
  G4: training_gate     — batch de treinamento → /v1/validate
  G5: lora_deploy_gate  — hot-swap LoRA → /v1/validate (Irreversible)

Invariantes ADR-030:
  - Sem evidence_id → sem indexação de dado sensível
  - Sem evidence_id → sem deploy de LoRA
  - BTV indisponível → BLOCK local (fail-secure)
  - TTL zero para Irreversible
≤ 200 linhas
"""
from __future__ import annotations
import hashlib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .agent_pdp import (
    ActionImpact, AgentAction, AgentContext,
    AgentDecisionRequest, AgentVerdict,
)

logger = logging.getLogger("btv.governance.chatbot_gates")

BLAKE3_ZERO = "0" * 64  # placeholder quando blake3 não disponível


class DataClassification(str, Enum):
    PUBLIC       = "PUBLIC"
    INTERNAL     = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED   = "RESTRICTED"


@dataclass
class GateResult:
    verdict:      AgentVerdict
    evidence_id:  Optional[str]
    explain:      str
    gate:         str

    @property
    def allowed(self) -> bool:
        return self.verdict in (AgentVerdict.ALLOW, AgentVerdict.EDUCATE)

    @property
    def blocked(self) -> bool:
        return self.verdict == AgentVerdict.BLOCK


def _make_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest().ljust(64, "0")[:64]


def _fail_secure(gate: str, reason: str) -> GateResult:
    logger.error("fail-secure: gate=%s reason=%s", gate, reason)
    return GateResult(
        verdict=AgentVerdict.BLOCK,
        evidence_id=None,
        explain=f"[fail-secure] {gate}: {reason}",
        gate=gate,
    )


def message_gate(
    content: str,
    classification: DataClassification,
    pii_detected: bool,
    workspace_id: str,
    sector_id: str = "general",
) -> AgentDecisionRequest:
    """
    G1: Constrói request para gate de mensagem.
    Caller envia ao BTV e verifica HMAC do VerdictEnvelope.
    Gate obrigatório se classification >= CONFIDENTIAL ou pii_detected.
    """
    needs_gate = (
        classification in (DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED)
        or pii_detected
    )
    if not needs_gate:
        return None  # Safe — não requer gate

    impact = (
        ActionImpact.IRREVERSIBLE
        if classification == DataClassification.RESTRICTED
        else ActionImpact.DESTRUCTIVE
    )
    return AgentDecisionRequest(
        agent_id=f"chatbot-internal-{workspace_id[:8]}",
        session_id=workspace_id,
        action=AgentAction(name="llm_message_send", impact=impact,
                           capabilities=["llm_inference"]),
        parameters_hash=_make_hash(content),
        context=AgentContext(profile_id="internal-chatbot", sector_id=sector_id),
    )


def indexing_gate(
    doc_id: str,
    classification: DataClassification,
    workspace_id: str,
    sector_id: str = "general",
) -> Optional[AgentDecisionRequest]:
    """G2: Gate de indexação de documento no Qdrant."""
    if classification not in (DataClassification.CONFIDENTIAL,
                               DataClassification.RESTRICTED):
        return None

    impact = (ActionImpact.IRREVERSIBLE
              if classification == DataClassification.RESTRICTED
              else ActionImpact.DESTRUCTIVE)
    return AgentDecisionRequest(
        agent_id=f"chatbot-internal-{workspace_id[:8]}",
        session_id=workspace_id,
        action=AgentAction(name="document_index", impact=impact,
                           capabilities=["qdrant_write"]),
        parameters_hash=_make_hash(doc_id),
        context=AgentContext(profile_id="internal-chatbot", sector_id=sector_id),
    )


def rag_gate(
    chunk: str,
    workspace_id: str,
) -> AgentDecisionRequest:
    """G3: Gate de chunk RAG — detecta prompt injection antes de injetar no prompt."""
    return AgentDecisionRequest(
        agent_id=f"chatbot-internal-{workspace_id[:8]}",
        session_id=workspace_id,
        action=AgentAction(name="rag_chunk_inject", impact=ActionImpact.DESTRUCTIVE,
                           capabilities=["rag_context"]),
        parameters_hash=_make_hash(chunk),
        context=AgentContext(profile_id="internal-chatbot"),
    )


def training_gate(
    batch_id: str,
    workspace_id: str,
    sector_id: str = "general",
) -> AgentDecisionRequest:
    """G4: Gate de aprovação de batch de treinamento."""
    return AgentDecisionRequest(
        agent_id=f"chatbot-internal-{workspace_id[:8]}",
        session_id=workspace_id,
        action=AgentAction(name="training_cycle_start",
                           impact=ActionImpact.DESTRUCTIVE,
                           capabilities=["model_training"]),
        parameters_hash=_make_hash(batch_id),
        context=AgentContext(profile_id="internal-chatbot", sector_id=sector_id),
    )


def lora_deploy_gate(
    lora_version: str,
    benchmark_delta: float,
    workspace_id: str,
) -> AgentDecisionRequest:
    """
    G5: Gate de deploy de LoRA — Irreversible.
    benchmark_delta < -0.05 → policy YAML deve retornar BLOCK.
    TTL zero: cache proibido pelo caller.
    """
    return AgentDecisionRequest(
        agent_id=f"chatbot-internal-{workspace_id[:8]}",
        session_id=workspace_id,
        action=AgentAction(name="lora_deploy", impact=ActionImpact.IRREVERSIBLE,
                           capabilities=["model_deploy", "vllm_hotswap"]),
        parameters_hash=_make_hash(f"{lora_version}:{benchmark_delta}"),
        context=AgentContext(
            profile_id="internal-chatbot",
            agent_metadata={
                "lora_version": lora_version,
                "benchmark_delta": benchmark_delta,
            },
        ),
    )
