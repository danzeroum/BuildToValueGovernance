"""
Chatbot External LLM Vendor — gates BTV (ADR-031).

Delta do ADR-030: toda mensagem é Irreversible.
Gates:
  G1: vendor_send_gate    — sanitize + validate (Irreversible, sempre)
  G2: vendor_response_gate — sanitize resposta antes de exibir
  G3: vendor_approval_gate — aprovação de vendor por sector_id/ZDR
  G4: rag_external_gate   — chunk RAG para vendor (mais restritivo)

Invariantes ADR-031:
  - RESTRICTED nunca sai do perímetro (bloqueio local)
  - Cache zero para vendor_send
  - eligible_for_training sempre False para dados que saíram
  - BTV indisponível → mensagem não enviada
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
from .chatbot_gates import DataClassification, GateResult

logger = logging.getLogger("btv.governance.chatbot_vendor_gates")


class VendorId(str, Enum):
    OPENAI    = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE    = "google"
    AZURE     = "azure"


@dataclass
class VendorConfig:
    vendor_id:      VendorId
    has_dpa:        bool   = False
    has_zdr:        bool   = False  # Zero Data Retention
    data_residency: str    = "US"


def _make_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:64]


def _fail_secure(gate: str, reason: str) -> GateResult:
    logger.error("fail-secure: gate=%s reason=%s", gate, reason)
    return GateResult(
        verdict=AgentVerdict.BLOCK,
        evidence_id=None,
        explain=f"[fail-secure] {gate}: {reason}",
        gate=gate,
    )


def vendor_send_gate(
    content: str,
    classification: DataClassification,
    sanitize_evidence_id: str,
    workspace_id: str,
    vendor: VendorConfig,
    sector_id: str = "general",
) -> AgentDecisionRequest:
    """
    G1: Gate de transmissão ao vendor.
    Toda mensagem é Irreversible — cache proibido pelo caller.
    RESTRICTED → bloqueio local antes de chamar esta função.
    sanitize_evidence_id obrigatório — BTV valida correlação.
    """
    if classification == DataClassification.RESTRICTED:
        raise ValueError("RESTRICTED data must be blocked locally before gate")

    return AgentDecisionRequest(
        agent_id=f"chatbot-external-{workspace_id[:8]}",
        session_id=workspace_id,
        action=AgentAction(
            name="llm_vendor_send",
            impact=ActionImpact.IRREVERSIBLE,  # sempre Irreversible
            capabilities=["external_data_transfer", f"llm_vendor_{vendor.vendor_id}"],
        ),
        parameters_hash=_make_hash(content),
        parameters_preview={},  # proibido em Irreversible
        context=AgentContext(
            profile_id="external-chatbot",
            sector_id=sector_id,
            agent_metadata={
                "sanitize_evidence_id": sanitize_evidence_id,
                "vendor_id": vendor.vendor_id,
                "data_classification": classification,
                "eligible_for_training": False,  # dado saiu — sempre False
            },
        ),
    )


def vendor_response_gate(
    response_content: str,
    send_evidence_id: str,
    workspace_id: str,
) -> AgentDecisionRequest:
    """
    G2: Gate de resposta do vendor.
    Detecta exfiltração (sk-, CPF, tokens) antes de exibir ao usuário.
    """
    return AgentDecisionRequest(
        agent_id=f"chatbot-external-{workspace_id[:8]}",
        session_id=workspace_id,
        action=AgentAction(
            name="llm_vendor_response_display",
            impact=ActionImpact.DESTRUCTIVE,
            capabilities=["display_response"],
        ),
        parameters_hash=_make_hash(response_content),
        context=AgentContext(
            profile_id="external-chatbot",
            agent_metadata={"send_evidence_id": send_evidence_id},
        ),
    )


def vendor_approval_gate(
    vendor: VendorConfig,
    workspace_id: str,
    sector_id: str = "general",
) -> AgentDecisionRequest:
    """
    G3: Aprovação de vendor por sessão.
    sector=health/legal exige ZDR/DPA — policy YAML define BLOCK.
    """
    return AgentDecisionRequest(
        agent_id=f"chatbot-external-{workspace_id[:8]}",
        session_id=workspace_id,
        action=AgentAction(
            name="vendor_session_approve",
            impact=ActionImpact.DESTRUCTIVE,
            capabilities=[f"llm_vendor_{vendor.vendor_id}"],
        ),
        parameters_hash=_make_hash(f"{vendor.vendor_id}:{workspace_id}"),
        context=AgentContext(
            profile_id="external-chatbot",
            sector_id=sector_id,
            agent_metadata={
                "vendor_id": vendor.vendor_id,
                "has_dpa": vendor.has_dpa,
                "has_zdr": vendor.has_zdr,
                "data_residency": vendor.data_residency,
            },
        ),
    )


def rag_external_gate(
    chunk: str,
    classification: DataClassification,
    workspace_id: str,
) -> Optional[AgentDecisionRequest]:
    """
    G4: Gate de chunk RAG para vendor externo.
    RESTRICTED → None (bloqueio local, nunca chega ao vendor).
    CONFIDENTIAL → action=rag_chunk_inject_conf (EDUCATE no policy).
    """
    if classification == DataClassification.RESTRICTED:
        return None  # bloqueio local — nunca sai do perímetro

    action_name = (
        "rag_chunk_inject_conf"
        if classification == DataClassification.CONFIDENTIAL
        else "rag_chunk_inject"
    )
    return AgentDecisionRequest(
        agent_id=f"chatbot-external-{workspace_id[:8]}",
        session_id=workspace_id,
        action=AgentAction(
            name=action_name,
            impact=ActionImpact.DESTRUCTIVE,
            capabilities=["rag_context"],
        ),
        parameters_hash=_make_hash(chunk),
        context=AgentContext(profile_id="external-chatbot"),
    )
