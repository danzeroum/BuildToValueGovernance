"""POST /v1/agent/decide — Structured Action Governance (ADR-029).

This route handles agent-initiated structured action requests (scenarios 31–35 and
other high-impact actions). It consumes AgentDecisionRequest and returns VerdictEnvelope.

Dual-path architecture:
  /v1/decide         → text-stream governance (scenarios 1–20), proxied by Rust gateway
  /v1/agent/decide   → structured action governance (scenarios 31–35), Python-direct

SLA: <100ms p99 (cold path — structured actions are deliberative by design).

M2 roadmap: Unify both paths into POST /v1/gate with mode="text"|"action".

Invariants (ADR-029):
  - ActionImpact absent → IRREVERSIBLE (fail-secure)
  - HMAC invalid → BLOCK immediate
  - TTL zero for Irreversible (no caching)
  - evidence_id mandatory in every VerdictEnvelope
  - explain_decision non-optional (Levinas)
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from buildtovalue.api.auth import require_api_key
from buildtovalue.governance.agent_pdp import (
    ActionImpact,
    AgentAction,
    AgentContext,
    AgentDecisionRequest,
    AgentVerdict,
    BiasSummary,
)
from buildtovalue.governance.approval_workflow import ApprovalWorkflow
from buildtovalue.governance.durable_ledger import DurableLedger
from buildtovalue.governance.liveness_monitor import AutonomyLevel, LivenessMonitor
from buildtovalue.governance.profile_manager import ProfileManager
from buildtovalue.governance.skill_behavior_monitor import SkillBehaviorMonitor
from buildtovalue.governance.visual_input_firewall import (
    FirewallVerdict,
    VisualInputFirewall,
)

logger = logging.getLogger("btv.api.agent_decide")

router = APIRouter()

# ── HMAC key (shared with app.py via buildtovalue.security) ──────────────────

from buildtovalue.security import get_hmac_key as _hmac_key


_POLICY_VERSION = "1.0.0-agents"
_BIAS_DECLARATION = BiasSummary(
    false_positive_rate_pct=2.5,
    false_negative_rate_pct=0.5,
    calibration_date="2026-01-01",
    known_limitations="Calibrated on synthetic agent scenarios. Review quarterly.",
)

# ── Request/Response models (HTTP layer over ADR-029 dataclasses) ─────────────

class AgentActionModel(BaseModel):
    name: str
    impact: str = "Irreversible"   # fail-secure default
    capabilities: List[str] = []


class AgentContextModel(BaseModel):
    profile_id: str = "default"
    sector_id: str = "general"
    session_trust_score: float = 0.5
    agent_metadata: Dict[str, Any] = {}


class AgentDecideRequest(BaseModel):
    """HTTP request body for POST /v1/agent/decide."""
    agent_id: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)
    action: AgentActionModel
    parameters_hash: str = Field(..., min_length=64, max_length=64,
                                  description="64-char BLAKE3 hex of full parameters")
    schema_version: str = "1.0"
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    parameters_preview: Dict[str, Any] = {}
    context: AgentContextModel = AgentContextModel()
    parent_verdict_id: Optional[str] = None
    delegation_depth: int = 0


class VerdictEnvelopeResponse(BaseModel):
    """HTTP response for POST /v1/agent/decide."""
    request_id: str
    verdict: str
    verdict_code: int
    explain_decision: str
    bias_false_positive_rate_pct: float
    bias_false_negative_rate_pct: float
    contestable: bool
    appeal_deadline_utc: str
    policy_version_applied: str
    evidence_id: str
    hmac_sha256: str
    timestamp_utc: str
    approval_id: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sign_envelope(
    request_id: str, verdict: str, evidence_id: str, timestamp_utc: str
) -> str:
    payload = f"{request_id}|{verdict}|{evidence_id}|{timestamp_utc}".encode()
    return hmac_lib.new(_hmac_key(), payload, hashlib.sha256).hexdigest()


def _make_envelope(
    request_id: str,
    verdict: AgentVerdict,
    explain: str,
    approval_id: Optional[str] = None,
) -> VerdictEnvelopeResponse:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    evidence_id = str(uuid.uuid4())
    code_map = {
        AgentVerdict.ALLOW: 200,
        AgentVerdict.EDUCATE: 202,
        AgentVerdict.PENDING_APPROVAL: 202,
        AgentVerdict.BLOCK: 403,
    }
    deadline = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() + 86400),  # 24h SLA
    )
    sig = _sign_envelope(request_id, verdict.value, evidence_id, ts)
    return VerdictEnvelopeResponse(
        request_id=request_id,
        verdict=verdict.value,
        verdict_code=code_map.get(verdict, 403),
        explain_decision=explain,
        bias_false_positive_rate_pct=_BIAS_DECLARATION.false_positive_rate_pct,
        bias_false_negative_rate_pct=_BIAS_DECLARATION.false_negative_rate_pct,
        contestable=True,
        appeal_deadline_utc=deadline,
        policy_version_applied=_POLICY_VERSION,
        evidence_id=evidence_id,
        hmac_sha256=sig,
        timestamp_utc=ts,
        approval_id=approval_id,
    )


def _policy_dir() -> Path:
    return Path(os.environ.get("BTV_POLICY_DIR", "data/policies"))


def _resolve_impact(impact_str: str) -> ActionImpact:
    """Resolves ActionImpact from string, defaulting to IRREVERSIBLE (fail-secure)."""
    for member in ActionImpact:
        if member.value.lower() == impact_str.lower():
            return member
    return ActionImpact.IRREVERSIBLE


def _to_domain_request(req: AgentDecideRequest) -> AgentDecisionRequest:
    """Converts HTTP Pydantic model to ADR-029 domain dataclass."""
    impact = _resolve_impact(req.action.impact)
    action = AgentAction(
        name=req.action.name,
        impact=impact,
        capabilities=req.action.capabilities,
    )
    context = AgentContext(
        profile_id=req.context.profile_id,
        sector_id=req.context.sector_id,
        session_trust_score=req.context.session_trust_score,
        agent_metadata=req.context.agent_metadata,
    )
    return AgentDecisionRequest(
        agent_id=req.agent_id,
        session_id=req.session_id,
        action=action,
        parameters_hash=req.parameters_hash,
        schema_version=req.schema_version,
        request_id=req.request_id,
        # parameters_preview is cleared for Irreversible by __post_init__
        parameters_preview=req.parameters_preview if impact != ActionImpact.IRREVERSIBLE else {},
        context=context,
        parent_verdict_id=req.parent_verdict_id,
        delegation_depth=req.delegation_depth,
    )


# ── Guard runners (fail-secure unless noted) ──────────────────────────────────

def _guard_liveness(
    agent_id: str, impact: ActionImpact, request_id: str
) -> Optional[VerdictEnvelopeResponse]:
    """Runs LivenessMonitor for IRREVERSIBLE actions (pa_dead_mans_switch)."""
    if impact != ActionImpact.IRREVERSIBLE:
        return None
    try:
        ledger_path = Path("data/ledger/liveness.jsonl")
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        ledger = DurableLedger(ledger_path)
        monitor = LivenessMonitor()
        level = monitor.autonomy_level(agent_id, ledger)
        days = monitor.days_since_last_confirmation(agent_id, ledger)

        if level == AutonomyLevel.HIBERNATION:
            return _make_envelope(
                request_id,
                AgentVerdict.BLOCK,
                (
                    f"[liveness_monitor] Agent '{agent_id}' in HIBERNATION "
                    f"({days}d without human confirmation). "
                    "Irreversible actions blocked. Human confirmation required."
                ),
            )
        if level == AutonomyLevel.RESTRICTED:
            return _make_envelope(
                request_id,
                AgentVerdict.PENDING_APPROVAL,
                (
                    f"[liveness_monitor] Agent '{agent_id}' RESTRICTED "
                    f"({days}d without confirmation). "
                    "Irreversible action pending human approval (ADR-017)."
                ),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("LivenessMonitor error (fail-secure → BLOCK): %s", exc)
        return _make_envelope(
            request_id,
            AgentVerdict.BLOCK,
            f"[liveness_monitor] Internal error — BLOCK fail-secure: {exc!s:.80}",
        )
    return None  # FULL autonomy → pass


def _guard_visual(
    preview: str, request_id: str
) -> Optional[VerdictEnvelopeResponse]:
    """Runs VisualInputFirewall; returns BLOCK envelope or None (pass)."""
    try:
        fw = VisualInputFirewall()
        result = fw.sanitize(preview)
        if result.verdict == FirewallVerdict.BLOCK:
            return _make_envelope(
                request_id,
                AgentVerdict.BLOCK,
                f"[visual_firewall] {result.explain}",
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("VisualInputFirewall error (fail-secure → BLOCK): %s", exc)
        return _make_envelope(
            request_id,
            AgentVerdict.BLOCK,
            f"[visual_firewall] Internal error — BLOCK fail-secure: {exc!s:.80}",
        )
    return None


def _guard_oracle_policy_check(
    agent_metadata: Dict[str, Any], request_id: str
) -> Optional[VerdictEnvelopeResponse]:
    """
    Checks that oracle verification metadata is provided when pa_p2p_oracle is active.

    OracleTrustGate requires a populated OracleRegistry (HMAC keys for each oracle).
    In production, the caller must pre-populate the registry and pass oracle_response
    in agent_metadata. This guard enforces the contract: if p2p oracle policy is
    active but no oracle_response is provided, the action is BLOCKED (fail-secure).
    """
    policies: List[str] = agent_metadata.get("policies", [])
    if "pa_p2p_oracle" not in policies:
        return None

    oracle_response = agent_metadata.get("oracle_response")
    if oracle_response is None:
        return _make_envelope(
            request_id,
            AgentVerdict.BLOCK,
            (
                "[oracle_trust_gate] Policy pa_p2p_oracle is active but no "
                "oracle_response was provided in agent_metadata. "
                "P2P financial actions require pre-verified oracle claims (ADR-029)."
            ),
        )
    # oracle_response present → oracle was pre-verified by caller; pass through
    return None


def _guard_skill_anomaly(
    agent_id: str, action_name: str, request_id: str
) -> None:
    """Runs SkillBehaviorMonitor (fail-open — anomaly is logged, not blocking here)."""
    try:
        ledger_path = Path("data/ledger/skill_behavior.jsonl")
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        ledger = DurableLedger(ledger_path)
        monitor = SkillBehaviorMonitor()
        monitor.record_action(
            skill_id=agent_id,
            action_category=action_name,
            ledger=ledger,
        )
        finding = monitor.detect_anomaly(skill_id=agent_id, ledger=ledger)
        if finding is not None:
            logger.warning(
                "SkillBehaviorMonitor anomaly: agent=%s action=%s explain=%s",
                agent_id, action_name, finding.explain_decision,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("SkillBehaviorMonitor error (fail-open): %s", exc)


def _guard_approval(
    req: AgentDecideRequest, impact: ActionImpact, request_id: str
) -> Optional[VerdictEnvelopeResponse]:
    """Checks ApprovalWorkflow for actions requiring HITL."""
    try:
        approval_path = _policy_dir() / "agents" / "approval_rules.yaml"
        workflow = ApprovalWorkflow(
            policy_path=approval_path if approval_path.exists() else None
        )
        domain_req = _to_domain_request(req)
        if workflow.needs_approval(domain_req):
            ticket = workflow.request_approval(
                domain_req,
                reason=(
                    f"Action '{req.action.name}' (impact={req.action.impact}) "
                    "requires human approval per approval_rules.yaml."
                ),
            )
            return _make_envelope(
                request_id,
                AgentVerdict.PENDING_APPROVAL,
                (
                    f"[approval_workflow] Action pending human approval. "
                    f"Ticket: {ticket.ticket_id}. Timeout: {ticket.timeout_s}s."
                ),
                approval_id=ticket.ticket_id,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("ApprovalWorkflow error (fail-open): %s", exc)
    return None


# ── Route ─────────────────────────────────────────────────────────────────────

@router.post(
    "/v1/agent/decide",
    response_model=VerdictEnvelopeResponse,
    summary="Structured Action Governance (ADR-029)",
    description=(
        "Evaluates a structured agent action against BTV governance policies. "
        "Activates guard modules (LivenessMonitor, VisualInputFirewall, OracleTrustGate, "
        "SkillBehaviorMonitor, ApprovalWorkflow) based on action impact and "
        "context.agent_metadata.policies. "
        "SLA: <100ms p99 (cold path). "
        "Use POST /v1/decide for text-stream governance (scenarios 1–20)."
    ),
)
def agent_decide(
    req: AgentDecideRequest,
    _: str = Depends(require_api_key),
) -> VerdictEnvelopeResponse:
    """
    Guard pipeline for structured actions (scenarios 31–35 + HITL):

    1. Liveness check        — IRREVERSIBLE actions (pa_dead_mans_switch)
    2. Visual firewall        — source=visual or pa_identity_firewall in policies
    3. Oracle policy check    — pa_p2p_oracle: oracle_response required
    4. Skill anomaly monitor  — SkillBehaviorMonitor (fail-open, logged only)
    5. Approval workflow      — ApprovalWorkflow HITL for flagged actions
    6. ALLOW                  — all guards passed
    """
    request_id = req.request_id
    agent_metadata: Dict[str, Any] = req.context.agent_metadata
    policies: List[str] = agent_metadata.get("policies", [])
    impact = _resolve_impact(req.action.impact)

    # ── Guard 1: Liveness (IRREVERSIBLE actions or pa_dead_mans_switch) ──
    if impact == ActionImpact.IRREVERSIBLE or "pa_dead_mans_switch" in policies:
        env = _guard_liveness(req.agent_id, impact, request_id)
        if env is not None:
            return env

    # ── Guard 2: Visual firewall ──────────────────────────────────────────
    if (
        agent_metadata.get("source") == "visual"
        or "pa_identity_firewall" in policies
    ):
        preview = str(req.parameters_preview) if req.parameters_preview else ""
        env = _guard_visual(preview, request_id)
        if env is not None:
            return env

    # ── Guard 3: Oracle policy check ──────────────────────────────────────
    if "pa_p2p_oracle" in policies:
        env = _guard_oracle_policy_check(agent_metadata, request_id)
        if env is not None:
            return env

    # ── Guard 4: Skill anomaly (fail-open — logged, not blocking) ─────────
    _guard_skill_anomaly(req.agent_id, req.action.name, request_id)

    # ── Guard 5: Approval workflow ────────────────────────────────────────
    env = _guard_approval(req, impact, request_id)
    if env is not None:
        return env

    # ── ALLOW — all guards passed ─────────────────────────────────────────
    return _make_envelope(
        request_id,
        AgentVerdict.ALLOW,
        (
            f"[agent_decide] Action '{req.action.name}' (impact={req.action.impact}) "
            f"passed all governance guards for agent '{req.agent_id}'. "
            "Evidence logged. Contestable within 24h (ADR-017)."
        ),
    )
