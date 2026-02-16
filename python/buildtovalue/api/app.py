"""
BuildToValue Governance API v1.2
Python side of the República Algorítmica (Judiciário).
Receives evidence from Rust Gateway, returns ethical verdict.
"""

import time
import uuid
import hmac
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ═══════════════════════════════════════════════════════════════
# MODELS (Pydantic - HTTP contracts)
# ═══════════════════════════════════════════════════════════════

class EvidenceRequest(BaseModel):
    finding_count: int = 0
    critical_count: int = 0
    composite_risk: float = 0.0
    action: str = "ALLOW"
    hard_blocked: bool = False
    matched_policies: List[str] = []
    session_id: Optional[str] = None
    trust_score: Optional[float] = None
    is_first_offense: Optional[bool] = None


class VerdictResponse(BaseModel):
    verdict_id: str
    action: str
    original_action: str
    mercy_applied: bool
    trust_score: float
    adjusted_risk: float
    rationale: str
    contestable: bool
    appeal_deadline_hours: int
    signature: str
    latency_ms: float


# ═══════════════════════════════════════════════════════════════
# MERCY CALCULATOR (Gilligan)
# ═══════════════════════════════════════════════════════════════

HMAC_KEY = b"btv-sovereign-trust-os-v1"


def calculate_mercy(
    composite_risk: float,
    critical_count: int,
    trust_score: float,
    is_first_offense: bool,
) -> tuple[bool, str]:
    """
    Misericordia Algoritmica (Gilligan):
    - uncertainty > 0.3 (risk < 0.7)
    - trust > 0.6
    - critical == 0
    - first offense
    -> abrandar um nivel
    """
    uncertainty = 1.0 - composite_risk

    if critical_count > 0:
        return False, "Critical findings present - mercy denied"

    if uncertainty > 0.3 and trust_score > 0.6 and is_first_offense:
        return True, (
            f"Mercy granted (Gilligan): uncertainty={uncertainty:.2f}, "
            f"trust={trust_score:.2f}, first_offense=True, critical=0"
        )

    reasons = []
    if uncertainty <= 0.3:
        reasons.append(f"risk too high ({composite_risk:.0%})")
    if trust_score <= 0.6:
        reasons.append(f"trust too low ({trust_score:.2f})")
    if not is_first_offense:
        reasons.append("repeat offense")

    return False, f"Mercy denied: {', '.join(reasons)}"


def soften_action(action: str) -> str:
    """Abrandar um nivel (Levinas: educar antes de punir)."""
    scale = {"BLOCK": "EDUCATE", "REDACT": "LOG", "EDUCATE": "LOG", "LOG": "ALLOW"}
    return scale.get(action, action)


# ═══════════════════════════════════════════════════════════════
# TRUST SCORE
# ═══════════════════════════════════════════════════════════════

SESSION_TRUST: Dict[str, float] = {}


def get_trust_score(session_id: Optional[str]) -> float:
    if not session_id:
        return 0.5
    return SESSION_TRUST.get(session_id, 0.5)


def update_trust(session_id: Optional[str], action: str):
    if not session_id:
        return
    current = SESSION_TRUST.get(session_id, 0.5)
    if action in ("ALLOW", "LOG"):
        current = min(1.0, current + 0.02)
    elif action == "EDUCATE":
        current = max(0.0, current - 0.05)
    elif action == "BLOCK":
        current = max(0.0, current - 0.15)
    SESSION_TRUST[session_id] = current


# ═══════════════════════════════════════════════════════════════
# OFFENSE TRACKER
# ═══════════════════════════════════════════════════════════════

SESSION_OFFENSES: Dict[str, int] = {}


def is_first_offense(session_id: Optional[str]) -> bool:
    if not session_id:
        return True
    return SESSION_OFFENSES.get(session_id, 0) == 0


def record_offense(session_id: Optional[str], action: str):
    if not session_id or action in ("ALLOW", "LOG"):
        return
    SESSION_OFFENSES[session_id] = SESSION_OFFENSES.get(session_id, 0) + 1


# ═══════════════════════════════════════════════════════════════
# SIGN VERDICT (Jonas: responsabilidade)
# ═══════════════════════════════════════════════════════════════

def sign_verdict(verdict_id: str, action: str, risk: float) -> str:
    payload = f"{verdict_id}:{action}:{risk:.4f}"
    return hmac.new(HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()


# ═══════════════════════════════════════════════════════════════
# RATIONALE (explain_decision - obrigatorio)
# ═══════════════════════════════════════════════════════════════

def build_rationale(
    original_action: str,
    final_action: str,
    mercy_applied: bool,
    mercy_reason: str,
    trust_score: float,
    risk: float,
    findings: int,
    critical: int,
) -> str:
    parts = [
        f"Input analysis: {findings} finding(s), {critical} critical, risk {risk:.0%}.",
        f"Policy recommendation: {original_action}.",
        f"Trust score: {trust_score:.2f}.",
    ]
    if mercy_applied:
        parts.append(f"Mercy applied: {original_action} -> {final_action}. {mercy_reason}.")
    else:
        parts.append(f"Final action: {final_action}. {mercy_reason}.")

    parts.append("Decision signed (HMAC-SHA256). Contestable within 24h.")
    return " ".join(parts)


# ═══════════════════════════════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════════════════════════════

app = FastAPI(title="BuildToValue Governance", version="1.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/v1/decide", response_model=VerdictResponse)
def decide(req: EvidenceRequest):
    start = time.perf_counter()

    verdict_id = f"verd_{uuid.uuid4().hex[:12]}"
    session_id = req.session_id

    # ALLOW - just update trust, no judgment needed
    if req.action == "ALLOW":
        trust = get_trust_score(session_id)
        update_trust(session_id, "ALLOW")
        sig = sign_verdict(verdict_id, "ALLOW", req.composite_risk)
        latency = (time.perf_counter() - start) * 1000
        return VerdictResponse(
            verdict_id=verdict_id,
            action="ALLOW",
            original_action="ALLOW",
            mercy_applied=False,
            trust_score=trust,
            adjusted_risk=req.composite_risk,
            rationale="Clean input. Trust updated.",
            contestable=False,
            appeal_deadline_hours=0,
            signature=sig,
            latency_ms=latency,
        )

    # Hard blocks are non-negotiable (Rawls: justice first)
    if req.hard_blocked:
        update_trust(session_id, "BLOCK")
        record_offense(session_id, "BLOCK")
        sig = sign_verdict(verdict_id, "BLOCK", req.composite_risk)
        latency = (time.perf_counter() - start) * 1000
        return VerdictResponse(
            verdict_id=verdict_id,
            action="BLOCK",
            original_action="BLOCK",
            mercy_applied=False,
            trust_score=get_trust_score(session_id),
            adjusted_risk=req.composite_risk,
            rationale="Hard block: dangerous content detected. Non-contestable.",
            contestable=False,
            appeal_deadline_hours=0,
            signature=sig,
            latency_ms=latency,
        )

    # Ethical judgment
    trust = req.trust_score if req.trust_score is not None else get_trust_score(session_id)
    first = req.is_first_offense if req.is_first_offense is not None else is_first_offense(session_id)
    original_action = req.action

    mercy_applied, mercy_reason = calculate_mercy(
        req.composite_risk, req.critical_count, trust, first,
    )

    final_action = soften_action(original_action) if mercy_applied else original_action

    rationale = build_rationale(
        original_action, final_action, mercy_applied, mercy_reason,
        trust, req.composite_risk, req.finding_count, req.critical_count,
    )

    sig = sign_verdict(verdict_id, final_action, req.composite_risk)

    # Update session state
    update_trust(session_id, final_action)
    record_offense(session_id, final_action)

    latency = (time.perf_counter() - start) * 1000

    return VerdictResponse(
        verdict_id=verdict_id,
        action=final_action,
        original_action=original_action,
        mercy_applied=mercy_applied,
        trust_score=trust,
        adjusted_risk=req.composite_risk,
        rationale=rationale,
        contestable=True,
        appeal_deadline_hours=24,
        signature=sig,
        latency_ms=latency,
    )


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "btv-governance",
        "sessions_tracked": len(SESSION_TRUST),
        "version": "1.2.0",
    }


@app.get("/v1/trust/{session_id}")
def get_trust(session_id: str):
    return {
        "session_id": session_id,
        "trust_score": get_trust_score(session_id),
        "offenses": SESSION_OFFENSES.get(session_id, 0),
    }