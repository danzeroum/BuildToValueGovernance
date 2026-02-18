"""
BuildToValue Governance API v2.1
Python side of the República Algorítmica (Judiciário).
Trust scores persist in SQLite. Appeals via ContestabilityLoop.
"""

import hashlib
import hmac
import logging
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from enum import Enum

from buildtovalue.compliance.plugin import ComplianceReport
from buildtovalue.compliance.lgpd_plugin import LGPDPlugin
from buildtovalue.compliance.eu_ai_act_plugin import EUAIActPlugin
from buildtovalue.governance.contestability_loop import (
    ContestabilityLoop,
    AppealStatus,
)
from buildtovalue.governance.profile_manager import ProfileManager
from buildtovalue.governance.sector_loader import SectorLoader
from buildtovalue.api.auth import require_api_key
from buildtovalue.api.routes.intelligence import get_ingestor, hydrate_from_sqlite
from buildtovalue.intelligence.misp_ingestor import ThreatEvent as BridgeThreatEvent
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# HMAC KEY (Gap #10 — env var, fail-secure in production)
# ═══════════════════════════════════════════════════════════════

def _load_hmac_key() -> bytes:
    key = os.environ.get("BTV_HMAC_KEY")
    if key:
        return key.encode("utf-8")
    env = os.environ.get("BTV_ENV", "development")
    if env == "production":
        raise RuntimeError(
            "BTV_HMAC_KEY must be set in production. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    logger.warning("BTV_HMAC_KEY not set — using dev fallback.")
    return b"btv-dev-key-NOT-FOR-PRODUCTION"


HMAC_KEY = _load_hmac_key()


# ═══════════════════════════════════════════════════════════════
# DATABASE (SQLite trust persistence)
# ═══════════════════════════════════════════════════════════════

DB_PATH = os.environ.get("BTV_DB_PATH", "data/trust.db")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            trust_score REAL NOT NULL DEFAULT 0.5,
            offenses INTEGER NOT NULL DEFAULT 0,
            total_requests INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def db_get_session(session_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT trust_score, offenses, total_requests "
        "FROM sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    conn.close()
    if row:
        return {"trust_score": row[0], "offenses": row[1], "total_requests": row[2]}
    return {"trust_score": 0.5, "offenses": 0, "total_requests": 0}


def db_update_session(session_id: str, trust_score: float, offense_delta: int):
    conn = sqlite3.connect(DB_PATH)
    existing = conn.execute(
        "SELECT session_id FROM sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE sessions SET trust_score = ?, offenses = offenses + ?, "
            "total_requests = total_requests + 1, updated_at = datetime('now') "
            "WHERE session_id = ?",
            (trust_score, offense_delta, session_id),
        )
    else:
        conn.execute(
            "INSERT INTO sessions (session_id, trust_score, offenses, total_requests) "
            "VALUES (?, ?, ?, 1)",
            (session_id, trust_score, offense_delta),
        )
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════
# MODELS — Governance
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
    profile: Optional[str] = None
    input_text: Optional[str] = None


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
# MODELS — Appeals (ADR-017)
# ═══════════════════════════════════════════════════════════════

class AppealStatusEnum(str, Enum):
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"


class AppealSubmitRequest(BaseModel):
    audit_trail_id: int = Field(..., description="ID da decisão contestada")
    user_id: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=20)
    evidence: Optional[str] = None


class AppealResponse(BaseModel):
    appeal_id: str
    audit_trail_id: int
    user_id: str
    timestamp: int
    reason: str
    evidence_provided: Optional[str] = None
    status: AppealStatusEnum
    reviewer_notes: Optional[str] = None
    resolution_timestamp: Optional[int] = None
    sla_deadline: int
    is_overdue: bool


class AppealListResponse(BaseModel):
    appeals: List[AppealResponse]
    total: int


class AppealResolveRequest(BaseModel):
    accepted: bool
    reviewer_notes: str = Field(..., min_length=10)
    reviewer_id: str = Field(..., min_length=1)


class AppealMetricsResponse(BaseModel):
    appeals_submitted: int
    appeals_accepted: int
    appeals_rejected: int
    sla_violations: int
    pending_appeals: int
    sla_compliance_rate: float
    appeal_success_rate: float


# ═══════════════════════════════════════════════════════════════
# MODELS — Compliance & Intelligence
# ═══════════════════════════════════════════════════════════════

class ComplianceRequest(BaseModel):
    framework: str
    evidence: dict = {}
    verdict: dict = {}


class ThreatIngestRequest(BaseModel):
    id: str
    threat_type: str
    severity: int
    source: str = "manual"
    indicators: List[str] = []
    description: str = ""
    mitre_id: str = ""


class ThreatQueryRequest(BaseModel):
    threat_type: Optional[str] = None
    min_severity: int = 0
    source: Optional[str] = None
    limit: int = 50


# ═══════════════════════════════════════════════════════════════
# BUSINESS LOGIC
# ═══════════════════════════════════════════════════════════════

COMPLIANCE_PLUGINS = {
    "LGPD": LGPDPlugin(),
    "EU_AI_ACT": EUAIActPlugin(),
}


def calculate_mercy(
    composite_risk: float,
    critical_count: int,
    trust_score: float,
    is_first_offense: bool,
) -> tuple:
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
    return {"BLOCK": "EDUCATE", "REDACT": "LOG", "EDUCATE": "LOG", "LOG": "ALLOW"}.get(action, action)


def get_trust_score(session_id: Optional[str]) -> float:
    if not session_id:
        return 0.5
    return db_get_session(session_id)["trust_score"]


def update_trust(session_id: Optional[str], action: str) -> float:
    if not session_id:
        return 0.5
    session = db_get_session(session_id)
    current = session["trust_score"]
    if action in ("ALLOW", "LOG"):
        current = min(1.0, current + 0.02)
    elif action == "EDUCATE":
        current = max(0.0, current - 0.05)
    elif action == "BLOCK":
        current = max(0.0, current - 0.15)
    offense_delta = 1 if action not in ("ALLOW", "LOG") else 0
    db_update_session(session_id, current, offense_delta)
    return current


def is_first_offense(session_id: Optional[str]) -> bool:
    if not session_id:
        return True
    return db_get_session(session_id)["offenses"] == 0


def sign_verdict(verdict_id: str, action: str, risk: float) -> str:
    payload = f"{verdict_id}:{action}:{risk:.4f}"
    return hmac.new(HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()


def build_rationale(
    original_action: str, final_action: str,
    mercy_applied: bool, mercy_reason: str,
    trust_score: float, risk: float,
    findings: int, critical: int,
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


def _appeal_to_response(appeal) -> AppealResponse:
    return AppealResponse(
        appeal_id=appeal.appeal_id,
        audit_trail_id=appeal.audit_trail_id,
        user_id=appeal.user_id,
        timestamp=appeal.timestamp,
        reason=appeal.reason,
        evidence_provided=appeal.evidence_provided,
        status=appeal.status.value,
        reviewer_notes=appeal.reviewer_notes,
        resolution_timestamp=appeal.resolution_timestamp,
        sla_deadline=appeal.sla_deadline,
        is_overdue=appeal.is_overdue(),
    )


# ═══════════════════════════════════════════════════════════════
# FASTAPI APP + ROUTERS
# ═══════════════════════════════════════════════════════════════

app = FastAPI(title="BuildToValue Governance", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register modular routers ──────────────────────────────────
from buildtovalue.api.routes.intelligence import router as intelligence_router
from buildtovalue.api.routes.ledger import router as ledger_router
from buildtovalue.api.routes.webhooks import router as webhooks_router

app.include_router(intelligence_router)
app.include_router(ledger_router)
app.include_router(webhooks_router)


# ═══════════════════════════════════════════════════════════════
# GLOBALS
# ═══════════════════════════════════════════════════════════════

_contestability_loop: Optional[ContestabilityLoop] = None
_profile_manager: Optional[ProfileManager] = None
_sector_loader: Optional[SectorLoader] = None


@app.on_event("startup")
def startup():
    global _contestability_loop, _profile_manager, _sector_loader
    init_db()

    from buildtovalue.intelligence.threat_feed import init_threats_db
    init_threats_db()

    _contestability_loop = ContestabilityLoop(sla_hours=24)

    root = Path(__file__).resolve().parent.parent.parent.parent
    profiles_dir = root / "data" / "policies" / "agents"
    if profiles_dir.exists():
        _profile_manager = ProfileManager(profiles_dir)
        logger.info("ProfileManager initialized: %s", profiles_dir)
    else:
        logger.warning("Profiles dir not found: %s", profiles_dir)

    _sector_loader = SectorLoader()
    logger.info("SectorLoader initialized")
    hydrated = hydrate_from_sqlite()
    logger.info(f"Bridge hydration: {hydrated} threats loaded from SQLite")
    from buildtovalue.api.auth import init_auth
    init_auth()


# ═══════════════════════════════════════════════════════════════
# GOVERNANCE — /v1/decide
# ═══════════════════════════════════════════════════════════════

@app.post("/v1/decide", response_model=VerdictResponse)
def decide(req: EvidenceRequest, _=Depends(require_api_key)):
    start = time.perf_counter()
    verdict_id = f"verd_{uuid.uuid4().hex[:12]}"
    session_id = req.session_id

    if req.action == "ALLOW":
        trust = get_trust_score(session_id)
        update_trust(session_id, "ALLOW")
        sig = sign_verdict(verdict_id, "ALLOW", req.composite_risk)
        latency = (time.perf_counter() - start) * 1000
        return VerdictResponse(
            verdict_id=verdict_id, action="ALLOW", original_action="ALLOW",
            mercy_applied=False, trust_score=trust, adjusted_risk=req.composite_risk,
            rationale="Clean input. Trust updated.",
            contestable=False, appeal_deadline_hours=0,
            signature=sig, latency_ms=latency,
        )

    if req.hard_blocked:
        update_trust(session_id, "BLOCK")
        sig = sign_verdict(verdict_id, "BLOCK", req.composite_risk)
        latency = (time.perf_counter() - start) * 1000
        return VerdictResponse(
            verdict_id=verdict_id, action="BLOCK", original_action="BLOCK",
            mercy_applied=False, trust_score=get_trust_score(session_id),
            adjusted_risk=req.composite_risk,
            rationale="Hard block: dangerous content detected. Non-contestable.",
            contestable=False, appeal_deadline_hours=0,
            signature=sig, latency_ms=latency,
        )

    # Profile-aware risk adjustment (Gap #4)
    profile_risk_multiplier = 1.0
    sector_id = None
    sector_note = ""

    if req.profile and _profile_manager:
        try:
            loaded_profile = _profile_manager.load_profile(req.profile)
            domain_keys = [k for k in loaded_profile.domain_config.keys() if k != "general"]
            if domain_keys:
                sector_id = domain_keys[0]
        except ValueError:
            logger.warning("Profile not found: %s", req.profile)

    if sector_id and _sector_loader and req.input_text:
        matched_types = [p.split(":")[0] for p in req.matched_policies]
        profile_risk_multiplier = _sector_loader.apply_whitelist(
            input_text=req.input_text, findings=matched_types, sector_id=sector_id,
        )
        if profile_risk_multiplier < 1.0:
            req.composite_risk *= profile_risk_multiplier
            sector_note = (
                f" Sector context ({sector_id}) reduced risk "
                f"by {(1 - profile_risk_multiplier) * 100:.0f}%."
            )

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
    ) + sector_note

    sig = sign_verdict(verdict_id, final_action, req.composite_risk)
    update_trust(session_id, final_action)
    latency = (time.perf_counter() - start) * 1000

    return VerdictResponse(
        verdict_id=verdict_id, action=final_action, original_action=original_action,
        mercy_applied=mercy_applied, trust_score=trust, adjusted_risk=req.composite_risk,
        rationale=rationale, contestable=True, appeal_deadline_hours=24,
        signature=sig, latency_ms=latency,
    )


# ═══════════════════════════════════════════════════════════════
# APPEALS — /v1/appeals (ADR-017, Levinas)
# ═══════════════════════════════════════════════════════════════

@app.post("/v1/appeals", response_model=AppealResponse, status_code=201)
def submit_appeal(req: AppealSubmitRequest):
    try:
        appeal = _contestability_loop.submit_appeal(
            audit_trail_id=req.audit_trail_id,
            user_id=req.user_id,
            reason=req.reason,
            evidence=req.evidence,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _appeal_to_response(appeal)


@app.get("/v1/appeals/metrics", response_model=AppealMetricsResponse)
def appeals_metrics():
    _contestability_loop.list_expired_appeals()
    return AppealMetricsResponse(**_contestability_loop.get_metrics())


@app.get("/v1/appeals/{appeal_id}", response_model=AppealResponse)
def get_appeal(appeal_id: str):
    appeal = _contestability_loop.get_appeal(appeal_id)
    if appeal is None:
        raise HTTPException(status_code=404, detail=f"Appeal not found: {appeal_id}")
    return _appeal_to_response(appeal)


@app.get("/v1/appeals", response_model=AppealListResponse)
def list_appeals(status: Optional[str] = None, user_id: Optional[str] = None):
    _contestability_loop.list_expired_appeals()
    appeals = list(_contestability_loop.appeals.values())
    if status:
        try:
            target_status = AppealStatus(status)
            appeals = [a for a in appeals if a.status == target_status]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    if user_id:
        appeals = [a for a in appeals if a.user_id == user_id]
    return AppealListResponse(
        appeals=[_appeal_to_response(a) for a in appeals],
        total=len(appeals),
    )


@app.post("/v1/appeals/{appeal_id}/resolve", response_model=AppealResponse)
def resolve_appeal(appeal_id: str, req: AppealResolveRequest):
    existing = _contestability_loop.get_appeal(appeal_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Appeal not found: {appeal_id}")
    if existing.status in (AppealStatus.ACCEPTED, AppealStatus.REJECTED):
        raise HTTPException(status_code=409, detail=f"Already resolved: {existing.status.value}")
    try:
        resolved = _contestability_loop.resolve_appeal(
            appeal_id=appeal_id, accepted=req.accepted,
            reviewer_notes=req.reviewer_notes, reviewer_id=req.reviewer_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _appeal_to_response(resolved)


# ═══════════════════════════════════════════════════════════════
# HEALTH & TRUST
# ═══════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    conn = sqlite3.connect(DB_PATH)
    sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    conn.close()
    return {
        "status": "healthy",
        "service": "btv-governance",
        "version": "2.1.0",
        "sessions_tracked": sessions,
        "persistence": "sqlite",
        "appeals_pending": len(_contestability_loop.list_pending_appeals()) if _contestability_loop else 0,
    }


@app.get("/v1/trust/{session_id}")
def get_trust(session_id: str, _=Depends(require_api_key)):
    session = db_get_session(session_id)
    return {
        "session_id": session_id,
        "trust_score": session["trust_score"],
        "offenses": session["offenses"],
        "total_requests": session["total_requests"],
    }


# ═══════════════════════════════════════════════════════════════
# COMPLIANCE — /v1/compliance
# ═══════════════════════════════════════════════════════════════

@app.post("/v1/compliance/check")
def compliance_check(req: ComplianceRequest, _=Depends(require_api_key)):
    plugin = COMPLIANCE_PLUGINS.get(req.framework)
    if not plugin:
        return {"error": f"Unknown framework: {req.framework}. Available: {list(COMPLIANCE_PLUGINS.keys())}"}
    artifacts = plugin.generate_artifacts(req.evidence, req.verdict)
    compliant = sum(1 for a in artifacts if a.status.value == "COMPLIANT")
    return {
        "framework": req.framework,
        "total": len(artifacts),
        "compliant": compliant,
        "compliance_rate": compliant / len(artifacts) if artifacts else 0,
        "artifacts": [
            {"article": a.article, "requirement": a.requirement,
             "status": a.status.value, "evidence": a.evidence,
             "recommendation": a.recommendation}
            for a in artifacts
        ],
    }


@app.get("/v1/compliance/frameworks")
def list_frameworks(_=Depends(require_api_key)):
    return {
        "frameworks": [
            {"id": p.framework_id(), "name": p.framework_name()}
            for p in COMPLIANCE_PLUGINS.values()
        ]
    }


@app.get("/v1/compliance/report/{framework}")
def compliance_report(framework: str, _=Depends(require_api_key)):
    plugin = COMPLIANCE_PLUGINS.get(framework)
    if not plugin:
        return {"error": f"Unknown framework: {framework}"}
    report = plugin.validate_requirements()
    return {
        "framework": report.framework,
        "version": report.version,
        "total_requirements": report.total_requirements,
        "compliant": report.compliant,
        "partial": report.partial,
        "non_compliant": report.non_compliant,
        "compliance_rate": report.compliance_rate,
        "generated_at": report.generated_at,
        "artifacts": [
            {"article": a.article, "requirement": a.requirement,
             "status": a.status.value, "evidence": a.evidence,
             "recommendation": a.recommendation}
            for a in report.artifacts
        ],
    }


# ═══════════════════════════════════════════════════════════════
# INTELLIGENCE HUB — /v1/intelligence (inline, SQLite-backed)
# ═══════════════════════════════════════════════════════════════

from buildtovalue.intelligence.threat_feed import (
    ingest_threat, query_threats, get_threat, get_stats,
)


@app.post("/v1/intelligence/ingest")
def intelligence_ingest(req: ThreatIngestRequest, _=Depends(require_api_key)):
    result = ingest_threat(
        req.id, req.threat_type, req.severity, req.source,
        req.indicators, req.description, req.mitre_id,
    )

    # 2. Feed bridge's in-memory ingestor (Gap #8 unification)
    try:
        get_ingestor().ingest(BridgeThreatEvent(
            id=req.id,
            threat_type=req.threat_type,
            severity=req.severity,
            source=req.source,
            indicators=req.indicators or [],
        ))
    except Exception as exc:
        logger.warning("Bridge ingestor feed failed (non-blocking): %s", exc)

    return result


@app.post("/v1/intelligence/ingest/batch")
def intelligence_ingest_batch(threats: List[ThreatIngestRequest], _=Depends(require_api_key)):
    results = [
        ingest_threat(t.id, t.threat_type, t.severity, t.source,
                      t.indicators, t.description, t.mitre_id)
        for t in threats
    ]
    return {"ingested": len(results), "results": results}


@app.post("/v1/intelligence/query")
def intelligence_query(req: ThreatQueryRequest, _=Depends(require_api_key)):
    threats = query_threats(req.threat_type, req.min_severity, req.source, req.limit)
    return {"count": len(threats), "threats": threats}


@app.get("/v1/intelligence/threat/{threat_id}")
def intelligence_get(threat_id: str, _=Depends(require_api_key)):
    threat = get_threat(threat_id)
    if not threat:
        return {"error": f"Threat {threat_id} not found"}
    return threat


@app.get("/v1/intelligence/stats")
def intelligence_stats(_=Depends(require_api_key)):
    return get_stats()