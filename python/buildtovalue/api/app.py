"""
BuildToValue Governance API v2.2
Python side of the República Algorítmica (Judiciário).
Trust scores persist in SQLite. Appeals via ContestabilityLoop.
SLM Classifier (ADR-027) for semantic ambiguity zone.
EthicalContextEngine (P8) orchestrates mercy + trust + HMAC.
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

from buildtovalue.intelligence.slm_classifier import SLMClassifier
from buildtovalue.compliance.plugin import ComplianceReport
from buildtovalue.compliance.lgpd_plugin import LGPDPlugin
from buildtovalue.compliance.eu_ai_act_plugin import EUAIActPlugin
from buildtovalue.governance.contestability_loop import (
    ContestabilityLoop,
    AppealStatus,
)
from buildtovalue.governance.profile_manager import ProfileManager
from buildtovalue.governance.sector_loader import SectorLoader
from buildtovalue.governance.context_engine import (
    EthicalContextEngine,
    RequestContext,
    RustEvidence,
)
from buildtovalue.governance.mercy_scenarios import ACTION_SEVERITY, SEVERITY_ACTION
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
    return b"btv-dev-key-NOT-FOR-PRODUCTION!!"


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

class DecideRequest(BaseModel):
    """Request from Rust Gateway (or direct call)."""
    input_text: str = ""
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
    # Evidence metadata
    entropy: float = 0.0
    total_chars: int = 0
    blake3_hash: str = ""
    max_finding_confidence: float = 0.0
    # Context (from Rust Network/Session modules)
    ip_risk: str = "Low"
    ip_jurisdiction: str = "XX"
    drift_level: str = "None"


class DecideResponse(BaseModel):
    verdict_id: str
    action: str
    original_action: str
    mercy_applied: bool
    mercy_scenario: str = ""
    mercy_score: float = 0.0
    trust_score: float
    adjusted_risk: float
    rationale: str
    contestable: bool
    appeal_deadline_hours: int
    signature: str
    latency_ms: float
    slm_used: bool = False
    slm_intent: Optional[str] = None
    slm_risk: Optional[float] = None


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


def _resolve_domain(profile: Optional[str]) -> str:
    mapping = {
        "medical": "medical",
        "healthcare": "medical",
        "financial": "finance",
        "legal": "legal",
        "research": "research",
        "education": "education",
    }
    return mapping.get(profile or "", "general")


def _resolve_role(session_id: str) -> str:
    """In prod: lookup from session DB. For now: anonymous."""
    return "anonymous"


def _load_slm_config() -> dict:
    """Load SLM config from YAML. Returns empty dict if not found."""
    try:
        import yaml
        config_path = Path(__file__).resolve().parent.parent.parent.parent / "data" / "policies" / "core" / "slm.yaml"
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f).get("slm", {})
    except Exception as e:
        logger.warning("Failed to load SLM config: %s", e)
    return {}


# ═══════════════════════════════════════════════════════════════
# FASTAPI APP + ROUTERS
# ═══════════════════════════════════════════════════════════════

app = FastAPI(title="BuildToValue Governance", version="2.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

from buildtovalue.api.routes.intelligence import router as intelligence_router
from buildtovalue.api.routes.ledger import router as ledger_router
from buildtovalue.api.routes.webhooks import router as webhooks_router
from buildtovalue.api.routes.compliance_eval import router as compliance_eval_router
app.include_router(intelligence_router)
app.include_router(ledger_router)
app.include_router(webhooks_router)
app.include_router(compliance_eval_router)


# ═══════════════════════════════════════════════════════════════
# GLOBALS
# ═══════════════════════════════════════════════════════════════

_contestability_loop: Optional[ContestabilityLoop] = None
_profile_manager: Optional[ProfileManager] = None
_sector_loader: Optional[SectorLoader] = None
_slm: Optional[SLMClassifier] = None
_ethical_engine: Optional[EthicalContextEngine] = None


@app.on_event("startup")
def startup():
    global _contestability_loop, _profile_manager, _sector_loader
    global _slm, _ethical_engine

    init_db()

    from buildtovalue.intelligence.threat_feed import init_threats_db
    init_threats_db()

    _contestability_loop = ContestabilityLoop(sla_hours=24)

    # ── EthicalContextEngine (P8) ─────────────────────────────
    _ethical_engine = EthicalContextEngine(signing_key=HMAC_KEY)

    # ── Profiles ──────────────────────────────────────────────
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

    # ── SLM Classifier (ADR-027) ──────────────────────────────
    slm_config = _load_slm_config()
    if slm_config.get("enabled", False):
        _slm = SLMClassifier(
            model_path=slm_config["model_path"],
            model_id=slm_config.get("model_id", "local-slm"),
            n_ctx=slm_config.get("n_ctx", 512),
            n_threads=slm_config.get("n_threads", 2),
            timeout_ms=slm_config.get("timeout_ms", 100),
        )
        if _slm.load_model():
            logger.info("SLM loaded: %s", slm_config["model_path"])
        else:
            logger.warning("SLM failed to load — disabled")
            _slm = None
    else:
        logger.info("SLM disabled (slm.enabled=false or config missing)")

    from buildtovalue.api.auth import init_auth
    init_auth()


# ═══════════════════════════════════════════════════════════════
# GOVERNANCE — /v1/decide (Judiciário da República Algorítmica)
# ═══════════════════════════════════════════════════════════════

@app.post("/v1/decide", response_model=DecideResponse)
def decide(req: DecideRequest, _=Depends(require_api_key)):
    """
    Pipeline:
      0. Hard block → BLOCK imediato
      1. SLM (ambiguity zone only — ADR-027)
      2. Profile/sector risk adjustment
      3. EthicalContextEngine.decide() → mercy + trust + HMAC
      4. Return signed, explainable, contestable verdict
    """
    start = time.perf_counter()
    session_id = req.session_id or "anonymous"

    # ── Step 0: Hard block — no governance, no mercy ──────────
    if req.hard_blocked:
        update_trust(session_id, "BLOCK")
        sig = sign_verdict(f"VRD-HB-{int(time.time())}", "BLOCK", req.composite_risk)
        return DecideResponse(
            verdict_id=f"VRD-HB-{int(time.time())}",
            action="BLOCK", original_action="BLOCK",
            mercy_applied=False, mercy_scenario="HARD_BLOCK",
            mercy_score=0.0,
            trust_score=get_trust_score(session_id),
            adjusted_risk=req.composite_risk,
            rationale=f"Hard block triggered. Matched: {req.matched_policies}. "
                      "No mercy applicable. Contestable within 24h.",
            contestable=True, appeal_deadline_hours=24,
            signature=sig,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    # ── Step 1: SLM classification (ambiguity zone) ───────────
    slm_used = False
    slm_intent = None
    slm_risk = None
    adjusted_finding_count = req.finding_count
    adjusted_critical_count = req.critical_count
    adjusted_risk = req.composite_risk
    adjusted_action = req.action

    if _slm is not None:
        slm_result = _slm.classify_if_ambiguous(
            text=req.input_text,
            finding_count=req.finding_count,
            max_confidence=req.max_finding_confidence,
        )
        if slm_result is not None:
            slm_used = True
            slm_intent = slm_result.intent.value
            slm_risk = slm_result.risk

            if slm_result.is_malicious:
                adjusted_finding_count += 1
                if slm_result.risk >= 0.8:
                    adjusted_critical_count += 1
                adjusted_risk = min(1.0, adjusted_risk + slm_result.risk * 0.3)

                current_sev = ACTION_SEVERITY.get(adjusted_action, 0)
                slm_sev = 2 if slm_result.risk < 0.7 else 3
                if slm_sev > current_sev:
                    adjusted_action = SEVERITY_ACTION.get(slm_sev, "EDUCATE")

                logger.info(
                    "SLM escalation: %s→%s (intent=%s, risk=%.2f)",
                    req.action, adjusted_action, slm_intent, slm_result.risk,
                )

    # ── Step 2: Profile/sector risk adjustment ────────────────
    sector_note = ""
    if req.profile and _profile_manager and _sector_loader and req.input_text:
        try:
            loaded_profile = _profile_manager.load_profile(req.profile)
            domain_keys = [k for k in loaded_profile.domain_config.keys() if k != "general"]
            if domain_keys:
                sector_id = domain_keys[0]
                matched_types = [p.split(":")[0] for p in req.matched_policies]
                multiplier = _sector_loader.apply_whitelist(
                    input_text=req.input_text, findings=matched_types, sector_id=sector_id,
                )
                if multiplier < 1.0:
                    adjusted_risk *= multiplier
                    sector_note = (
                        f" Sector context ({sector_id}) reduced risk "
                        f"by {(1 - multiplier) * 100:.0f}%."
                    )
        except ValueError:
            logger.warning("Profile not found: %s", req.profile)

    # ── Step 3: EthicalContextEngine → EthicalVerdict ─────────
    evidence = RustEvidence(
        composite_risk=adjusted_risk,
        finding_count=adjusted_finding_count,
        critical_count=adjusted_critical_count,
        entropy=req.entropy,
        total_chars=req.total_chars,
        policy_action=adjusted_action,
        blake3_hash=req.blake3_hash,
    )

    context = RequestContext(
        agent_id=req.profile or "default",
        session_id=session_id,
        domain=_resolve_domain(req.profile),
        user_role=_resolve_role(session_id),
        ip_jurisdiction=req.ip_jurisdiction,
        ip_risk=req.ip_risk,
        drift_level=req.drift_level,
    )

    trust = get_trust_score(session_id)
    _ethical_engine.set_trust_score(session_id, trust)

    verdict = _ethical_engine.decide(evidence, context)

    # ── Step 4: Update trust + respond ────────────────────────
    update_trust(session_id, verdict.final_action)
    latency = (time.perf_counter() - start) * 1000

    rationale = verdict.explanation + sector_note

    return DecideResponse(
        verdict_id=verdict.verdict_id,
        action=verdict.final_action,
        original_action=req.action,
        mercy_applied=verdict.mercy_applied,
        mercy_scenario=verdict.mercy_scenario,
        mercy_score=verdict.mercy_score,
        trust_score=verdict.trust_score,
        adjusted_risk=adjusted_risk,
        rationale=rationale,
        contestable=verdict.contestable,
        appeal_deadline_hours=24,
        signature=verdict.hmac_signature,
        latency_ms=latency,
        slm_used=slm_used,
        slm_intent=slm_intent,
        slm_risk=slm_risk,
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
        "version": "2.2.0",
        "sessions_tracked": sessions,
        "persistence": "sqlite",
        "slm_loaded": _slm is not None and _slm.is_loaded,
        "ethical_engine": _ethical_engine is not None,
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
# SLM METRICS — /v1/slm
# ═══════════════════════════════════════════════════════════════

@app.get("/v1/slm/metrics")
def slm_metrics(_=Depends(require_api_key)):
    if _slm is None:
        return {"enabled": False, "message": "SLM not loaded"}
    return {"enabled": True, **_slm.get_metrics()}


@app.get("/v1/slm/bias")
def slm_bias(_=Depends(require_api_key)):
    if _slm is None:
        return {"enabled": False, "message": "SLM not loaded"}
    b = _slm.get_bias_declaration()
    return {
        "enabled": True,
        "fpr": b.fpr, "fnr": b.fnr,
        "calibration_date": b.calibration_date,
        "sample_size": b.sample_size,
        "model_id": b.model_id,
        "limitations": b.limitations,
        "affected_groups": b.affected_groups,
    }


# ═══════════════════════════════════════════════════════════════
# INTELLIGENCE HUB — /v1/intelligence (SQLite-backed)
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