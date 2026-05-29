"""
BuildToValue Governance API v2.3
Python side of the República Algorítmica (Judiciário).
Trust scores persist in SQLite. Appeals via ContestabilityLoop.
SLM Classifier (ADR-027) for semantic ambiguity zone.
EthicalContextEngine (P8) orchestrates mercy + trust + HMAC.

Changelog v2.3 (Sprint 5, Gaps 10/12/14/19):
  - Gap 12/19: TrustScoreCalculator singleton (activity_log persistido)
  - Gap 14: adjust_post_penalty delta persistido no SQLite
  - Gap 10: GoalDriftSentinel integrado ao pipeline; cross-signal drift×sensitivity
"""

import asyncio
import hashlib
import hmac
import logging
import os
import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from enum import Enum

from contextlib import asynccontextmanager
from buildtovalue.intelligence.slm_classifier import SLMClassifier, SLMContext
from buildtovalue.intelligence.ner_detector import NERDetector
# ADR-0093 Passo 3 r3: ComplianceReport/LGPDPlugin/EUAIActPlugin/FRIAGenerator
# migrados para routes/compliance.py. RiskClassifier permanece (hot path).
from buildtovalue.compliance.risk_classifier import RiskClassifier
from buildtovalue.governance.output_validator import OutputSchemaValidator
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
from buildtovalue.governance.sensitivity_accumulator import (
    SessionSensitivityAccumulator,
    SensitivityState,
)
from buildtovalue.governance.mercy_scenarios import ACTION_SEVERITY, SEVERITY_ACTION
# Gap 10: GoalDriftSentinel integrado ao pipeline
from buildtovalue.governance.goal_drift_sentinel import GoalDriftSentinel, DriftReport
# Gap 12/19: TrustScoreCalculator como singleton (nao mais inline)
from buildtovalue.governance.trust_score import TrustScoreCalculator
from buildtovalue.api.auth import require_api_key
from buildtovalue.api.routes.intelligence import get_ingestor, hydrate_from_sqlite
from buildtovalue.intelligence.misp_ingestor import ThreatEvent as BridgeThreatEvent
from buildtovalue.compliance.risk_classifier import RiskClassifier, RiskClassification
from buildtovalue.governance.cross_agent_correlator import CrossAgentCorrelator
from buildtovalue.governance.delegation_ledger import DelegationLedger
# Guard modules — imported lazily to avoid startup cost when not used
from buildtovalue.governance.visual_input_firewall import (
    VisualInputFirewall,
    FirewallVerdict as VisualFirewallVerdict,
)
from buildtovalue.governance.oracle_trust_gate import OracleTrustGate
from buildtovalue.governance.rag_integrity_verifier import RagIntegrityVerifier
from buildtovalue.governance.ffi_client import get_ffi_client, BridgeNotAvailableError, FFIError
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# GUARD HELPERS — agent_policies, source, channel activation
# ═══════════════════════════════════════════════════════════════

def _block_guard_response(
    session_id: str,
    verdict_id: str,
    guard_name: str,
    explain: str,
    composite_risk: float,
    start: float,
) -> "DecideResponse":
    """Returns a BLOCK DecideResponse from a guard module (fail-secure)."""
    update_trust(session_id, "BLOCK")
    sig = sign_verdict(verdict_id, "BLOCK", composite_risk)
    return DecideResponse(
        verdict_id=verdict_id,
        action="BLOCK",
        original_action="BLOCK",
        mercy_applied=False,
        mercy_scenario=f"GUARD_{guard_name.upper()}",
        mercy_score=0.0,
        trust_score=get_trust_score(session_id),
        adjusted_risk=composite_risk,
        rationale=(
            f"Guard '{guard_name}' blocked request. {explain} "
            "Contestable within 24h (ADR-017)."
        ),
        contestable=True,
        appeal_deadline_hours=24,
        signature=sig,
        latency_ms=(time.perf_counter() - start) * 1000,
        bias_declaration=_build_bias_declaration(
            trust_score=get_trust_score(session_id),
            adjusted_risk=composite_risk,
            mercy_applied=False,
            pii_redacted=False,
            explain=(
                f"Guard '{guard_name}' blocked request. {explain} "
                "Contestable within 24h (ADR-017)."
            ),
        ),
    )


def _run_visual_guard(
    input_text: str, yaml_path: "Optional[Path]"  # noqa: ARG001 — path reserved for future config
) -> "tuple[bool, str]":
    """
    Runs VisualInputFirewall on input_text.

    Returns (blocked: bool, explain: str).
    Fail-secure: any exception → (True, error message).
    """
    try:
        fw = VisualInputFirewall()
        result = fw.sanitize(input_text)
        if result.verdict == VisualFirewallVerdict.BLOCK:
            return True, result.explain or "Visual injection pattern detected."
        return False, ""
    except Exception as exc:  # noqa: BLE001
        logger.warning("VisualInputFirewall error (fail-secure → BLOCK): %s", exc)
        return True, f"VisualInputFirewall internal error: {exc!s:.80}"


def _run_channel_guard(
    channel: str, yaml_path: "Optional[Path]"
) -> "tuple[bool, str, int]":
    """
    Loads pa_channel_hierarchy.yaml and resolves trust level for the given channel.

    Returns (blocked: bool, explain: str, trust_level: int).
    Trust level 0=UNTRUSTED, 1=LOW, 2=MEDIUM, 3=HIGH, 4=SOVEREIGN.
    Fail-secure: unknown channel → trust_level=0 (UNTRUSTED), not blocked by default.
    """
    try:
        import yaml as _yaml
        if yaml_path is None or not yaml_path.exists():
            return False, "", 1  # no config → LOW trust, not blocked
        with open(yaml_path) as f:
            cfg = _yaml.safe_load(f)
        registry: dict = cfg.get("channel_registry", {}) if cfg else {}
        entry = registry.get(channel, {})
        level: int = entry.get("trust_level", 0) if isinstance(entry, dict) else 0
        return False, "", level
    except Exception as exc:  # noqa: BLE001
        logger.warning("ChannelAuthorityVerifier error: %s", exc)
        return False, "", 0


def _run_rag_guard(
    input_text: str, channel_trust: int, yaml_path: "Optional[Path]"
) -> "tuple[bool, str]":
    """
    Runs RagIntegrityVerifier for requests tagged with pa_p2p_oracle.

    Returns (blocked: bool, explain: str).
    Fail-secure: any exception → (True, error message).
    """
    try:
        verifier = RagIntegrityVerifier()
        result = verifier.verify_chunk(input_text)
        if not result.valid:
            return True, result.reason or "RAG integrity check failed."
        return False, ""
    except Exception as exc:  # noqa: BLE001
        logger.warning("RagIntegrityVerifier error (fail-secure → BLOCK): %s", exc)
        return True, f"RagIntegrityVerifier internal error: {exc!s:.80}"


# ═══════════════════════════════════════════════════════════════
# HMAC KEY (Gap #10 — env var, fail-secure in production)
# ═══════════════════════════════════════════════════════════════

from buildtovalue.security import get_hmac_key, init_hmac_key, sqlite_connect_wal


_risk_classifier: Optional[RiskClassifier] = RiskClassifier()

# ═══════════════════════════════════════════════════════════════
# DATABASE (SQLite trust persistence)
# ═══════════════════════════════════════════════════════════════

DB_PATH = os.environ.get("BTV_DB_PATH", "data/trust.db")


# ADR-0093 Phase 2 (Passo 3): camada SQLite extraída para api/_db.py.
# Reimportada aqui para preservar os call-sites internos e o lifespan.
from buildtovalue.api._db import (  # noqa: E402
    DB_PATH,
    db_get_session,
    db_update_session,
    db_update_session_state,
    init_db,
)


# ═══════════════════════════════════════════════════════════════
# MODELS — Governance
# ═══════════════════════════════════════════════════════════════

# ADR-0093: contratos de dados extraídos para api/_models.py.
from buildtovalue.api._models import (  # noqa: E402
    AppealListResponse,
    AppealMetricsResponse,
    AppealResolveRequest,
    AppealResponse,
    AppealStatusEnum,
    AppealSubmitRequest,
    BiasDeclaration,
    ComplianceRequest,
    DecideRequest,
    DecideResponse,
    FRIARequest,
    MultiDecideRequest,
    MultiDecideResponse,
    RiskClassifyRequest,
    ThreatIngestRequest,
    ThreatQueryRequest,
)


# ADR-0093 Phase 2 (Passo 2): helpers sem estado extraídos para
# api/_decide_helpers.py. Reimportados aqui para preservar os call-sites.
from buildtovalue.api._decide_helpers import (  # noqa: E402
    _appeal_to_response,
    _build_bias_declaration,
    _impact_label,
    _resolve_domain,
    _resolve_role,
    sign_verdict,
)


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


def _load_slm_config() -> dict:
    """Load SLM config. Env var overrides YAML."""
    import yaml
    env_path = os.environ.get("BTV_SLM_MODEL_PATH")
    if env_path:
        return {"enabled": True, "model_path": env_path}
    candidates = [
        Path("/app/data/policies/core/slm.yaml"),
        Path(__file__).resolve().parent.parent.parent.parent / "data" / "policies" / "core" / "slm.yaml",
    ]
    for config_path in candidates:
        try:
            if config_path.exists():
                with open(config_path) as f:
                    return yaml.safe_load(f).get("slm", {})
        except Exception as e:
            logger.warning("Failed to load SLM config from %s: %s", config_path, e)
    return {}

# ═══════════════════════════════════════════════════════════════
# LIFESPAN + FASTAPI APP + ROUTERS
# ═══════════════════════════════════════════════════════════════

# ADR-0093 Phase 2 (Passo 1): lifespan extraído para api/_lifespan.py.
# O startup reinjeta os 11 singletons nos globals deste módulo via shim
# provisório (removido no Passo 4, quando os 105 read-sites usarem app.state).
from buildtovalue.api._lifespan import lifespan  # noqa: E402


app = FastAPI(title="BuildToValue Governance", version="0.1.0a1", lifespan=lifespan)

def _cors_origins() -> list[str]:
    raw = os.environ.get("BTV_CORS_ORIGINS", "").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    if os.environ.get("BTV_ENV", "development").lower() == "production":
        raise RuntimeError(
            "BTV_CORS_ORIGINS must be set in production. "
            'Example: BTV_CORS_ORIGINS="https://app.example.com,https://admin.example.com"'
        )
    return [
        "http://localhost:8501",
        "http://localhost:3000",
        "http://localhost:8080",
        "http://localhost:8000",  # Lab v3.0 — demo/ servido same-origin pelo FastAPI
    ]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-BTV-Session", "X-BTV-Jurisdiction"],
)

from buildtovalue.api.routes.intelligence import router as intelligence_router
from buildtovalue.api.routes.ledger import router as ledger_router
from buildtovalue.api.routes.webhooks import router as webhooks_router
from buildtovalue.api.routes.compliance_eval import router as compliance_eval_router
from buildtovalue.api.routes.auth import router as auth_router
from buildtovalue.api.routes.agent_decide import router as agent_decide_router
from buildtovalue.api.routes.fleet import router as fleet_router
from buildtovalue.api.routes.metrics import router as metrics_router
from buildtovalue.api.routes.health import router as health_router
from buildtovalue.api.routes.appeals import router as appeals_router
app.include_router(intelligence_router)
app.include_router(ledger_router)
app.include_router(webhooks_router)
app.include_router(compliance_eval_router)
app.include_router(auth_router)
app.include_router(agent_decide_router)
app.include_router(fleet_router)
app.include_router(metrics_router)
app.include_router(health_router)
app.include_router(appeals_router)

# ═══════════════════════════════════════════════════════════════
# Lab v3.0 — demo/ servido estaticamente same-origin (CORS estrito)
# app.py em python/buildtovalue/api/app.py → 4x .parent = raiz do repo
# ═══════════════════════════════════════════════════════════════
_BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
_DEMO_PATH = _BASE_DIR / "demo"
if _DEMO_PATH.exists():
    app.mount("/demo", StaticFiles(directory=str(_DEMO_PATH), html=True), name="demo")
    logger.info("demo/ mounted at /demo: %s", _DEMO_PATH)
else:
    logger.warning("demo/ not found at %s — static UI not mounted", _DEMO_PATH)

# ═══════════════════════════════════════════════════════════════
# GLOBALS
# ═══════════════════════════════════════════════════════════════

_contestability_loop: Optional[ContestabilityLoop] = None
_profile_manager: Optional[ProfileManager] = None
_sector_loader: Optional[SectorLoader] = None
_slm: Optional[SLMClassifier] = None
_ner: Optional[NERDetector] = None
_ethical_engine: Optional[EthicalContextEngine] = None
_output_validator: Optional[OutputSchemaValidator] = None
_sensitivity_accumulator: Optional["SessionSensitivityAccumulator"] = None
# Gap 12/19: singleton (nao mais inline por request)
_trust_calculator: Optional[TrustScoreCalculator] = None
# Gap 10: singleton com ring buffer de sessões
_goal_drift_sentinel: Optional[GoalDriftSentinel] = None
# C6: multi-agent governance singletons
_cross_agent: Optional[CrossAgentCorrelator] = None
_delegation_ledger: Optional[DelegationLedger] = None
# PR-4: kernel executor — isolates blocking Rust calls from the event loop
_KERNEL_EXECUTOR: Optional[ThreadPoolExecutor] = None

# ═══════════════════════════════════════════════════════════════
# GOVERNANCE — /v1/decide helpers
# ═══════════════════════════════════════════════════════════════

class _AdjSignals:
    """Mutable accumulator for risk-adjusted signals used across decide() stages."""
    __slots__ = ("risk", "finding_count", "critical_count", "action")

    def __init__(self, req: "DecideRequest") -> None:
        self.risk: float = req.composite_risk
        self.finding_count: int = req.finding_count
        self.critical_count: int = req.critical_count
        self.action: str = req.action


class _SLMMeta:
    __slots__ = ("used", "intent", "risk", "justifiability")

    def __init__(self) -> None:
        self.used: bool = False
        self.intent: Optional[str] = None
        self.risk: Optional[float] = None
        self.justifiability: Optional[float] = None


class _ComplianceMeta:
    __slots__ = ("risk_class", "violations", "rate")

    def __init__(self) -> None:
        self.risk_class: Optional[str] = None
        self.violations: Optional[list] = None
        self.rate: Optional[float] = None


def _decide_hard_block(
    req: "DecideRequest",
    session_id: str,
    start: float,
) -> "Optional[DecideResponse]":
    if not req.hard_blocked:
        return None
    update_trust(session_id, "BLOCK")
    sig = sign_verdict(f"VRD-HB-{int(time.time())}", "BLOCK", req.composite_risk)
    return DecideResponse(
        verdict_id=f"VRD-HB-{int(time.time())}",
        action="BLOCK",
        original_action="BLOCK",
        mercy_applied=False,
        mercy_scenario="HARD_BLOCK",
        mercy_score=0.0,
        trust_score=get_trust_score(session_id),
        adjusted_risk=req.composite_risk,
        rationale=(
            f"Hard block triggered. Matched: {req.matched_policies}. "
            "No mercy applicable. Contestable within 24h."
        ),
        contestable=True,
        appeal_deadline_hours=24,
        signature=sig,
        latency_ms=(time.perf_counter() - start) * 1000,
        bias_declaration=_build_bias_declaration(
            trust_score=get_trust_score(session_id),
            adjusted_risk=req.composite_risk,
            mercy_applied=False,
            pii_redacted=False,
            explain=(
                f"Hard block triggered. Matched: {req.matched_policies}. "
                "No mercy applicable. Contestable within 24h."
            ),
        ),
    )


def _decide_run_guards(
    req: "DecideRequest",
    session_id: str,
    start: float,
) -> "Optional[DecideResponse]":
    # Guards run early to short-circuit the expensive pipeline on BLOCK.
    # Layer 1 (source=visual, channel) run first; layer 2 (rag_verifier) after channel.
    if not (req.source or req.channel or req.agent_policies):
        return None
    module_config = None
    if _profile_manager and req.agent_policies:
        module_config = _profile_manager.resolve_module_config(req.agent_policies)

    _channel_trust_level: int = 1

    _vf_yaml = (
        module_config.visual_firewall
        if module_config and module_config.visual_firewall
        else None
    )
    if req.source == "visual" or (module_config and module_config.visual_firewall):
        _vf_blocked, _vf_explain = _run_visual_guard(req.input_text, _vf_yaml)
        if _vf_blocked:
            return _block_guard_response(
                session_id, f"VRD-VF-{int(time.time())}", "visual_firewall",
                _vf_explain, req.composite_risk, start,
            )

    _ch_yaml = (
        module_config.channel_authority
        if module_config and module_config.channel_authority
        else None
    )
    if req.channel or (module_config and module_config.channel_authority):
        _ch_blocked, _ch_explain, _channel_trust_level = _run_channel_guard(
            req.channel or "", _ch_yaml
        )
        if _ch_blocked:
            return _block_guard_response(
                session_id, f"VRD-CH-{int(time.time())}", "channel_authority",
                _ch_explain, req.composite_risk, start,
            )

    if module_config and module_config.rag_verifier:
        _rg_yaml = module_config.rag_verifier
        _rg_blocked, _rg_explain = _run_rag_guard(
            req.input_text, _channel_trust_level, _rg_yaml
        )
        if _rg_blocked:
            return _block_guard_response(
                session_id, f"VRD-RG-{int(time.time())}", "rag_verifier",
                _rg_explain, req.composite_risk, start,
            )
    return None


def _decide_accumulate_signals(
    req: "DecideRequest",
    session_id: str,
) -> "tuple[Optional[SensitivityState], Optional[DriftReport]]":
    sensitivity_state: Optional[SensitivityState] = None
    if _sensitivity_accumulator is not None:
        findings_summary = [
            p.split("->")[0].lower()
            for p in req.matched_policies
            if p
        ]
        sensitivity_state = _sensitivity_accumulator.accumulate(
            session_id=session_id,
            findings_summary=findings_summary,
        )

    drift_report: Optional[DriftReport] = None
    if _goal_drift_sentinel is not None:
        drift_report = _goal_drift_sentinel.record_and_analyze(
            session_id=session_id,
            drift_level=req.drift_level,
            policy_action=req.action,
        )
        if drift_report.policy_drift_detected:
            logger.info(
                "GoalDriftSentinel: drift detectado session=%s action=%s trend=%d%%",
                session_id,
                drift_report.drift_action.value,
                drift_report.trend_pct,
            )
    return sensitivity_state, drift_report


def _decide_slm(
    req: "DecideRequest",
    session_id: str,
    adj: _AdjSignals,
) -> _SLMMeta:
    meta = _SLMMeta()
    if _slm is None:
        return meta

    # F2-01: use context-aware classification when kernel signals are available
    _slm_ctx = SLMContext(
        lang=getattr(req, "detected_language", None) or "unknown",
        entropy=getattr(req, "entropy", 4.0),
        instruction_density=getattr(req, "instruction_density", 0.0),
        entropy_shift=bool(getattr(req, "entropy_shift", False)),
        leet_ratio=float(getattr(req, "leet_ratio", 0.0)),
        trust_score=get_trust_score(session_id),
        domain=_resolve_domain(req.profile),
        violation_count=db_get_session(session_id)["offenses"] if session_id else 0,
    )
    slm_result = _slm.classify_with_context(
        text=req.input_text,
        finding_count=req.finding_count,
        critical_count=req.critical_count,
        context=_slm_ctx,
    ) or _slm.classify_if_ambiguous(
        text=req.input_text,
        finding_count=req.finding_count,
        critical_count=req.critical_count,
    )
    if slm_result is not None:
        meta.used = True
        meta.intent = slm_result.intent.value
        meta.risk = slm_result.risk

        if slm_result.is_malicious:
            adj.finding_count += 1
            if slm_result.risk >= 0.8:
                adj.critical_count += 1
            adj.risk = min(1.0, adj.risk + slm_result.risk * 0.3)

            current_sev = ACTION_SEVERITY.get(adj.action, 0)
            slm_sev = 2 if slm_result.risk < 0.7 else 3
            if slm_sev > current_sev:
                adj.action = SEVERITY_ACTION.get(slm_sev, "EDUCATE")

            logger.info(
                "SLM escalation: %s→%s (intent=%s, risk=%.2f)",
                req.action, adj.action, meta.intent, slm_result.risk,
            )

    # SLM Mercy Advisor (F2-02, fail-open)
    if adj.action not in ("BLOCK",):
        _slm_mercy = _slm.advise_mercy(
            text=req.input_text,
            finding_types=req.matched_policies if hasattr(req, "matched_policies") else [],
            domain=_resolve_domain(req.profile),
            user_role=_resolve_role(session_id),
            is_first_offense=(db_get_session(session_id)["offenses"] == 0 if session_id else True),
            trust_score=get_trust_score(session_id),
        )
        if _slm_mercy is not None:
            meta.justifiability = _slm_mercy.legitimate_probability
            logger.info(
                "SLM mercy advisor: legitimate_probability=%.2f reasoning=%s",
                _slm_mercy.legitimate_probability, _slm_mercy.reasoning[:80],
            )
    return meta


def _decide_adjust_risk(
    req: "DecideRequest",
    session_id: str,
    adj: _AdjSignals,
    sensitivity_state: "Optional[SensitivityState]",
    drift_report: "Optional[DriftReport]",
) -> "tuple[str, str, str]":
    """Profile/sector + cumulative + cross-signal adjustments.

    Mutates adj.risk. Returns (sector_note, cumulative_note, drift_cross_note).
    """
    sector_note = ""
    if req.profile and _profile_manager and _sector_loader and req.input_text:
        try:
            loaded_profile = _profile_manager.load_profile(req.profile)
            domain_keys = [
                k for k in loaded_profile.domain_config.keys() if k != "general"
            ]
            if domain_keys:
                sector_id = domain_keys[0]
                matched_types = [p.split(":")[0] for p in req.matched_policies]
                multiplier = _sector_loader.apply_whitelist(
                    input_text=req.input_text,
                    findings=matched_types,
                    sector_id=sector_id,
                )
                if multiplier < 1.0:
                    adj.risk *= multiplier
                    sector_note = (
                        f" Sector context ({sector_id}) reduced risk "
                        f"by {(1 - multiplier) * 100:.0f}%."
                    )
        except ValueError:
            logger.warning("Profile not found: %s", req.profile)

    cumulative_note = ""
    if sensitivity_state is not None and sensitivity_state.cumulative_risk > 0.0:
        adj.risk = min(1.0, adj.risk + sensitivity_state.cumulative_risk)
        cumulative_note = (
            f" Hybrid Alignment (ADR-046): acúmulo de sessão detectou "
            f"combinação perigosa ({', '.join(sensitivity_state.active_combinations)}). "
            f"Risco cumulativo: {sensitivity_state.cumulative_risk:.2f}."
        )
        logger.info(
            "Sensitivity accumulator: session=%s cumulative_risk=%.2f combinations=%s",
            session_id,
            sensitivity_state.cumulative_risk,
            sensitivity_state.active_combinations,
        )

    # Gap 10: cross-signal drift × sensitivity — Jonas: sinais compostos = risco composto
    # Drift confirmado + acúmulo de sessão > 0.3 indica vetor adversarial coordenado.
    drift_cross_note = ""
    if (
        drift_report is not None
        and drift_report.policy_drift_detected
        and sensitivity_state is not None
        and sensitivity_state.cumulative_risk > 0.3
    ):
        adj.risk = min(1.0, adj.risk + 0.15)
        drift_cross_note = (
            " Cross-signal (ADR-046/PROP-038): drift de objetivo detectado + "
            f"risco cumulativo de sessão {sensitivity_state.cumulative_risk:.2f} > 0.30 "
            "→ +0.15 risco composto."
        )
        logger.info(
            "Cross-signal drift×sensitivity: session=%s drift_detected=True cumulative_risk=%.2f",
            session_id,
            sensitivity_state.cumulative_risk,
        )
    return sector_note, cumulative_note, drift_cross_note


def _decide_ethical_verdict(
    req: "DecideRequest",
    session_id: str,
    adj: _AdjSignals,
    slm_meta: _SLMMeta,
    sensitivity_state: "Optional[SensitivityState]",
) -> "tuple[EthicalVerdict, RequestContext]":
    evidence = RustEvidence(
        composite_risk=adj.risk,
        finding_count=adj.finding_count,
        critical_count=adj.critical_count,
        entropy=req.entropy,
        total_chars=req.total_chars,
        policy_action=adj.action,
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
        prior_sensitivity_tags=(
            list(sensitivity_state.tags) if sensitivity_state else []
        ),
        cumulative_risk=(
            sensitivity_state.cumulative_risk if sensitivity_state else 0.0
        ),
        active_combinations=(
            sensitivity_state.active_combinations if sensitivity_state else []
        ),
    )
    trust = get_trust_score(session_id)
    _ethical_engine.set_trust_score(session_id, trust)
    verdict = _ethical_engine.decide(
        evidence, context,
        external_verdict_id=req.verdict_id,
        slm_justifiability=slm_meta.justifiability,
    )
    return verdict, context


def _decide_compliance(
    req: "DecideRequest",
    adj: _AdjSignals,
    verdict: "EthicalVerdict",
) -> _ComplianceMeta:
    meta = _ComplianceMeta()
    if _risk_classifier is None:
        return meta
    sector_id = _resolve_domain(req.profile) or "general"
    caps: list = []
    if req.profile and _profile_manager:
        try:
            loaded = _profile_manager.load_profile(req.profile)
            caps = loaded.domain_config.get("capabilities", [])
        except ValueError:
            pass
    rc = _risk_classifier.classify(
        agent_id=req.profile or "unknown",
        sector=sector_id,
        capabilities=caps,
    )
    meta.risk_class = rc.risk_level.value
    if rc.risk_level.value in ("HIGH_RISK", "PROHIBITED"):
        from buildtovalue.compliance.compliance_evaluator import ComplianceEvaluator
        evaluator = ComplianceEvaluator()
        agent_meta = {
            "agent_id": req.profile or "unknown",
            "sector": sector_id,
            "risk_level": rc.risk_level.value,
            "capabilities": caps,
            "risk_score": adj.risk,
            "use_case": sector_id,
            "conformity_assessment_completed": False,
            "transparency_score": 1.0 if verdict.explanation else 0.0,
            "human_review": {"available": verdict.contestable},
        }
        eval_result = evaluator.evaluate(agent_meta)
        meta.violations = [
            {
                "framework": v.framework,
                "article": v.article,
                "requirement": v.requirement,
                "action": v.action,
            }
            for v in eval_result.violations
        ]
        meta.rate = eval_result.compliance_rate
    return meta


def _decide_output_pipeline(
    req: "DecideRequest",
    session_id: str,
    adj: _AdjSignals,
    context: "RequestContext",
    verdict: "EthicalVerdict",
    slm_meta: _SLMMeta,
) -> "tuple[EthicalVerdict, Optional[list], Optional[str]]":
    """Schema validation + SLM output analysis + SLM explanation.

    Returns (possibly updated verdict, schema_violations, slm_explanation).
    """
    schema_violations = None
    if req.llm_output and req.profile and _profile_manager:
        try:
            loaded = _profile_manager.load_profile(req.profile)
            output_schema = loaded.output_schema
            if output_schema and _output_validator:
                schema_result = _output_validator.validate(req.llm_output, output_schema)
                if not schema_result.valid:
                    schema_violations = [
                        {"path": v.path, "rule": v.rule, "message": v.message}
                        for v in schema_result.violations
                    ]
                    if ACTION_SEVERITY.get(verdict.final_action, 0) < ACTION_SEVERITY.get("REDACT", 0):
                        verdict = _ethical_engine.decide(
                            RustEvidence(
                                composite_risk=max(adj.risk, 0.6),
                                finding_count=adj.finding_count + 1,
                                critical_count=adj.critical_count,
                                entropy=req.entropy,
                                total_chars=req.total_chars,
                                policy_action="REDACT",
                                blake3_hash=req.blake3_hash,
                            ),
                            context,
                        )
                        logger.info(
                            "Output schema violation → REDACT (session=%s, violations=%d)",
                            session_id, len(schema_result.violations),
                        )
        except Exception as e:
            logger.warning("Output schema validation error: %s", e)

    if _slm is not None and req.llm_output:
        try:
            _out_analysis = _slm.analyze_output(
                output_text=req.llm_output,
                domain=_resolve_domain(req.profile),
                masked_count=0,
            )
            if _out_analysis and _out_analysis.leak_detected and _out_analysis.risk >= 0.5:
                if ACTION_SEVERITY.get(verdict.final_action, 0) < ACTION_SEVERITY.get("REDACT", 0):
                    verdict = _ethical_engine.decide(
                        RustEvidence(
                            composite_risk=max(adj.risk, _out_analysis.risk),
                            finding_count=adj.finding_count + 1,
                            critical_count=adj.critical_count,
                            entropy=req.entropy,
                            total_chars=req.total_chars,
                            policy_action="REDACT",
                            blake3_hash=req.blake3_hash,
                        ),
                        context,
                        slm_justifiability=slm_meta.justifiability,
                    )
                logger.warning(
                    "SLM output analysis: leak_type=%s risk=%.2f → REDACT (session=%s)",
                    _out_analysis.leak_type, _out_analysis.risk, session_id,
                )
        except Exception as e:
            logger.warning("SLM output analysis error (fail-open): %s", e)

    slm_explanation: Optional[str] = None
    if _slm is not None:
        try:
            slm_explanation = _slm.generate_explanation(
                action=verdict.final_action,
                original_action=req.action,
                mercy_applied=verdict.mercy_applied,
                mercy_scenario=verdict.mercy_scenario or "S6_DEFAULT_NO_MERCY",
                trust_score=verdict.trust_score,
                findings_summary=(
                    f"{adj.finding_count} findings, {adj.critical_count} critical"
                ),
                levinas_note=(
                    "Usuário pode contestar em 24h"
                    if getattr(verdict, "contestable", True)
                    else "Decisão automática"
                ),
                gilligan_note=(
                    f"Cenário de misericórdia: {verdict.mercy_scenario}"
                    if verdict.mercy_applied
                    else "Regra aplicada uniformemente"
                ),
                language="pt-BR",
            )
        except Exception as e:
            logger.warning("SLM explanation error (fail-open): %s", e)

    return verdict, schema_violations, slm_explanation


def _decide_persist_trust(
    session_id: str,
    req: "DecideRequest",
    verdict: "EthicalVerdict",
    context: "RequestContext",
) -> None:
    if session_id:
        prev = db_get_session(session_id)
        if prev["last_action"] in ("BLOCK", "EDUCATE") and prev["last_entropy"] > 0.0:
            if _trust_calculator is not None:
                delta = _trust_calculator.adjust_post_penalty(
                    session_id=session_id,
                    pre_block_entropy=prev["last_entropy"],
                    post_block_entropy=req.entropy,
                    subsequent_action=verdict.final_action,
                )
                if delta != 0.0:
                    session_data = db_get_session(session_id)
                    new_trust = max(0.0, min(1.0, session_data["trust_score"] + delta))
                    db_update_session(session_id, new_trust, 0)
                    logger.info(
                        "adjust_post_penalty persisted: session=%s delta=%.3f new_trust=%.3f",
                        session_id, delta, new_trust,
                    )
        db_update_session_state(session_id, req.entropy, verdict.final_action)

        # Action Graph telemetry (ADR-041)
        prev_action = prev["last_action"]
        curr_action = verdict.final_action
        if prev_action:
            from buildtovalue.observability.metrics import (
                ACTION_TRANSITION_TOTAL,
                ACTION_SEQUENCE_ESCALATION_TOTAL,
            )
            ACTION_TRANSITION_TOTAL.labels(
                from_action=prev_action,
                to_action=curr_action,
            ).inc()
            _ESCALATION_MAP = {
                ("ALLOW", "BLOCK"):   "ALLOW_to_BLOCK",
                ("EDUCATE", "BLOCK"): "EDUCATE_to_BLOCK",
                ("LOG", "BLOCK"):     "LOG_to_BLOCK",
                ("ALLOW", "EDUCATE"): "ALLOW_to_EDUCATE",
            }
            pattern = _ESCALATION_MAP.get((prev_action, curr_action))
            if pattern:
                ACTION_SEQUENCE_ESCALATION_TOTAL.labels(pattern=pattern).inc()
    update_trust(session_id, verdict.final_action)

    # Over-refusal telemetry (ADR-041 + Art.104/168)
    _BENIGN_MERCY = {"S1_CRITICAL_OVERRIDE", "S2_LEGAL", "S3_RESEARCH"}
    if (
        verdict.trust_score > 0.7
        and verdict.mercy_scenario in _BENIGN_MERCY
        and verdict.final_action != "ALLOW"
    ):
        from buildtovalue.observability.metrics import BENIGN_REFUSAL_TOTAL
        BENIGN_REFUSAL_TOTAL.labels(
            action=verdict.final_action,
            mercy_scenario=verdict.mercy_scenario,
            domain=getattr(context, "domain", None) or "general",
        ).inc()


# ═══════════════════════════════════════════════════════════════
# GOVERNANCE — /v1/decide (Judiciário da República Algorítmica)
# ═══════════════════════════════════════════════════════════════

@app.post("/v1/decide", response_model=DecideResponse)
def decide(req: DecideRequest, request: Request, _=Depends(require_api_key)):
    """
    Pipeline v2.3:
      0. Hard block → BLOCK imediato (sem mercy, sem ADR-046)
      1. ADR-046: acumular findings da sessão → cumulative_risk
      1.5. GoalDriftSentinel: rastrear drift da sessão (Gap 10)
      2. SLM (ambiguity zone only — ADR-027)
      3. Profile/sector risk adjustment
      4. Aplicar cumulative_risk + cross-signal drift×sensitivity (Gap 10)
      5. EthicalContextEngine.decide() → mercy + trust + HMAC
      6. Update trust + persist adjust_post_penalty delta (Gap 14)
    """
    start = time.perf_counter()
    session_id = req.session_id or "anonymous"

    # ── Etapa 0: FFI scan — Rust Kernel populates TechnicalEvidence ─────────
    # Fail-secure: bridge unavailability never blocks the API (silent degradation).
    _ffi = getattr(request.app.state, "ffi_client", None)
    _ffi_categories: list = []
    if _ffi is not None:
        try:
            _ev = _ffi.scan(req.input_text)
            req.composite_risk = _ev.composite_risk
            req.finding_count  = _ev.finding_count
            req.critical_count = _ev.critical_count
            req.blake3_hash    = _ev.hash
            req.entropy        = _ev.entropy
            req.total_chars    = _ev.input_size
            _ffi_categories    = getattr(_ev, "categories", [])
            if not req.matched_policies:
                req.matched_policies = [
                    f"{f.category}->{f.title}" for f in _ev.findings
                ]
        except FFIError as exc:
            logger.warning("FFI scan failed — fail-secure (degraded mode): %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("FFI scan unexpected error — fail-secure: %s", exc)

    # ADR-048 Phase 4: Category-based action routing.
    # Deobfuscator and ZScore are statistical analysis modules that fire on
    # every input — they are not semantic threat detectors and must be excluded
    # before routing decisions are made.
    _ANALYSIS_MODULES = {"Deobfuscator", "ZScore"}
    _ALWAYS_BLOCK     = {"CPF", "CNPJ", "CreditCard", "Luhn"}
    _ATTACK_BLOCK     = {"SqlInjection", "Jailbreak", "DataExfiltration", "Xss", "Ssti"}
    _EDUCATE          = {"SSN", "Email", "Phone", "Iban", "EuVat", "SensitiveData", "PromptInjection"}
    _LOG              = {"NhsNumber", "Network"}
    # Distinguishes SQL injection attacks from benign SQL queries (both trigger
    # the SqlInjection validator, but only attacks contain these signatures).
    _SQL_ATTACK_SIGS  = {"union select", "drop table", "drop database",
                         "insert into", "delete from", "; --", ";--", "exec(", "xp_"}

    _t    = req.input_text.lower()
    _cats = set(_ffi_categories) - _ANALYSIS_MODULES
    # Levinas — PII detectada (sujeita a tratamento protetivo) para BiasDeclaration.
    _PII_CATS = {"CPF", "CNPJ", "CreditCard", "Luhn", "SSN", "Email",
                 "Phone", "Iban", "EuVat", "NhsNumber", "SensitiveData"}
    _pii_detected = bool(_cats & _PII_CATS)

    if _cats:
        if _cats & _ALWAYS_BLOCK:
            req.action = "BLOCK"
            req.hard_blocked = True
        elif _cats & _ATTACK_BLOCK and req.critical_count > 0:
            req.action = "BLOCK"
            req.hard_blocked = True
        elif req.critical_count > 0:
            # ToolScreen (PROP-034a InterceptorChain) may emit Critical(255) under
            # ValidatorModule::Unknown before named validators run. That puts
            # 'Unknown' in _cats (non-empty, so Python fallback is skipped) but
            # 'Unknown' is not in _ATTACK_BLOCK, causing silent ALLOW. Fail-secure:
            # any critical finding that reaches here must block.
            req.action = "BLOCK"
            req.hard_blocked = True
        elif "SqlInjection" in _cats and any(p in _t for p in _SQL_ATTACK_SIGS):
            req.action = "BLOCK"
            req.hard_blocked = True
        elif _cats & _EDUCATE:
            req.action = "EDUCATE"
        elif _cats & _LOG:
            req.action = "LOG"
        elif _cats & _ATTACK_BLOCK:
            # Non-critical attack signal with no specific injection signature
            # (e.g. benign SELECT) → educate rather than punish
            req.action = "EDUCATE"
        # else: unrecognised category — leave action at default ALLOW
    else:
        # No semantic threat categories after filtering — Python-side text
        # fallback for patterns the kernel doesn't model (XSS, credentials).
        # "eval(atob" (not bare "eval(") mirrors the kernel XSS signature: a
        # plain eval() mention is benign (e.g. documentation) and must ALLOW,
        # while eval(atob(...)) is the obfuscated-payload attack vector. Bare
        # "eval(" here was a false positive on educational text (battery G6).
        _BLOCK_TEXT = ["<script", "javascript:", "eval(atob", "senha:", "login: root",
                       "union select", "drop table", "drop database"]
        _EDUCATE_TEXT = [
            "ignore as instru", "desconsidere suas", "you are now unrestricted",
            "forget all previous", "cpf", "iban",
            # "base64:" removed: benign encoding is now distinguished from attack
            # patterns by EXFIL "base64 -d" and XSS "eval(atob" in the kernel.
        ]
        if any(p in _t for p in _BLOCK_TEXT):
            req.action = "BLOCK"
            req.hard_blocked = True
        elif any(p in _t for p in _EDUCATE_TEXT):
            req.action = "EDUCATE"
        # else: leave at ALLOW (default — no threat detected)

    resp = _decide_hard_block(req, session_id, start)
    if resp:
        return resp

    resp = _decide_run_guards(req, session_id, start)
    if resp:
        return resp

    adj = _AdjSignals(req)
    sensitivity_state, drift_report = _decide_accumulate_signals(req, session_id)
    slm_meta = _decide_slm(req, session_id, adj)
    sector_note, cumulative_note, drift_cross_note = _decide_adjust_risk(
        req, session_id, adj, sensitivity_state, drift_report,
    )

    verdict, context = _decide_ethical_verdict(req, session_id, adj, slm_meta, sensitivity_state)
    compliance = _decide_compliance(req, adj, verdict)
    verdict, schema_violations, slm_explanation = _decide_output_pipeline(
        req, session_id, adj, context, verdict, slm_meta,
    )

    _decide_persist_trust(session_id, req, verdict, context)

    latency = (time.perf_counter() - start) * 1000
    # F2-03: use SLM natural language explanation when available; fallback to template
    rationale = (slm_explanation or verdict.explanation) + sector_note + cumulative_note + drift_cross_note

    return DecideResponse(
        verdict_id=verdict.verdict_id,
        action=verdict.final_action,
        original_action=req.action,
        mercy_applied=verdict.mercy_applied,
        mercy_scenario=verdict.mercy_scenario,
        mercy_score=verdict.mercy_score,
        trust_score=verdict.trust_score,
        adjusted_risk=adj.risk,
        rationale=rationale,
        contestable=verdict.contestable,
        appeal_deadline_hours=24,
        signature=verdict.hmac_signature,
        latency_ms=latency,
        bias_declaration=_build_bias_declaration(
            trust_score=verdict.trust_score,
            adjusted_risk=adj.risk,
            mercy_applied=verdict.mercy_applied,
            pii_redacted=_pii_detected,
            explain=rationale,
        ),
        slm_used=slm_meta.used,
        slm_intent=slm_meta.intent,
        slm_risk=slm_meta.risk,
        risk_classification=compliance.risk_class,
        compliance_violations=compliance.violations,
        compliance_rate=compliance.rate,
        schema_violations=schema_violations,
    )


@app.post("/v1/multi-decide", response_model=MultiDecideResponse)
async def multi_decide(
    req: MultiDecideRequest, request: Request, _=Depends(require_api_key)
):
    """Lab v3.0 — fan-out concorrente do mesmo prompt para N agentes.

    Governance é síncrono; paralelizamos no boundary FFI/I-O com
    asyncio.to_thread (nunca threading manual). Reutiliza decide() — sem
    duplicar a pipeline de decisão.
    """
    if not req.agent_ids:
        raise HTTPException(status_code=422, detail="agent_ids must not be empty")

    def _one(agent_id: str) -> DecideResponse:
        single = DecideRequest(
            input_text=req.prompt,
            session_id=req.session_id or f"multi-{agent_id}",
            profile=agent_id,
            agent_policies=[agent_id],
        )
        return decide(single, request)

    verdicts = await asyncio.gather(
        *[asyncio.to_thread(_one, aid) for aid in req.agent_ids]
    )
    return MultiDecideResponse(verdicts=list(verdicts))


# ═══════════════════════════════════════════════════════════════
# APPEALS — /v1/appeals (ADR-017, Levinas)
# ═══════════════════════════════════════════════════════════════

# ADR-0093 Phase 2 (Passo 3, router 2): /v1/appeals/* migrado para
# routes/appeals.py (lê app.state.contestability_loop via Depends). Registrado abaixo.


# ═══════════════════════════════════════════════════════════════
# HEALTH & TRUST
# ═══════════════════════════════════════════════════════════════

# ADR-0093 Phase 2 (Passo 3, router 1): /health e /v1/trust migrados para
# routes/health.py (leem app.state, não os globals). Registrado abaixo.


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


@app.post("/v1/compliance/classify-risk")
def classify_risk(req: RiskClassifyRequest, _=Depends(require_api_key)):
    result = _risk_classifier.classify(
        agent_id=req.agent_id,
        sector=req.sector,
        capabilities=req.capabilities,
        deployment_context=req.deployment_context,
    )
    return result.to_dict()

_fria_generator = FRIAGenerator()


@app.post("/v1/compliance/fria/generate")
def generate_fria(req: FRIARequest, _=Depends(require_api_key)):
    rc = _risk_classifier.classify(
        agent_id=req.agent_id,
        sector=req.sector,
        capabilities=req.capabilities,
        deployment_context=req.deployment_context,
    )
    viols = []
    rate = 1.0
    if rc.risk_level.value in ("HIGH_RISK", "PROHIBITED"):
        from buildtovalue.compliance.compliance_evaluator import ComplianceEvaluator
        evaluator = ComplianceEvaluator()
        result = evaluator.evaluate({
            "agent_id": req.agent_id,
            "sector": req.sector,
            "risk_level": rc.risk_level.value,
            "capabilities": req.capabilities,
            "risk_score": 0.5,
            "use_case": req.sector,
            "conformity_assessment_completed": False,
        })
        viols = [
            {"framework": v.framework, "article": v.article,
             "requirement": v.requirement, "action": v.action}
            for v in result.violations
        ]
        rate = result.compliance_rate

    doc = _fria_generator.generate(
        agent_id=req.agent_id,
        risk_level=rc.risk_level.value,
        sector=req.sector,
        obligations=rc.obligations,
        violations=viols,
        compliance_rate=rate,
        capabilities=req.capabilities,
        ledger_analytics=_ledger_analytics,
    )
    return doc.to_dict()


# ═══════════════════════════════════════════════════════════════
# COMPLIANCE-AS-CODE — ROPA, Art. 20, Document Export (ADR-048)
# ═══════════════════════════════════════════════════════════════

from buildtovalue.compliance.ledger_analytics import LedgerAnalytics
from buildtovalue.compliance.ropa_generator import ROPAGenerator
from buildtovalue.compliance.art20_report import Art20ReportGenerator
from buildtovalue.compliance.document_exporter import DocumentExporter

_ledger_analytics = LedgerAnalytics()
_ropa_generator = ROPAGenerator(_ledger_analytics)
_art20_generator = Art20ReportGenerator(_ledger_analytics)
_doc_exporter = DocumentExporter()


@app.post("/v1/compliance/ropa/generate")
def generate_ropa(req: dict, _=Depends(require_api_key)):
    """Generate ROPA document from ledger data (LGPD Art. 37, ADR-048)."""
    controller = req.get("controller", "Not specified")
    dpo_name = req.get("dpo_name", "Not specified")
    dpo_contact = req.get("dpo_contact", "Not specified")
    start_ts = req.get("start_ts")
    end_ts = req.get("end_ts")

    ropa = _ropa_generator.generate(
        controller=controller,
        dpo_name=dpo_name,
        dpo_contact=dpo_contact,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    return ropa.to_dict()


@app.post("/v1/compliance/art20/report")
def generate_art20(req: dict, _=Depends(require_api_key)):
    """Generate Art. 20 automated decision report (LGPD, ADR-048)."""
    start_ts = req.get("start_ts")
    end_ts = req.get("end_ts")
    include_decisions = req.get("include_decisions", True)
    max_decisions = req.get("max_decisions", 500)

    report = _art20_generator.generate(
        start_ts=start_ts,
        end_ts=end_ts,
        include_decisions=include_decisions,
        max_decisions=max_decisions,
    )
    return report.to_dict()


@app.post("/v1/compliance/documents/export")
def export_compliance_document(req: dict, _=Depends(require_api_key)):
    """Export compliance document to PDF (ADR-048)."""
    doc_type = req.get("type", "")  # ropa, fria, art20
    data = req.get("data", {})
    fmt = req.get("format", "json")  # json or pdf

    if doc_type not in ("ropa", "fria", "art20"):
        raise HTTPException(status_code=400, detail="type must be ropa, fria, or art20")
    if not data:
        raise HTTPException(status_code=400, detail="data is required")

    if fmt == "pdf":
        try:
            path = _doc_exporter.export_pdf(data=data, template_name=doc_type)
            return {"status": "ok", "format": "pdf", "path": path}
        except ImportError as e:
            raise HTTPException(status_code=503, detail=str(e))
    else:
        path = _doc_exporter.export_json(data=data, template_name=doc_type)
        return {"status": "ok", "format": "json", "path": path}


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
# NER SEMANTIC SCAN — /v1/scan/semantic (ADR-047)
# ═══════════════════════════════════════════════════════════════

@app.post("/v1/scan/semantic")
def scan_semantic(req: dict, _=Depends(require_api_key)):
    """Semantic PII detection via SLM NER (ADR-047)."""
    if _ner is None:
        raise HTTPException(status_code=503, detail="NER detector not available (SLM not loaded)")
    text = req.get("text", "")
    if not text or len(text) < 3:
        raise HTTPException(status_code=400, detail="Text must be at least 3 characters")
    result = _ner.detect(text)
    return result.to_dict()


@app.get("/v1/ner/metrics")
def ner_metrics(_=Depends(require_api_key)):
    """NER detector metrics (ADR-047)."""
    if _ner is None:
        return {"enabled": False, "message": "NER not loaded"}
    return {"enabled": True, **_ner.get_metrics()}


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


# ═══════════════════════════════════════════════════════════════
# C3 — Agent Public Key Registration (cold path — management)
# C10 — IdentityAnchorPolicy integration
# ═══════════════════════════════════════════════════════════════

class AgentRegisterRequest(BaseModel):
    public_key_hex: str = Field(..., min_length=64, max_length=64, description="Ed25519 public key (32 bytes hex)")
    registration_proof: Optional[str] = Field(None, description="Identity proof for anti-Sybil (C10)")


def _load_identity_anchor_policy() -> dict:
    import yaml
    candidates = [
        Path(os.environ.get("BTV_POLICY_DIR", "data/policies")) / "core" / "identity_anchor.yaml",
        Path(__file__).resolve().parent.parent.parent.parent / "data" / "policies" / "core" / "identity_anchor.yaml",
    ]
    for p in candidates:
        try:
            if p.exists():
                with open(p) as f:
                    return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {"require_identity_anchor": False}


@app.post("/v1/agents/{agent_id}/register", status_code=201)
def agent_register(agent_id: str, req: AgentRegisterRequest, _=Depends(require_api_key)):
    """Register an Ed25519 public key for an agent (C3)."""
    # C10: identity anchor enforcement
    policy = _load_identity_anchor_policy()
    if policy.get("require_identity_anchor", False) and not req.registration_proof:
        raise HTTPException(status_code=403, detail="registration_proof required (identity_anchor policy)")

    try:
        bytes.fromhex(req.public_key_hex)
    except ValueError:
        raise HTTPException(status_code=422, detail="public_key_hex must be valid hex")

    key_fingerprint = hashlib.sha256(bytes.fromhex(req.public_key_hex)).hexdigest()[:16]
    registered_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    conn = sqlite_connect_wal(DB_PATH)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO agent_pubkeys (agent_id, public_key_hex, registered_at, revoked_at, registration_proof) "
            "VALUES (?, ?, ?, NULL, ?)",
            (agent_id, req.public_key_hex, registered_at, req.registration_proof),
        )
        conn.commit()
    finally:
        conn.close()

    return {"agent_id": agent_id, "registered_at": registered_at, "key_fingerprint": key_fingerprint}


@app.get("/v1/agents/{agent_id}/pubkey")
def agent_get_pubkey(agent_id: str, _=Depends(require_api_key)):
    """Retrieve registered public key for an agent (C3)."""
    conn = sqlite_connect_wal(DB_PATH)
    row = conn.execute(
        "SELECT public_key_hex, registered_at, revoked_at FROM agent_pubkeys WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not registered")
    if row[2]:
        raise HTTPException(status_code=410, detail=f"Agent {agent_id} key revoked at {row[2]}")

    return {"agent_id": agent_id, "public_key_hex": row[0], "registered_at": row[1]}


@app.delete("/v1/agents/{agent_id}/revoke")
def agent_revoke(agent_id: str, _=Depends(require_api_key)):
    """Revoke the public key of an agent (C3)."""
    revoked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn = sqlite_connect_wal(DB_PATH)
    cur = conn.execute(
        "UPDATE agent_pubkeys SET revoked_at = ? WHERE agent_id = ? AND revoked_at IS NULL",
        (revoked_at, agent_id),
    )
    conn.commit()
    conn.close()

    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found or already revoked")

    return {"agent_id": agent_id, "revoked_at": revoked_at}


# ═══════════════════════════════════════════════════════════════
# C34 — OracleTrustGate endpoints (Cenário 34: Boato Digital P2P)
# Seguindo padrão /v1/agents/{id}/register e /v1/agents/{id}/revoke
# ═══════════════════════════════════════════════════════════════

class OracleRegisterRequest(BaseModel):
    hmac_key_hex: str       # chave HMAC do oráculo (hex)
    valid_until_iso: str    # data de expiração UTC ISO 8601
    description: str = ""


class OracleRevokeRequest(BaseModel):
    reason: str = "Revogação solicitada via API"


_ORACLE_REGISTRY_STORE: dict = {}  # oracle_id → {hmac_key_hex, valid_until, revoked}


@app.post("/v1/oracles/{oracle_id}/register", status_code=201)
def oracle_register(
    oracle_id: str,
    req: OracleRegisterRequest,
    _=Depends(require_api_key),
):
    """Registra chave HMAC de um oráculo regulatório (Cenário 34).

    Segue padrão de /v1/agents/{id}/register.
    """
    registered_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _ORACLE_REGISTRY_STORE[oracle_id] = {
        "oracle_id": oracle_id,
        "hmac_key_hex": req.hmac_key_hex,
        "valid_until_iso": req.valid_until_iso,
        "description": req.description,
        "registered_at": registered_at,
        "revoked": False,
    }
    logger.info("Oracle registrado: oracle_id=%s", oracle_id)
    return {
        "oracle_id": oracle_id,
        "registered_at": registered_at,
        "valid_until_iso": req.valid_until_iso,
    }


@app.post("/v1/oracles/{oracle_id}/revoke", status_code=200)
def oracle_revoke(
    oracle_id: str,
    req: OracleRevokeRequest,
    _=Depends(require_api_key),
):
    """Revoga chave HMAC de um oráculo regulatório (Cenário 34).

    Persiste rastreabilidade no ledger (Gap 3).
    Segue padrão de /v1/agents/{id}/revoke.
    """
    entry = _ORACLE_REGISTRY_STORE.get(oracle_id)
    if entry is None or entry.get("revoked", False):
        raise HTTPException(
            status_code=404,
            detail=f"Oracle '{oracle_id}' não encontrado ou já revogado",
        )

    entry["revoked"] = True
    revoked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry["revoked_at"] = revoked_at
    entry["revocation_reason"] = req.reason

    # Persiste rastreabilidade no DurableLedger global (se disponível)
    try:
        if hasattr(app.state, "durable_ledger") and app.state.durable_ledger is not None:
            app.state.durable_ledger.append({
                "type": "oracle_revocation_api",
                "oracle_id": oracle_id,
                "revoked_at_iso": revoked_at,
                "reason": req.reason,
                "explain_decision": (
                    f"Oráculo '{oracle_id}' revogado via API em {revoked_at}. "
                    f"Motivo: {req.reason}"
                ),
            })
    except Exception as exc:  # noqa: BLE001
        logger.warning("Falha ao registrar revogação no ledger: %s", exc)

    logger.info("Oracle revogado: oracle_id=%s reason=%s", oracle_id, req.reason)
    return {"oracle_id": oracle_id, "revoked_at": revoked_at}


# ═══════════════════════════════════════════════════════════════
# C6 — CrossAgentCorrelator endpoints
# ═══════════════════════════════════════════════════════════════

class A2ACorrelateRequest(BaseModel):
    agent_id: str
    action: str


class A2AScanRequest(BaseModel):
    src: str
    dst: str
    payload: str


class A2ACollusionRequest(BaseModel):
    agent_actions: dict  # {agent_id: action}


@app.post("/v1/a2a/correlate")
def a2a_correlate(req: A2ACorrelateRequest, _=Depends(require_api_key)):
    """Check agent action for conflicts (C6 — CrossAgentCorrelator)."""
    if _cross_agent is None:
        raise HTTPException(status_code=503, detail="CrossAgentCorrelator not initialized")
    result = _cross_agent.correlate(req.agent_id, req.action)
    return {
        "allowed": result.allowed,
        "conflict": result.conflict,
        "circuit_state": result.circuit_state.value if hasattr(result.circuit_state, "value") else str(result.circuit_state),
        "explain": result.explain,
    }


@app.post("/v1/a2a/scan")
def a2a_scan(req: A2AScanRequest, _=Depends(require_api_key)):
    """Scan an agent-to-agent payload for injection patterns (C6)."""
    if _cross_agent is None:
        raise HTTPException(status_code=503, detail="CrossAgentCorrelator not initialized")
    result = _cross_agent.scan_a2a_payload(req.src, req.dst, req.payload)
    # Auto-trigger collusion detection after scan (C6 — internal, no separate endpoint abuse)
    collusion = _cross_agent.detect_collusion({req.src: req.payload[:64], req.dst: req.payload[:64]})
    return {
        "allowed": result.allowed if hasattr(result, "allowed") else True,
        "explain": result.explain if hasattr(result, "explain") else "",
        "collusion_detected": not collusion.get("allowed", True) if isinstance(collusion, dict) else False,
    }


# ═══════════════════════════════════════════════════════════════
# C6 — DelegationLedger endpoints
# ═══════════════════════════════════════════════════════════════

class DelegationRecordRequest(BaseModel):
    parent_agent: str
    child_agent: str
    scope: str
    capabilities: Optional[List[str]] = None


class DelegationRevokeRequest(BaseModel):
    record_id: str


@app.post("/v1/delegation/record", status_code=201)
def delegation_record(req: DelegationRecordRequest, _=Depends(require_api_key)):
    """Record a new agent delegation (C6 — DelegationLedger)."""
    if _delegation_ledger is None:
        raise HTTPException(status_code=503, detail="DelegationLedger not initialized")
    try:
        rec = _delegation_ledger.record_delegation(
            req.parent_agent, req.child_agent, req.scope, req.capabilities
        )
        return {
            "record_id": rec.record_id,
            "parent_agent": rec.parent_agent,
            "child_agent": rec.child_agent,
            "scope": rec.scope,
            "created_at": rec.created_at,
            "chain_hash": rec.chain_hash,
        }
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.get("/v1/delegation/{agent_id}/chain")
def delegation_chain(agent_id: str, _=Depends(require_api_key)):
    """Verify the delegation chain for an agent (C6)."""
    if _delegation_ledger is None:
        raise HTTPException(status_code=503, detail="DelegationLedger not initialized")
    result = _delegation_ledger.verify_chain(agent_id)
    return {
        "agent_id": agent_id,
        "valid": result.valid,
        "depth": result.depth,
        "chain": result.chain,
        "explain": result.explain,
    }


@app.post("/v1/delegation/{agent_id}/revoke")
def delegation_revoke(agent_id: str, req: DelegationRevokeRequest, _=Depends(require_api_key)):
    """Revoke a delegation record (C6)."""
    if _delegation_ledger is None:
        raise HTTPException(status_code=503, detail="DelegationLedger not initialized")
    try:
        _delegation_ledger.revoke_delegation(req.record_id)
        return {"record_id": req.record_id, "revoked": True}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
