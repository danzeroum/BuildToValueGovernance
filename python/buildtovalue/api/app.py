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
import hmac
import logging
import os
import sqlite3
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
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









# ═══════════════════════════════════════════════════════════════
# HMAC KEY (Gap #10 — env var, fail-secure in production)
# ═══════════════════════════════════════════════════════════════

from buildtovalue.security import get_hmac_key, init_hmac_key



# ═══════════════════════════════════════════════════════════════
# DATABASE (SQLite trust persistence)
# ═══════════════════════════════════════════════════════════════

DB_PATH = os.environ.get("BTV_DB_PATH", "data/trust.db")


# ADR-0093 Phase 2 (Passo 3): camada SQLite extraída para api/_db.py.
# Reimportada aqui para preservar os call-sites internos e o lifespan.
from buildtovalue.api._db import (  # noqa: E402
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

# COMPLIANCE_PLUGINS migrado para routes/compliance.py (ADR-0093 Passo 3 r3).








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

from buildtovalue.api.routes.intelligence import (
    router as intelligence_router,
    hub_router as intelligence_hub_router,
)
from buildtovalue.api.routes.ledger import router as ledger_router
from buildtovalue.api.routes.webhooks import router as webhooks_router
from buildtovalue.api.routes.compliance_eval import router as compliance_eval_router
from buildtovalue.api.routes.auth import router as auth_router
from buildtovalue.api.routes.agent_decide import router as agent_decide_router
from buildtovalue.api.routes.fleet import router as fleet_router
from buildtovalue.api.routes.metrics import router as metrics_router
from buildtovalue.api.routes.health import router as health_router
from buildtovalue.api.routes.appeals import router as appeals_router
from buildtovalue.api.routes.compliance import router as compliance_router
from buildtovalue.api.routes.agents import router as agents_router
from buildtovalue.api.routes.slm_ner import router as slm_ner_router
from buildtovalue.api.routes.decide import router as decide_router
app.include_router(intelligence_router)
app.include_router(intelligence_hub_router)
app.include_router(ledger_router)
app.include_router(webhooks_router)
app.include_router(compliance_eval_router)
app.include_router(auth_router)
app.include_router(agent_decide_router)
app.include_router(fleet_router)
app.include_router(metrics_router)
app.include_router(health_router)
app.include_router(appeals_router)
app.include_router(compliance_router)
app.include_router(agents_router)
app.include_router(slm_ner_router)
app.include_router(decide_router)

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
_ner: Optional[NERDetector] = None
# Gap 12/19: singleton (nao mais inline por request)
# Gap 10: singleton com ring buffer de sessões
# C6: multi-agent governance singletons
_cross_agent: Optional[CrossAgentCorrelator] = None
_delegation_ledger: Optional[DelegationLedger] = None
# PR-4: kernel executor — isolates blocking Rust calls from the event loop
_KERNEL_EXECUTOR: Optional[ThreadPoolExecutor] = None

# ═══════════════════════════════════════════════════════════════
# GOVERNANCE — /v1/decide helpers
# ═══════════════════════════════════════════════════════════════









# ═══════════════════════════════════════════════════════════════
# GOVERNANCE — /v1/decide (Judiciário da República Algorítmica)
# ═══════════════════════════════════════════════════════════════





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

# ADR-0093 Phase 2 (Passo 3, router 3): /v1/compliance/* (8 rotas) migrado para
# routes/compliance.py. _risk_classifier via app.state.risk_classifier (Depends);
# plugins/geradores module-level no router. Registrado abaixo.

# ADR-0093 Phase 2 (Passo 3, router 6): /v1/intelligence/* (ingest, ingest/batch,
# query, threat/{id}, stats) fundido em routes/intelligence.py (hub_router, sem o
# prefixo /bridge). Registrado abaixo.
