"""
BuildToValue Governance API v2.3 — montagem de borda (edge wiring).

Python side of the República Algorítmica (Judiciário). Após a decomposição
ADR-0093 (Passos 1-4), este módulo contém estritamente a fiação: criação do
app FastAPI, CORS/middleware, montagem dos routers e o mount estático do demo/.
Toda a lógica de domínio vive em routes/* e os singletons em app.state
(ver api/_lifespan.py). Sem estado global de módulo, sem shim.
"""

import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

# re-export: tests/integration/test_hmac_key.py consome este símbolo a partir do monolito
from buildtovalue.api._decide_helpers import sign_verdict as sign_verdict  # noqa: F401,E402


def _load_slm_config() -> dict[str, object]:
    """Load SLM config. Env var overrides YAML. (bootstrap deferido — Passo 2)."""
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
                    parsed = yaml.safe_load(f)
                slm = parsed.get("slm", {}) if isinstance(parsed, dict) else {}
                return slm if isinstance(slm, dict) else {}
        except Exception as e:
            logger.warning("Failed to load SLM config from %s: %s", config_path, e)
    return {}


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


# ADR-0093 Phase 2 (Passo 1): lifespan extraído para api/_lifespan.py (inicializa
# todos os singletons em app.state; Passo 4 Commit 2 removeu o shim).
from buildtovalue.api._lifespan import lifespan  # noqa: E402

app = FastAPI(title="BuildToValue Governance", version="0.1.0a1", lifespan=lifespan)

# HIGH-01: rate limiting (slowapi). The shared limiter lives in api/_limiter.py;
# per-route limits are applied with @limiter.limit (e.g. login = 10/minute).
from slowapi import _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402

from buildtovalue.api._limiter import limiter  # noqa: E402

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-BTV-Session", "X-BTV-Jurisdiction"],
)

# CRITICO-04: security headers applied to every response (was dead code in an
# isolated FastAPI() instance in response_sanitizer.py).
from buildtovalue.api.response_sanitizer import SecurityHeadersMiddleware  # noqa: E402

app.add_middleware(SecurityHeadersMiddleware)

# ─── Routers (toda a lógica de domínio; ADR-0093 Passos 3-4) ───────────────────
from buildtovalue.api.routes.intelligence import (  # noqa: E402
    router as intelligence_router,
    hub_router as intelligence_hub_router,
)
from buildtovalue.api.routes.ledger import router as ledger_router  # noqa: E402
from buildtovalue.api.routes.webhooks import router as webhooks_router  # noqa: E402
from buildtovalue.api.routes.compliance_eval import router as compliance_eval_router  # noqa: E402
from buildtovalue.api.routes.auth import router as auth_router  # noqa: E402
from buildtovalue.api.routes.agent_decide import router as agent_decide_router  # noqa: E402
from buildtovalue.api.routes.fleet import router as fleet_router  # noqa: E402
from buildtovalue.api.routes.metrics import router as metrics_router  # noqa: E402
from buildtovalue.api.routes.health import router as health_router  # noqa: E402
from buildtovalue.api.routes.appeals import router as appeals_router  # noqa: E402
from buildtovalue.api.routes.compliance import router as compliance_router  # noqa: E402
from buildtovalue.api.routes.agents import router as agents_router  # noqa: E402
from buildtovalue.api.routes.slm_ner import router as slm_ner_router  # noqa: E402
from buildtovalue.api.routes.decide import router as decide_router  # noqa: E402

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

# ─── Lab v3.0 — demo/ servido estaticamente same-origin (4× .parent = raiz) ────
_BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
_DEMO_PATH = _BASE_DIR / "demo"
if _DEMO_PATH.exists():
    app.mount("/demo", StaticFiles(directory=str(_DEMO_PATH), html=True), name="demo")
    logger.info("demo/ mounted at /demo: %s", _DEMO_PATH)
else:
    logger.warning("demo/ not found at %s — static UI not mounted", _DEMO_PATH)
