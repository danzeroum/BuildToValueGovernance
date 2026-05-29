"""Ciclo de vida da aplicação FastAPI (ADR-0093 Phase 2, Passo 1).

O bloco `lifespan` foi extraído de `app.py` para isolar a fiação de startup/
shutdown da montagem do app. Símbolos definidos/importados em `app.py` são
acessados via import preguiçoso (`import ... as M`) **dentro** da função, para
evitar import circular (app.py importa `lifespan` deste módulo no topo).

# ADR-0093-Phase2-shim: remove after Passo 4
Enquanto os 105 read-sites de `app.py` ainda leem variáveis-módulo, o startup
reinjeta os 11 singletons de volta em `app.py` (shim provisório). A migração
completa para `app.state` é concluída no Passo 4, quando o shim é removido.
"""
from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path


@asynccontextmanager
async def lifespan(application):
    """Startup/shutdown lifecycle (replaces deprecated on_event)."""
    import buildtovalue.api.app as M  # lazy — evita import circular
    logger = M.logger

    # S-01: initialize the HMAC key holder before any worker starts serving.
    M.init_hmac_key()

    # PR-4: dedicated kernel executor before anything touches Rust.
    _KERNEL_EXECUTOR = ThreadPoolExecutor(
        max_workers=int(os.environ.get("BTV_KERNEL_WORKERS", "4")),
        thread_name_prefix="btv-kernel",
    )
    loop = asyncio.get_event_loop()
    try:
        application.state.ffi_client = await loop.run_in_executor(
            _KERNEL_EXECUTOR, M.get_ffi_client
        )
        logger.info("FFI bridge initialized in executor (bridge_mode=%s)",
                    application.state.ffi_client.bridge_mode)
    except M.BridgeNotAvailableError as exc:
        logger.warning("FFI bridge unavailable at startup: %s", exc)
        application.state.ffi_client = None

    M.init_db()

    from buildtovalue.intelligence.threat_feed import init_threats_db
    init_threats_db()

    _contestability_loop = M.ContestabilityLoop(
        sla_hours=24,
        db_path=os.environ.get("BTV_APPEALS_DB"),
    )
    # S-09: signing_key_fn — SIGHUP rotation propaga sem restart.
    _ethical_engine = M.EthicalContextEngine(signing_key_fn=M.get_hmac_key)

    _sensitivity_accumulator = M.SessionSensitivityAccumulator()
    application.state.sensitivity_accumulator = _sensitivity_accumulator
    logger.info("SessionSensitivityAccumulator initialized")

    # Gap 12/19: singleton — activity_log persiste durante toda a vida do processo
    _trust_calculator = M.TrustScoreCalculator()
    application.state.trust_calculator = _trust_calculator
    logger.info("TrustScoreCalculator initialized as singleton (Gap 12/19)")

    # Gap 10 + S-09: hmac_secret_fn — SIGHUP rotation propaga sem restart.
    _goal_drift_sentinel = M.GoalDriftSentinel(hmac_secret_fn=M.get_hmac_key)
    application.state.goal_drift_sentinel = _goal_drift_sentinel
    logger.info("GoalDriftSentinel initialized as singleton (Gap 10)")

    policy_root = Path(os.environ.get("BTV_POLICY_DIR", "data/policies"))

    # C6: CrossAgentCorrelator + DelegationLedger singletons
    _a2a_policy = policy_root / "agents" / "coordination_rules.yaml"
    _cross_agent = M.CrossAgentCorrelator(
        policy_path=_a2a_policy if _a2a_policy.exists() else None
    )
    application.state.cross_agent = _cross_agent
    logger.info("CrossAgentCorrelator initialized (C6)")

    _deleg_policy = policy_root / "agents" / "delegation_rules.yaml"
    # S-09: hmac_key_fn — SIGHUP rotation propaga.
    _delegation_ledger = M.DelegationLedger(
        policy_path=_deleg_policy if _deleg_policy.exists() else None,
        hmac_key_fn=M.get_hmac_key,
    )
    application.state.delegation_ledger = _delegation_ledger
    logger.info("DelegationLedger initialized (C6)")
    profiles_dir = policy_root / "agents"

    if profiles_dir.exists():
        _profile_manager = M.ProfileManager(profiles_dir)
        application.state.profile_manager = _profile_manager
        logger.info("ProfileManager initialized: %s", profiles_dir)
    else:
        _profile_manager = None
        application.state.profile_manager = None
        logger.warning("Profiles dir not found: %s", profiles_dir)

    _sector_loader = M.SectorLoader()
    logger.info("SectorLoader initialized")

    _output_validator = M.OutputSchemaValidator()  # noqa: F841 — paridade com app.py
    logger.info("OutputSchemaValidator initialized")

    hydrated = M.hydrate_from_sqlite()
    logger.info("Bridge hydration: %d threats loaded from SQLite", hydrated)

    slm_config = M._load_slm_config()
    _slm = None
    if slm_config.get("enabled", False):
        _slm = M.SLMClassifier(
            model_path=slm_config["model_path"],
            model_id=slm_config.get("model_id", "local-slm"),
            n_ctx=slm_config.get("n_ctx", 512),
            n_threads=slm_config.get("n_threads", 2),
            timeout_ms=slm_config.get("timeout_ms", 100),
            n_gpu_layers=slm_config.get("n_gpu_layers", 0),
        )
        if _slm.load_model():
            logger.info("SLM loaded: %s", slm_config["model_path"])
        else:
            logger.warning("SLM failed to load — disabled")
            _slm = None
    else:
        logger.info("SLM disabled (slm.enabled=false or config missing)")

    # ADR-047: NER detector — reutiliza SLM para extração semântica de PII
    if _slm is not None:
        _ner = M.NERDetector(_slm)
        logger.info("NER detector initialized (SLM-backed)")
    else:
        _ner = None
        logger.info("NER detector disabled (SLM not loaded)")

    from buildtovalue.api.auth import init_auth
    init_auth()

    # ADR-0093-Phase2-shim: remove after Passo 4 — reinjeta singletons nos
    # globals de app.py para os 105 read-sites ainda não migrados.
    M._contestability_loop = _contestability_loop
    M._ethical_engine = _ethical_engine
    M._trust_calculator = _trust_calculator
    M._goal_drift_sentinel = _goal_drift_sentinel
    M._cross_agent = _cross_agent
    M._delegation_ledger = _delegation_ledger
    M._profile_manager = _profile_manager
    M._sector_loader = _sector_loader
    M._slm = _slm
    M._ner = _ner
    M._KERNEL_EXECUTOR = _KERNEL_EXECUTOR

    yield

    if _KERNEL_EXECUTOR is not None:
        _KERNEL_EXECUTOR.shutdown(wait=True)
    logger.info("Shutdown complete")
