"""Ciclo de vida da aplicação FastAPI (ADR-0093 Phase 2, Passo 1).

O bloco `lifespan` foi extraído de `app.py` para isolar a fiação de startup/
shutdown da montagem do app. Símbolos de biblioteca são importados das suas
fontes reais (sem ciclo — esses módulos não importam `app.py`). As poucas
funções definidas em `app.py` (`init_db`, `_load_slm_config`, `logger`) são
importadas de forma preguiçosa **dentro** da função (executadas no startup,
após `app.py` já estar carregado), evitando import circular.

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
from typing import AsyncIterator, Optional

from fastapi import FastAPI

from buildtovalue.api.routes.intelligence import hydrate_from_sqlite
from buildtovalue.governance.context_engine import EthicalContextEngine
from buildtovalue.governance.contestability_loop import ContestabilityLoop
from buildtovalue.governance.cross_agent_correlator import CrossAgentCorrelator
from buildtovalue.governance.delegation_ledger import DelegationLedger
from buildtovalue.governance.ffi_client import (
    BridgeNotAvailableError,
    get_ffi_client,
)
from buildtovalue.governance.goal_drift_sentinel import GoalDriftSentinel
from buildtovalue.governance.output_validator import OutputSchemaValidator
from buildtovalue.governance.profile_manager import ProfileManager
from buildtovalue.governance.sector_loader import SectorLoader
from buildtovalue.governance.sensitivity_accumulator import (
    SessionSensitivityAccumulator,
)
from buildtovalue.governance.trust_score import TrustScoreCalculator
from buildtovalue.intelligence.ner_detector import NERDetector
from buildtovalue.intelligence.slm_classifier import SLMClassifier
from buildtovalue.security import get_hmac_key, init_hmac_key


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown lifecycle (replaces deprecated on_event)."""
    # Lazy: definidos em app.py — import no startup (após app.py carregar) evita
    # o ciclo de import (app.py importa `lifespan` deste módulo no topo).
    import buildtovalue.api.app as M
    from buildtovalue.api.app import (  # noqa: E402
        _load_slm_config,
        init_db,
        logger,
    )

    # S-01: initialize the HMAC key holder before any worker starts serving.
    init_hmac_key()

    # PR-4: dedicated kernel executor before anything touches Rust.
    _KERNEL_EXECUTOR = ThreadPoolExecutor(
        max_workers=int(os.environ.get("BTV_KERNEL_WORKERS", "4")),
        thread_name_prefix="btv-kernel",
    )
    loop = asyncio.get_event_loop()
    try:
        application.state.ffi_client = await loop.run_in_executor(
            _KERNEL_EXECUTOR, get_ffi_client
        )
        logger.info("FFI bridge initialized in executor (bridge_mode=%s)",
                    application.state.ffi_client.bridge_mode)
    except BridgeNotAvailableError as exc:
        logger.warning("FFI bridge unavailable at startup: %s", exc)
        application.state.ffi_client = None

    init_db()  # type: ignore[no-untyped-call]  # app.py-defined, sem anotação

    from buildtovalue.intelligence.threat_feed import init_threats_db
    init_threats_db()  # type: ignore[no-untyped-call]  # sem anotação na origem

    _contestability_loop = ContestabilityLoop(
        sla_hours=24,
        db_path=os.environ.get("BTV_APPEALS_DB"),
    )
    application.state.contestability_loop = _contestability_loop
    # S-09: signing_key_fn — SIGHUP rotation propaga sem restart.
    _ethical_engine = EthicalContextEngine(signing_key_fn=get_hmac_key)
    application.state.ethical_engine = _ethical_engine

    _sensitivity_accumulator = SessionSensitivityAccumulator()
    application.state.sensitivity_accumulator = _sensitivity_accumulator
    logger.info("SessionSensitivityAccumulator initialized")

    # Gap 12/19: singleton — activity_log persiste durante toda a vida do processo
    _trust_calculator = TrustScoreCalculator()
    application.state.trust_calculator = _trust_calculator
    logger.info("TrustScoreCalculator initialized as singleton (Gap 12/19)")

    # Gap 10 + S-09: hmac_secret_fn — SIGHUP rotation propaga sem restart.
    _goal_drift_sentinel = GoalDriftSentinel(hmac_secret_fn=get_hmac_key)
    application.state.goal_drift_sentinel = _goal_drift_sentinel
    logger.info("GoalDriftSentinel initialized as singleton (Gap 10)")

    policy_root = Path(os.environ.get("BTV_POLICY_DIR", "data/policies"))

    # C6: CrossAgentCorrelator + DelegationLedger singletons
    _a2a_policy = policy_root / "agents" / "coordination_rules.yaml"
    _cross_agent = CrossAgentCorrelator(
        policy_path=_a2a_policy if _a2a_policy.exists() else None
    )
    application.state.cross_agent = _cross_agent
    logger.info("CrossAgentCorrelator initialized (C6)")

    _deleg_policy = policy_root / "agents" / "delegation_rules.yaml"
    # S-09: hmac_key_fn — SIGHUP rotation propaga.
    _delegation_ledger = DelegationLedger(
        policy_path=_deleg_policy if _deleg_policy.exists() else None,
        hmac_key_fn=get_hmac_key,
    )
    application.state.delegation_ledger = _delegation_ledger
    logger.info("DelegationLedger initialized (C6)")
    profiles_dir = policy_root / "agents"

    _profile_manager: Optional[ProfileManager]
    if profiles_dir.exists():
        _profile_manager = ProfileManager(profiles_dir)
        application.state.profile_manager = _profile_manager
        logger.info("ProfileManager initialized: %s", profiles_dir)
    else:
        _profile_manager = None
        application.state.profile_manager = None
        logger.warning("Profiles dir not found: %s", profiles_dir)

    _sector_loader = SectorLoader()
    logger.info("SectorLoader initialized")

    _output_validator = OutputSchemaValidator()  # noqa: F841 — paridade com app.py
    logger.info("OutputSchemaValidator initialized")

    hydrated = hydrate_from_sqlite()
    logger.info("Bridge hydration: %d threats loaded from SQLite", hydrated)

    slm_config = _load_slm_config()
    _slm: Optional[SLMClassifier] = None
    if slm_config.get("enabled", False):
        _slm = SLMClassifier(
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
    application.state.slm = _slm

    # ADR-047: NER detector — reutiliza SLM para extração semântica de PII
    _ner: Optional[NERDetector]
    if _slm is not None:
        _ner = NERDetector(_slm)
        logger.info("NER detector initialized (SLM-backed)")
    else:
        _ner = None
        logger.info("NER detector disabled (SLM not loaded)")

    from buildtovalue.api.auth import init_auth
    init_auth()  # type: ignore[no-untyped-call]  # auth.init_auth sem anotação

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
