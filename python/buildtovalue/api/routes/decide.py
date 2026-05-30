"""Decision hot-path routes (ADR-0093 Phase 2, Passo 4 — extração).

/v1/decide e /v1/multi-decide e todo o pipeline de decisão (_decide_* + guards +
trust helpers + classes acumuladoras) extraídos de app.py para este módulo.

Commit 1 (esta extração): mantém o shim provisório — os singletons do hot path
permanecem como globais de MÓDULO aqui, reinjetados pelo lifespan (M.→D.). A
migração para app.state + Depends é feita no Commit 2 (remoção do shim).
"""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import NamedTuple, Optional, cast

from fastapi import APIRouter, Depends, HTTPException, Request

from buildtovalue.api._db import (
    db_get_session,
    db_update_session,
    db_update_session_state,
)
from buildtovalue.api._decide_helpers import (
    _build_bias_declaration,
    _resolve_domain,
    _resolve_role,
    sign_verdict,
)
from buildtovalue.api._models import (
    DecideRequest,
    DecideResponse,
    MultiDecideRequest,
    MultiDecideResponse,
)
from buildtovalue.api.auth import require_api_key
from buildtovalue.compliance.risk_classifier import RiskClassifier
from buildtovalue.governance.context_engine import (
    EthicalContextEngine,
    EthicalVerdict,
    RequestContext,
    RustEvidence,
)
from buildtovalue.governance.ffi_client import FFIError
from buildtovalue.governance.goal_drift_sentinel import DriftReport, GoalDriftSentinel
from buildtovalue.governance.mercy_scenarios import ACTION_SEVERITY, SEVERITY_ACTION
from buildtovalue.governance.output_validator import OutputSchemaValidator
from buildtovalue.governance.profile_manager import ProfileManager
from buildtovalue.governance.rag_integrity_verifier import RagIntegrityVerifier
from buildtovalue.governance.sector_loader import SectorLoader
from buildtovalue.governance.sensitivity_accumulator import (
    SensitivityState,
    SessionSensitivityAccumulator,
)
from buildtovalue.governance.trust_score import TrustScoreCalculator
from buildtovalue.governance.visual_input_firewall import (
    FirewallVerdict as VisualFirewallVerdict,
    VisualInputFirewall,
)
from buildtovalue.intelligence.slm_classifier import SLMClassifier, SLMContext

logger = logging.getLogger(__name__)

# ── Hot-path singletons (ADR-0093 Passo 4 Commit 2: shim removido) ──
# As rotas resolvem os singletons de app.state via Depends(get_decide_singletons)
# e os passam aos helpers _decide_* como parâmetros. Sem estado global de módulo.
class _DecideCtx(NamedTuple):
    # Obrigatórios (Fail-Secure gate → 503 se ausentes):
    risk_classifier: RiskClassifier
    ethical_engine: EthicalContextEngine
    # Degradação graciosa (helpers já tratam None — comportamento legado preservado):
    profile_manager: Optional[ProfileManager]
    sector_loader: Optional[SectorLoader]
    slm: Optional[SLMClassifier]
    output_validator: Optional[OutputSchemaValidator]
    sensitivity_accumulator: Optional[SessionSensitivityAccumulator]
    trust_calculator: Optional[TrustScoreCalculator]
    goal_drift_sentinel: Optional[GoalDriftSentinel]


def get_decide_singletons(request: Request) -> _DecideCtx:
    """Resolve os singletons do hot path de app.state (Fail-Secure 503).

    A ausência dos singletons essenciais do ecossistema ético (ethical_engine,
    risk_classifier) significa bootstrap quebrado → recusa Fail-Secure (HTTP 503),
    nunca uma decisão não regulada. Os demais degradam graciosamente (None).
    """
    st = request.app.state
    ethical = getattr(st, "ethical_engine", None)
    risk = getattr(st, "risk_classifier", None)
    if not isinstance(ethical, EthicalContextEngine) or not isinstance(risk, RiskClassifier):
        raise HTTPException(
            status_code=503,
            detail="FAIL-SECURE: decide pipeline singletons não inicializados no lifespan.",
        )
    return _DecideCtx(
        risk_classifier=risk,
        ethical_engine=ethical,
        profile_manager=getattr(st, "profile_manager", None),
        sector_loader=getattr(st, "sector_loader", None),
        slm=getattr(st, "slm", None),
        output_validator=getattr(st, "output_validator", None),
        sensitivity_accumulator=getattr(st, "sensitivity_accumulator", None),
        trust_calculator=getattr(st, "trust_calculator", None),
        goal_drift_sentinel=getattr(st, "goal_drift_sentinel", None),
    )

router = APIRouter()


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
        registry: dict[str, object] = cfg.get("channel_registry", {}) if cfg else {}
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


def get_trust_score(session_id: Optional[str]) -> float:
    if not session_id:
        return 0.5
    return cast(float, db_get_session(session_id)["trust_score"])


def update_trust(session_id: Optional[str], action: str) -> float:
    if not session_id:
        return 0.5
    session = db_get_session(session_id)
    current = cast(float, session["trust_score"])
    if action in ("ALLOW", "LOG"):
        current = min(1.0, current + 0.02)
    elif action == "EDUCATE":
        current = max(0.0, current - 0.05)
    elif action == "BLOCK":
        current = max(0.0, current - 0.15)
    offense_delta = 1 if action not in ("ALLOW", "LOG") else 0
    db_update_session(session_id, current, offense_delta)
    return current


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
        self.violations: Optional[list[dict[str, object]]] = None
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
    _profile_manager: "Optional[ProfileManager]",
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
    _sensitivity_accumulator: "Optional[SessionSensitivityAccumulator]",
    _goal_drift_sentinel: "Optional[GoalDriftSentinel]",
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
    _slm: "Optional[SLMClassifier]",
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
        violation_count=cast(int, db_get_session(session_id)["offenses"]) if session_id else 0,
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
    _profile_manager: "Optional[ProfileManager]",
    _sector_loader: "Optional[SectorLoader]",
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
    _ethical_engine: EthicalContextEngine,
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
    _risk_classifier: RiskClassifier,
    _profile_manager: "Optional[ProfileManager]",
) -> _ComplianceMeta:
    meta = _ComplianceMeta()
    if _risk_classifier is None:
        return meta
    sector_id = _resolve_domain(req.profile) or "general"
    caps: list[str] = []
    if req.profile and _profile_manager:
        try:
            loaded = _profile_manager.load_profile(req.profile)
            caps = cast("list[str]", loaded.domain_config.get("capabilities", []))
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
    _profile_manager: "Optional[ProfileManager]",
    _slm: "Optional[SLMClassifier]",
    _ethical_engine: EthicalContextEngine,
    _output_validator: "Optional[OutputSchemaValidator]",
) -> "tuple[EthicalVerdict, Optional[list[object]], Optional[str]]":
    """Schema validation + SLM output analysis + SLM explanation.

    Returns (possibly updated verdict, schema_violations, slm_explanation).
    """
    schema_violations: Optional[list[object]] = None
    if req.llm_output and req.profile and _profile_manager:
        try:
            loaded = _profile_manager.load_profile(req.profile)
            output_schema = loaded.output_schema
            if output_schema and _output_validator:
                schema_result = _output_validator.validate(req.llm_output, output_schema)
                if not schema_result.valid:
                    schema_violations = cast("list[object]", [
                        {"path": v.path, "rule": v.rule, "message": v.message}
                        for v in schema_result.violations
                    ])
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
    _trust_calculator: "Optional[TrustScoreCalculator]",
) -> None:
    if session_id:
        prev = db_get_session(session_id)
        if prev["last_action"] in ("BLOCK", "EDUCATE") and cast(float, prev["last_entropy"]) > 0.0:
            if _trust_calculator is not None:
                delta = _trust_calculator.adjust_post_penalty(
                    session_id=session_id,
                    pre_block_entropy=cast(float, prev["last_entropy"]),
                    post_block_entropy=req.entropy,
                    subsequent_action=verdict.final_action,
                )
                if delta != 0.0:
                    session_data = db_get_session(session_id)
                    new_trust = max(0.0, min(1.0, cast(float, session_data["trust_score"]) + delta))
                    db_update_session(session_id, new_trust, 0)
                    logger.info(
                        "adjust_post_penalty persisted: session=%s delta=%.3f new_trust=%.3f",
                        session_id, delta, new_trust,
                    )
        db_update_session_state(session_id, req.entropy, verdict.final_action)

        # Action Graph telemetry (ADR-041)
        prev_action = cast(str, prev["last_action"])
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


@router.post("/v1/decide", response_model=DecideResponse)
def decide(
    req: DecideRequest,
    request: Request,
    ctx: _DecideCtx = Depends(get_decide_singletons),
    _: None = Depends(require_api_key),
) -> DecideResponse:
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
    _ffi_categories: list[str] = []
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

    resp = _decide_run_guards(req, session_id, start, ctx.profile_manager)
    if resp:
        return resp

    adj = _AdjSignals(req)
    sensitivity_state, drift_report = _decide_accumulate_signals(
        req, session_id, ctx.sensitivity_accumulator, ctx.goal_drift_sentinel,
    )
    slm_meta = _decide_slm(req, session_id, adj, ctx.slm)
    sector_note, cumulative_note, drift_cross_note = _decide_adjust_risk(
        req, session_id, adj, sensitivity_state, drift_report,
        ctx.profile_manager, ctx.sector_loader,
    )

    verdict, context = _decide_ethical_verdict(
        req, session_id, adj, slm_meta, sensitivity_state, ctx.ethical_engine,
    )
    compliance = _decide_compliance(req, adj, verdict, ctx.risk_classifier, ctx.profile_manager)
    verdict, schema_violations, slm_explanation = _decide_output_pipeline(
        req, session_id, adj, context, verdict, slm_meta,
        ctx.profile_manager, ctx.slm, ctx.ethical_engine, ctx.output_validator,
    )

    _decide_persist_trust(session_id, req, verdict, context, ctx.trust_calculator)

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


@router.post("/v1/multi-decide", response_model=MultiDecideResponse)
async def multi_decide(
    req: MultiDecideRequest, request: Request, _: None = Depends(require_api_key)
) -> MultiDecideResponse:
    """Lab v3.0 — fan-out concorrente do mesmo prompt para N agentes.

    Governance é síncrono; paralelizamos no boundary FFI/I-O com
    asyncio.to_thread (nunca threading manual). Reutiliza decide() — sem
    duplicar a pipeline de decisão.
    """
    if not req.agent_ids:
        raise HTTPException(status_code=422, detail="agent_ids must not be empty")

    # decide() é chamado diretamente (não via FastAPI), então o Depends de ctx
    # não é auto-injetado — resolvemos uma vez e repassamos (Fail-Secure herdado).
    ctx = get_decide_singletons(request)

    def _one(agent_id: str) -> DecideResponse:
        single = DecideRequest(
            input_text=req.prompt,
            session_id=req.session_id or f"multi-{agent_id}",
            profile=agent_id,
            agent_policies=[agent_id],
        )
        return decide(single, request, ctx)

    verdicts = await asyncio.gather(
        *[asyncio.to_thread(_one, aid) for aid in req.agent_ids]
    )
    return MultiDecideResponse(verdicts=list(verdicts))
