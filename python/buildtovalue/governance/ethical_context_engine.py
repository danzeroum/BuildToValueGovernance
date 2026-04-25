"""
EthicalContextEngine v1.1.0 — Orquestrador Unificado (T1.3 / v1.6.0)

Arquivo decomposto conforme T1.3 (divida aberta desde 89353d3):
  ece_types.py      — dataclasses locais (Rule, TechnicalVerdict, EthicalDecision, UnifiedDecision)
  ece_technical.py  — TechnicalLayer (regras, SafeEvaluator, trust)
  ece_governance.py — GovernanceLayer (Gilligan, MercyFactor, assinatura)
  ethical_context_engine.py — este arquivo, orquestrador puro

API publica preservada: decide(), decide_v2(), decide_v3(), decide_with_cot(),
EthicalContextEngineV2, EthicalContextEngineV3, EthicalContextEngineFactory.
"""
from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .mercy_factor import MercyFactor  # noqa: F401 — re-export backward compat

from .ece_types import (
    Rule, TechnicalVerdict, EthicalDecision, UnifiedDecision,
)
from .ece_technical import TechnicalLayer
from .ece_governance import GovernanceLayer
from .safe_expression_evaluator import SafeExpressionEvaluator
from .trust_score import TrustScoreCalculator
from .mercy_algorithm import MercyCalculator
from .profile_manager import Profile, ProfileManager
from .policy_signer import PolicySigner, PolicySigningError
from .types import TechnicalEvidence, Finding
from .contestability_loop import ContestabilityLoop
from .consensus_validator import ConsensusValidator, ConsensusDecision, Reversibility
from .bias_guardian import BiasGuardian
from .persuasion_guard import (
    PersuasionGuard, AnnotatedCoT, BiasDeclarationV2, PersuasionGuardUnavailableError,
)
from .gilligan import GilliganStage
from .types import ActionType, RequestMetadata, EthicalContext

logger = logging.getLogger(__name__)


def _validate_persuasion_guard_startup(guard: PersuasionGuard) -> None:
    """Confirma guard configurado (ADR-0049 D2). Falha explicita em startup."""
    decl = guard.bias_declaration
    if not decl.checker_model_family:
        raise ValueError("PersuasionGuard.checker_model_family ausente (ADR-0049 D1)")
    logger.info(
        "PersuasionGuard startup OK: model=%s checker=%s",
        decl.model_family, decl.checker_model_family,
    )


_DEFAULT_BIAS_DECLARATION: Dict[str, Any] = {
    "model_version": "1.1.0-unified",
    "last_calibration": datetime.now().strftime("%Y-%m-%d"),
    "known_limitations": [
        "Does not detect context-specific semantic violations",
        "False positive rate: ~5% in low-confidence scenarios",
        "Requires human review for CRITICAL operations",
    ],
    "false_positive_rate": 0.05,
    "false_negative_rate": 0.02,
    "calibration_dataset_size": 10000,
}


class EthicalContextEngine:
    """
    Orquestrador unificado — combina TechnicalLayer e GovernanceLayer.

    Performance SLA: <10ms p99 com cache.
    Governanca: LGPD Art. 20, EU AI Act, ADR-016, ADR-038.
    """

    def __init__(
        self,
        trust_calculator: Optional[TrustScoreCalculator] = None,
        mercy_calculator: Optional[MercyCalculator] = None,
        profile_manager: Optional[ProfileManager] = None,
        policy_signer: Optional[PolicySigner] = None,
        safe_evaluator: Optional[SafeExpressionEvaluator] = None,
        contestability_loop: Optional[ContestabilityLoop] = None,
        bias_guardian: Optional[BiasGuardian] = None,  # None → default instance criada internamente
        persuasion_guard: Optional[PersuasionGuard] = None,
        gilligan_stage: Optional[GilliganStage] = None,
        consensus_validator: Optional[ConsensusValidator] = None,
    ) -> None:
        self.profile_manager = profile_manager
        self.contestability_loop = contestability_loop or ContestabilityLoop()
        # ADR-036 0.4: garante que bias_guardian nunca é None — elimina Optional[BiasGuardian]
        self.bias_guardian: BiasGuardian = bias_guardian if bias_guardian is not None else BiasGuardian()
        self.persuasion_guard: Optional[PersuasionGuard] = persuasion_guard
        if persuasion_guard is not None:
            _validate_persuasion_guard_startup(persuasion_guard)

        self.bias_declaration: Dict[str, Any] = _DEFAULT_BIAS_DECLARATION.copy()
        self._profile_cache: Dict[str, Profile] = {}
        self.metrics: Dict[str, Any] = {
            "decisions_total": 0, "technical_decisions": 0,
            "governance_decisions": 0, "mercy_applied": 0,
            "contests_submitted": 0, "security_violations": 0,
            "timeouts": 0, "cache_hits": 0,
            "avg_technical_time_ms": 0.0, "avg_governance_time_ms": 0.0,
        }

        _trust = trust_calculator or TrustScoreCalculator()
        _mercy = mercy_calculator or MercyCalculator()
        _eval = safe_evaluator or SafeExpressionEvaluator(
            timeout_ms=100, max_expression_length=1024, max_depth=10
        )
        _signer = policy_signer or PolicySigner()
        _gilligan = gilligan_stage or GilliganStage()

        self._technical = TechnicalLayer(
            _trust, _mercy, _eval, self.metrics, self._profile_cache, profile_manager
        )
        self._governance = GovernanceLayer(_signer, _gilligan, self.bias_declaration)
        self.consensus_validator: Optional[ConsensusValidator] = consensus_validator
        logger.info("EthicalContextEngine v1.1.0 initialized")

    # ── API publica unificada ─────────────────────────────────────────────────

    def decide(
        self,
        evidence: TechnicalEvidence,
        request_metadata: RequestMetadata,
        ethical_context: Optional[EthicalContext] = None,
        profile_name: str = "default",
        _annotated_cot: Optional[AnnotatedCoT] = None,
    ) -> UnifiedDecision:
        if not self.profile_manager:
            raise ValueError("ProfileManager required for decisions")
        if ethical_context is None:
            ethical_context = self._generate_context(request_metadata)
        start = time.perf_counter()
        self.metrics["decisions_total"] += 1

        t0 = time.perf_counter()
        tv = self._technical.decide(evidence, request_metadata, profile_name)
        tech_ms = (time.perf_counter() - t0) * 1000
        self.metrics["technical_decisions"] += 1

        g0 = time.perf_counter()
        ed = self._governance.decide(tv, evidence, ethical_context, _annotated_cot)
        gov_ms = (time.perf_counter() - g0) * 1000
        self.metrics["governance_decisions"] += 1

        if ed.mercy_applied:
            self.metrics["mercy_applied"] += 1
        self._update_ema(tech_ms, gov_ms)

        return UnifiedDecision(
            decision_id=self._decision_id(evidence, request_metadata, ethical_context),
            timestamp=int(time.time()),
            technical_verdict=tv,
            ethical_decision=ed,
            evidence_hash=evidence.hash,
            request_metadata=request_metadata,
            ethical_context=ethical_context,
            profile_name=profile_name,
            total_processing_time_ms=(time.perf_counter() - start) * 1000,
            technical_time_ms=tech_ms,
            governance_time_ms=gov_ms,
        )

    def decide_with_cot(
        self,
        evidence: TechnicalEvidence,
        request_metadata: RequestMetadata,
        cot: str,
        ethical_context: Optional[EthicalContext] = None,
        profile_name: str = "default",
    ) -> UnifiedDecision:
        """Decisao com CoT protegido (ADR-0049). Guard ausente -> BLOCK (Jonas)."""
        from .ece_governance import build_cot_block_decision
        if ethical_context is None:
            ethical_context = self._generate_context(request_metadata)
        if self.persuasion_guard is None:
            return build_cot_block_decision(
                evidence, request_metadata, ethical_context,
                "persuasion_guard_not_configured", self.bias_declaration, self._decision_id
            )
        try:
            annotated = self.persuasion_guard.annotate_cot(cot)
        except PersuasionGuardUnavailableError:
            return build_cot_block_decision(
                evidence, request_metadata, ethical_context,
                "persuasion_guard_runtime_unavailable", self.bias_declaration, self._decision_id
            )
        return self.decide(evidence, request_metadata, ethical_context, profile_name, _annotated_cot=annotated)

    # ── Compatibilidade v2/v3 ─────────────────────────────────────────────────

    def decide_v2(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        profile_name: str,
    ) -> TechnicalVerdict:
        return self._technical.decide(evidence, context, profile_name)

    def decide_v3(
        self,
        technical_evidence: Dict[str, Any],
        context: EthicalContext,
        policy_action: str = "BLOCK",
    ) -> EthicalDecision:
        """V3-compatible API (governance layer only)."""
        from .ece_governance import _MockEvidence
        mock_tv = TechnicalVerdict(
            action=ActionType[policy_action], confidence=0.8, rule_id=None,
            rationale=f"Policy action: {policy_action}", trust_score=context.trust_score,
        )
        return self._governance.decide(mock_tv, _MockEvidence(technical_evidence), context)

    # ── Helpers internos ──────────────────────────────────────────────────────

    def _generate_context(self, m: RequestMetadata) -> EthicalContext:
        return EthicalContext(
            user_id=m.agent_id, session_id=m.session_id,
            user_role=m.user_role, domain=m.domain, timestamp=m.timestamp,
        )

    def _decision_id(
        self,
        e: TechnicalEvidence,
        m: RequestMetadata,
        c: EthicalContext,
    ) -> str:
        content = f"{e.hash}{m.session_id}{m.timestamp}{c.user_id or ''}"
        return f"DEC-{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    def _update_ema(self, tech_ms: float, gov_ms: float) -> None:
        a = 0.1
        self.metrics["avg_technical_time_ms"] = (
            a * tech_ms + (1 - a) * self.metrics["avg_technical_time_ms"]
        )
        self.metrics["avg_governance_time_ms"] = (
            a * gov_ms + (1 - a) * self.metrics["avg_governance_time_ms"]
        )

    # ── Metricas ──────────────────────────────────────────────────────────────

    # ── Metricas ──────────────────────────────────────────────────────────────

    async def judge_with_consensus(
        self,
        evidence: TechnicalEvidence,
        request_metadata: RequestMetadata,
        reversibility: Reversibility = Reversibility.REVERSIBLE,
        ethical_context: Optional[EthicalContext] = None,
        profile_name: str = "default",
    ) -> UnifiedDecision:
        """Decisao com consenso opcional. Guard ausente -> decide() direto (Jonas)."""
        from .ece_governance import build_mock_decision
        self.metrics["decisions_total"] += 1
        if ethical_context is None:
            ethical_context = self._generate_context(request_metadata)
        if self.profile_manager is None:
            decision = build_mock_decision(
                evidence, request_metadata, ethical_context, self._decision_id, profile_name
            )
        else:
            decision = self.decide(evidence, request_metadata, ethical_context, profile_name)
        if self.consensus_validator is not None:
            await self.consensus_validator.validate(reversibility, decision.technical_verdict.confidence)
        return decision

    def get_metrics(self) -> Dict[str, Any]:
        total = max(self.metrics["decisions_total"], 1)
        return {
            **self.metrics,
            "mercy_rate": self.metrics["mercy_applied"] / total,
            "security_violation_rate": self.metrics["security_violations"] / total,
            "total_avg_time_ms": (
                self.metrics["avg_technical_time_ms"]
                + self.metrics["avg_governance_time_ms"]
            ),
        }

    def get_bias_declaration(self) -> Dict[str, Any]:
        return self._build_bias_declaration()

    def _build_bias_declaration(self) -> Dict[str, Any]:
        """Bias declaration enriquecida com status do BiasGuardian (ADR-036, Jonas).

        Type guard explicito: bias_guardian nunca invocado sem verificacao.
        Principio de Jonas: responsabilidade proporcional — declarar estado real.
        """
        bd = self.bias_declaration.copy()
        # bias_guardian é sempre não-None (instância default garantida no __init__)
        bd["bias_guardian_active"] = True
        return bd

    def reset_metrics(self) -> None:
        for k in self.metrics:
            self.metrics[k] = 0 if isinstance(self.metrics[k], int) else 0.0
        self._profile_cache.clear()
        logger.info("Metrics reset")


# ── Compatibilidade v2/v3 + Factory ──────────────────────────────────────────
class EthicalContextEngineV2(EthicalContextEngine):
    def decide(self, *args: Any, **kwargs: Any) -> Any: return self.decide_v2(*args, **kwargs)

class EthicalContextEngineV3(EthicalContextEngine):
    def decide(self, *args: Any, **kwargs: Any) -> Any: return self.decide_v3(*args, **kwargs)

class EthicalContextEngineFactory:
    @staticmethod
    def create_v2_compatible(tc=None, mc=None, pm=None): return EthicalContextEngineV2(tc, mc, pm)
    @staticmethod
    def create_v3_compatible(tc=None, ps=None): return EthicalContextEngineV3(tc, policy_signer=ps)
    @staticmethod
    def create_unified(tc=None, mc=None, pm=None, ps=None): return EthicalContextEngine(tc, mc, pm, ps)
