"""
ece_governance.py — Camada de Governanca do EthicalContextEngine (T1.3 / v1.6.0)

Responsabilidade unica: contestabilidade, assinatura HMAC, Gilligan,
MercyFactor, EthicalDecision.
"""
from __future__ import annotations
import hashlib
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .ece_types import EthicalDecision, TechnicalVerdict
from .mercy_factor import MercyFactor
from .types import ActionType, EthicalContext
from .ffi_client import TechnicalEvidence
from .policy_signer import PolicySigner, PolicySigningError
from .gilligan import GilliganStage
from .persuasion_guard import AnnotatedCoT

logger = logging.getLogger(__name__)


def calculate_technical_uncertainty(evidence: TechnicalEvidence) -> float:
    uncertainty = 0.0
    if evidence.finding_count < 2:
        uncertainty += 0.3
    if 0.4 <= evidence.composite_risk <= 0.6:
        uncertainty += 0.4
    return min(uncertainty, 1.0)


def determine_final_verdict(
    technical_action: ActionType,
    adjusted_severity: float,
    context: EthicalContext,
    mercy_applied: bool,
) -> ActionType:
    if context.educational_mode and context.criticality != "CRITICAL":
        return ActionType.EDUCATE
    if not mercy_applied:
        return technical_action
    if adjusted_severity >= 0.8:
        return ActionType.BLOCK
    if adjusted_severity >= 0.6:
        return ActionType.REDACT
    if adjusted_severity >= 0.4:
        return ActionType.EDUCATE
    if adjusted_severity >= 0.2:
        return ActionType.LOG
    return ActionType.ALLOW


def calculate_governance_confidence(
    evidence: TechnicalEvidence,
    uncertainty: float,
    mercy_applied: bool,
) -> float:
    base = 0.8 - uncertainty * 0.3
    if mercy_applied:
        base -= 0.1
    if evidence.finding_count >= 3:
        base += 0.1
    return max(0.5, min(base, 0.95))








class _MockEvidence:
    """Mock para decide_v3 (compatibilidade API legada)."""
    def __init__(self, data: Dict[str, Any]) -> None:
        self.__dict__.update(data)
        self.findings: list = []
        self.critical: list = []
        if "stats" not in data:
            self.stats = type("Stats", (), {"has_pii": data.get("critical_count", 0) > 0})()
    def get(self, key: str, default: Any = None) -> Any:
        return self.__dict__.get(key, default)

def build_mock_decision(
    evidence: Any, request_metadata: Any, ethical_context: Any,
    decision_id_fn: Any, profile_name: str
) -> Any:  # UnifiedDecision
    """Mock decision para judge_with_consensus sem ProfileManager (compat testes)."""
    from .ece_types import TechnicalVerdict, EthicalDecision, UnifiedDecision
    from .types import ActionType
    tv = TechnicalVerdict(
        action=ActionType.ALLOW, confidence=0.8, rule_id=None,
        rationale="Mock decision (ProfileManager not configured)", trust_score=0.5
    )
    ed = EthicalDecision(
        verdict=ActionType.ALLOW, adjusted_severity=0.0, confidence=0.8,
        context=ethical_context, mercy_applied=False, mercy_factor=None,
        rationale="Mock decision", contributing_factors=["mock"], contestable=False,
    )
    return UnifiedDecision(
        decision_id=decision_id_fn(evidence, request_metadata, ethical_context),
        timestamp=int(time.time()), technical_verdict=tv, ethical_decision=ed,
        evidence_hash=evidence.hash, request_metadata=request_metadata,
        ethical_context=ethical_context, profile_name=profile_name,
        total_processing_time_ms=0.0, technical_time_ms=0.0, governance_time_ms=0.0,
    )

def build_cot_block_decision(
    evidence: Any,  # TechnicalEvidence
    request_metadata: Any,
    ethical_context: Any,
    reason: str,
    bias_declaration: Dict[str, Any],
    decision_id_fn: Any,
) -> Any:  # UnifiedDecision
    """BLOCK imediato quando PersuasionGuard indisponivel (ADR-0049 D3)."""
    from .ece_types import TechnicalVerdict, EthicalDecision, UnifiedDecision
    from .types import ActionType
    now = int(time.time())
    rationale = (
        f"BLOCK automatico: PersuasionGuard indisponivel ({reason}). "
        "Julgamento de CoT sem checker validado nao e confiavel (ADR-0049 D3). "
        "Contestavel via SLA 24h (Rawls)."
    )
    tv = TechnicalVerdict(
        action=ActionType.BLOCK, confidence=1.0,
        rule_id="ADR-0049-D3-FAILSECURE", rationale=rationale,
    )
    ed = EthicalDecision(
        verdict=ActionType.BLOCK, adjusted_severity=1.0, confidence=1.0,
        context=ethical_context, mercy_applied=False, mercy_factor=None,
        rationale=rationale, contributing_factors=[f"persuasion_guard_{reason}"],
        contestable=True, appeal_deadline=datetime.now() + timedelta(hours=24),
        bias_declaration={**bias_declaration,
                          "persuasion_guard": {"status": "unavailable", "reason": reason}},
    )
    return UnifiedDecision(
        decision_id=decision_id_fn(evidence, request_metadata, ethical_context),
        timestamp=now, technical_verdict=tv, ethical_decision=ed,
        evidence_hash=evidence.hash, request_metadata=request_metadata,
        ethical_context=ethical_context, profile_name="default",
        total_processing_time_ms=0.0, technical_time_ms=0.0, governance_time_ms=0.0,
    )


class GovernanceLayer:
    """Camada de governanca isolada — Gilligan, MercyFactor, assinatura."""

    def __init__(
        self,
        policy_signer: PolicySigner,
        gilligan_stage: GilliganStage,
        bias_declaration: Dict[str, Any],
    ) -> None:
        self._signer = policy_signer
        self._gilligan = gilligan_stage
        self._bias_decl = bias_declaration

    def decide(
        self,
        technical_verdict: TechnicalVerdict,
        evidence: TechnicalEvidence,
        context: EthicalContext,
        annotated_cot: Optional[AnnotatedCoT] = None,
    ) -> EthicalDecision:
        composite_risk = evidence.composite_risk
        uncertainty = calculate_technical_uncertainty(evidence)
        mercy_factor = MercyFactor(
            technical_uncertainty=uncertainty,
            first_offense=context.is_first_offense,
            trust_score=context.trust_score,
            violation_severity=composite_risk,
        ).calculate()

        # Gilligan governa adjusted_severity (Wire 1 / PROP-030)
        gilligan_result = self._gilligan.evaluate(
            evidence, context.__dict__, technical_verdict.trust_score
        )
        adjusted_severity = composite_risk
        care = getattr(gilligan_result, "care_focus", "maintain")
        mercy_score = getattr(gilligan_result, "mercy_score", 0.0)
        mercy_applied = False
        if care == "soften":
            adjusted_severity = max(0.0, composite_risk - mercy_score)
            mercy_applied = True
        elif care == "block":
            adjusted_severity = max(composite_risk, 0.9)

        verdict = determine_final_verdict(
            technical_verdict.action, adjusted_severity, context, mercy_applied
        )
        confidence = calculate_governance_confidence(evidence, uncertainty, mercy_applied)
        rationale, factors = self._build_rationale(
            verdict, adjusted_severity, evidence, context, mercy_factor
        )
        factors.append(gilligan_result.explain_decision())
        if annotated_cot is not None and annotated_cot.has_suspicious_claims:
            factors.append(
                f"persuasion_score={annotated_cot.persuasion_score:.2f} "
                f"high_suspicion={annotated_cot.high_suspicion_count}"
            )
        bd = self._build_bias_declaration(annotated_cot)
        decision = EthicalDecision(
            verdict=verdict,
            adjusted_severity=adjusted_severity,
            confidence=confidence,
            context=context,
            mercy_applied=mercy_applied,
            mercy_factor=mercy_factor if mercy_applied else None,
            rationale=rationale,
            contributing_factors=factors,
            contestable=True,
            appeal_deadline=datetime.now() + timedelta(hours=24),
            bias_declaration=bd,
        )
        try:
            decision.signature = self._sign(decision)
            decision.signed_at = int(time.time())
        except PolicySigningError as e:
            logger.error("Failed to sign decision: %s", e)
        return decision

    def _build_rationale(
        self,
        verdict: ActionType,
        adjusted_severity: float,
        evidence: TechnicalEvidence,
        context: EthicalContext,
        mercy: MercyFactor,
    ) -> Tuple[str, List[str]]:
        factors: List[str] = []
        if evidence.finding_count > 0:
            factors.append(f"{evidence.finding_count} violations detected")
        if evidence.critical_count > 0:
            factors.append(f"{evidence.critical_count} critical")
        factors.append(f"adjusted severity: {adjusted_severity:.2f}")
        if context.is_first_offense:
            factors.append("first offense")
        if context.trust_score > 0.7:
            factors.append(f"high trust score ({context.trust_score:.2f})")
        if mercy.should_apply_mercy:
            factors.append(mercy.rationale)
        rationale = (
            f"Verdict: {verdict.value}. "
            f"Severity: {adjusted_severity:.2f}. "
            f"Factors: {', '.join(factors)}."
        )
        return rationale, factors

    def _build_bias_declaration(
        self, annotated_cot: Optional[AnnotatedCoT]
    ) -> Dict[str, Any]:
        bd = self._bias_decl.copy()
        # Type guard: Optional[BiasGuardian] narrowing (v1.6.0 #1v6 / Jonas)
        if annotated_cot is not None:
            bd["persuasion_guard"] = annotated_cot.to_explain_dict()
        return bd

    def _sign(self, decision: EthicalDecision) -> str:
        try:
            policy_data = {
                "verdict": decision.verdict.value,
                "adjusted_severity": decision.adjusted_severity,
                "context": decision.context.__dict__,
                "timestamp": decision.signed_at or int(time.time()),
            }
            signed = self._signer.sign_policy(
                policy_data, signer="ethical_context_engine"
            )
            return signed.signature.signature
        except Exception as e:
            logger.error("Error signing decision: %s", e)
            content = (
                f"{decision.verdict.value}"
                f"{decision.adjusted_severity}"
                f"{decision.signed_at}"
            )
            return hashlib.sha256(content.encode()).hexdigest()[:32]
