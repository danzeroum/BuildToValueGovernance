"""
ece_technical.py — Camada Tecnica do EthicalContextEngine (T1.3 / v1.6.0)

Responsabilidade unica: regras de perfil, SafeExpressionEvaluator,
risk_level, trust_score, TechnicalVerdict.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional, Tuple

from .ece_types import Rule, TechnicalVerdict
from .types import ActionType, RequestMetadata
from .ffi_client import TechnicalEvidence
from .safe_expression_evaluator import SafeExpressionEvaluator, SecurityError
from .trust_score import TrustScoreCalculator
from .mercy_algorithm import MercyCalculator
from .profile_manager import Profile, ProfileManager

logger = logging.getLogger(__name__)

_RISK_THRESHOLDS = (
    (80.0, "CRITICAL"),
    (60.0, "HIGH"),
    (30.0, "MEDIUM"),
)


def calculate_risk_level(composite_risk: float) -> str:
    for threshold, level in _RISK_THRESHOLDS:
        if composite_risk >= threshold:
            return level
    return "LOW"


def build_technical_eval_context(
    evidence: TechnicalEvidence,
    context: RequestMetadata,
    risk_level: str,
    trust_score: float,
) -> Dict[str, Any]:
    finding_titles = {f.title for f in (evidence.findings + evidence.critical)}
    pii_titles = {"CPF_PATTERN_DETECTED", "CNPJ_PATTERN_DETECTED", "EMAIL_DETECTED"}
    return {
        "finding_count": evidence.finding_count,
        "critical_count": evidence.critical_count,
        "composite_risk": evidence.composite_risk,
        "risk_level": risk_level,
        "trust_score": trust_score,
        "agent_id": context.agent_id,
        "session_id": context.session_id,
        "user_role": context.user_role,
        "domain": context.domain,
        "has_cpf": "CPF_PATTERN_DETECTED" in finding_titles,
        "has_cnpj": "CNPJ_PATTERN_DETECTED" in finding_titles,
        "has_pii": bool(finding_titles & pii_titles),
        "max_severity": (
            max((f.severity for f in evidence.findings), default=0.0)
        ),
        "total_findings": evidence.finding_count + evidence.critical_count,
        "is_high_risk": risk_level in ("HIGH", "CRITICAL"),
        "is_trusted": trust_score >= 0.7,
    }


class TechnicalLayer:
    """Camada tecnica isolada — regras, SafeEvaluator, TrustScore."""

    def __init__(
        self,
        trust_calculator: TrustScoreCalculator,
        mercy_calculator: MercyCalculator,
        evaluator: SafeExpressionEvaluator,
        metrics: Dict[str, Any],
        profile_cache: Dict[str, Profile],
        profile_manager: Optional[ProfileManager],
    ) -> None:
        self._trust = trust_calculator
        self._mercy = mercy_calculator
        self._eval = evaluator
        self._metrics = metrics
        self._cache = profile_cache
        self._pm = profile_manager

    def decide(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        profile_name: str,
    ) -> TechnicalVerdict:
        self._metrics["cache_hits"] += 1
        profile = self._load_profile(profile_name)
        risk_level = calculate_risk_level(evidence.composite_risk)
        trust_score = self._trust.calculate(context.session_id, context.user_role)
        action, matched_rule, eval_time, nodes = self._apply_rules(
            evidence, context, profile, risk_level, trust_score
        )
        mercy_score = self._mercy.calculate(
            evidence=evidence, context=context.__dict__, trust_score=trust_score
        )
        rationale = self._build_rationale(
            evidence, context, matched_rule, mercy_score, trust_score, risk_level
        )
        return TechnicalVerdict(
            action=action,
            confidence=0.95 if matched_rule else 0.5,
            rule_id=matched_rule.id if matched_rule else None,
            rationale=rationale,
            mercy_score=mercy_score,
            trust_score=trust_score,
            context_factors={
                "risk_level": risk_level,
                "finding_count": evidence.finding_count,
                "critical_count": evidence.critical_count,
                "domain": context.domain,
            },
            security_evaluation_time_ms=eval_time,
            expression_nodes_evaluated=nodes,
        )

    def _load_profile(self, profile_name: str) -> Profile:
        if profile_name in self._cache:
            return self._cache[profile_name]
        if not self._pm:
            raise ValueError("ProfileManager not configured")
        profile = self._pm.load_profile(profile_name)
        self._cache[profile_name] = profile
        return profile

    def _apply_rules(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        profile: Profile,
        risk_level: str,
        trust_score: float,
    ) -> Tuple[ActionType, Optional[Rule], float, int]:
        total_eval_time = 0.0
        total_nodes = 0
        for rule in sorted(profile.rules, key=lambda r: r.priority, reverse=True):
            matches, et, n = self._rule_matches(
                rule, evidence, context, risk_level, trust_score
            )
            total_eval_time += et
            total_nodes += n
            if matches:
                try:
                    return ActionType[rule.action], rule, total_eval_time, total_nodes
                except KeyError:
                    logger.error("Invalid action in rule %s: %s", rule.id, rule.action)
        if evidence.finding_count + evidence.critical_count == 0:
            return ActionType.ALLOW, None, total_eval_time, total_nodes
        return ActionType.LOG, None, total_eval_time, total_nodes

    def _rule_matches(
        self,
        rule: Rule,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        risk_level: str,
        trust_score: float,
    ) -> Tuple[bool, float, int]:
        levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if rule.domain and context.domain != rule.domain:
            return False, 0.0, 0
        if rule.min_risk_level:
            if levels.index(risk_level) < levels.index(rule.min_risk_level):
                return False, 0.0, 0
        if rule.min_trust_score and trust_score < rule.min_trust_score:
            return False, 0.0, 0
        if rule.max_trust_score and trust_score > rule.max_trust_score:
            return False, 0.0, 0
        if not rule.condition:
            return True, 0.0, 0
        eval_ctx = build_technical_eval_context(evidence, context, risk_level, trust_score)
        try:
            result = self._eval.evaluate(rule.condition, eval_ctx)
            if not result.success:
                if "timeout" in (result.error or "").lower():
                    self._metrics["timeouts"] += 1
                return False, result.execution_time_ms, result.nodes_evaluated
            return bool(result.value), result.execution_time_ms, result.nodes_evaluated
        except SecurityError as e:
            self._metrics["security_violations"] += 1
            logger.error("Security violation in rule %s: %s", rule.id, e)
            return False, 0.0, 0

    def _build_rationale(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        rule: Optional[Rule],
        mercy_score: float,
        trust_score: float,
        risk_level: str,
    ) -> str:
        parts = []
        if evidence.finding_count > 0:
            parts.append(
                f"Detected {evidence.finding_count} findings "
                f"({evidence.critical_count} critical)"
            )
        if rule:
            parts.append(f"Rule applied: {rule.id}")
        parts.append(f"Risk level: {risk_level}")
        parts.append(f"Trust score: {trust_score:.2f}")
        if mercy_score > 0.5:
            parts.append(f"Technical mercy: {mercy_score:.2f}")
        return ". ".join(parts) + "."
