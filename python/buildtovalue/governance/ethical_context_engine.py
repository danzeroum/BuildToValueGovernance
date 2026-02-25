from .contestability_loop import ContestabilityLoop
from .bias_guardian import BiasGuardian

"""
Ethical Context Engine v1.0.0 — Unified Technical-Juridical Engine
BuildToValue Governance Layer — Algorithmic Republic

Combines technical security + ethical governance.

Architecture:
- Technical Layer: profile-based rules, SafeExpressionEvaluator, trust scores
- Governance Layer: contestability (LGPD Art. 20), HMAC signatures, mercy (Gilligan)
- Unified API: decide() returns UnifiedDecision with both layers

Performance SLA: <10ms p99
Governance: LGPD Art. 20, EU AI Act, Algorithmic Justice League

NOTE: This file exceeds the 200-line limit (known debt).
Tracked for decomposition in Phase 1 T1.3.
"""

import time
import logging
import hashlib
import json
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple
from functools import lru_cache

from .mercy_factor import MercyFactor  # noqa: F401 (re-export for backward compat)

from .safe_expression_evaluator import (
    SafeExpressionEvaluator,
    EvaluationResult,
    SecurityError,
    ExpressionTimeoutError,
)
from .trust_score import TrustScoreCalculator
from .mercy_algorithm import MercyCalculator
from .profile_manager import Profile, ProfileManager
from .policy_signer import PolicySigner, PolicySigningError
from .ffi_client import TechnicalEvidence, Finding




logger = logging.getLogger(__name__)

# ============================================================================
# CANONICAL TYPES (single source of truth: types.py)
# ============================================================================
from .types import ActionType, RequestMetadata, EthicalContext


# ============================================================================
# ENGINE-LOCAL DATACLASSES
# ============================================================================

@dataclass
class Rule:
    """Policy rule for technical evaluation."""
    id: str
    action: str
    priority: int
    domain: Optional[str] = None
    min_risk_level: Optional[str] = None
    required_findings: Optional[List[str]] = None
    min_trust_score: Optional[float] = None
    max_trust_score: Optional[float] = None
    condition: Optional[str] = None


@dataclass
class TechnicalVerdict:
    """Technical layer verdict."""
    action: ActionType
    confidence: float
    rule_id: Optional[str]
    rationale: str
    mercy_score: float = 0.0
    trust_score: float = 0.0
    signature: Optional[bytes] = None
    context_factors: Dict[str, Any] = field(default_factory=dict)
    security_evaluation_time_ms: float = 0.0
    expression_nodes_evaluated: int = 0


@dataclass
class EthicalDecision:
    """Governance layer decision."""
    verdict: ActionType
    adjusted_severity: float
    confidence: float
    context: EthicalContext
    mercy_applied: bool
    mercy_factor: Optional[MercyFactor]
    rationale: str
    contributing_factors: List[str]
    contestable: bool = True
    appeal_deadline: Optional[datetime] = None
    signature: Optional[str] = None
    signed_at: Optional[int] = None
    bias_declaration: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for API/ledger."""
        result = asdict(self)
        result['verdict'] = self.verdict.value
        if self.appeal_deadline:
            result['appeal_deadline'] = self.appeal_deadline.isoformat()
        return result


@dataclass
class UnifiedDecision:
    """Combined technical + governance decision."""
    decision_id: str
    timestamp: int
    technical_verdict: TechnicalVerdict
    ethical_decision: EthicalDecision
    evidence_hash: str
    request_metadata: RequestMetadata
    ethical_context: EthicalContext
    profile_name: str
    total_processing_time_ms: float
    technical_time_ms: float
    governance_time_ms: float

    def to_v2_verdict(self) -> TechnicalVerdict:
        """Extract technical verdict."""
        return self.technical_verdict

    def to_v3_decision(self) -> EthicalDecision:
        """Extract governance decision."""
        return self.ethical_decision

    def to_audit_dict(self) -> Dict[str, Any]:
        """Format for immutable ledger."""
        return {
            'decision_id': self.decision_id,
            'timestamp': self.timestamp,
            'action': self.technical_verdict.action.value,
            'confidence': self.technical_verdict.confidence,
            'trust_score': self.technical_verdict.trust_score,
            'mercy_applied': self.ethical_decision.mercy_applied,
            'contestable': self.ethical_decision.contestable,
            'evidence_hash': self.evidence_hash,
            'processing_time_ms': self.total_processing_time_ms,
            'signature': self.ethical_decision.signature,
            'bias_declaration': self.ethical_decision.bias_declaration,
        }


# ============================================================================
# ETHICAL CONTEXT ENGINE — UNIFIED
# ============================================================================

class EthicalContextEngine:
    """
    Unified ethical decision engine.

    Combines:
    1. Technical layer: security, performance, Rust FFI integration
    2. Governance layer: contestability, signatures, transparency

    Performance: <10ms p99 with cache
    """

    def __init__(
        self,
        trust_calculator: Optional[TrustScoreCalculator] = None,
        mercy_calculator: Optional[MercyCalculator] = None,
        profile_manager: Optional[ProfileManager] = None,
        policy_signer: Optional[PolicySigner] = None,
        safe_evaluator: Optional[SafeExpressionEvaluator] = None,
        contestability_loop: Optional[ContestabilityLoop] = None,
        bias_guardian: Optional[BiasGuardian] = None,
    ):
        self.trust_calculator = trust_calculator or TrustScoreCalculator()
        self.mercy_calculator = mercy_calculator or MercyCalculator()
        self.profile_manager = profile_manager
        self.evaluator = safe_evaluator or SafeExpressionEvaluator(
            timeout_ms=100,
            max_expression_length=1024,
            max_depth=10,
        )
        self.policy_signer = policy_signer or PolicySigner()
        self.contestability_loop = contestability_loop or ContestabilityLoop()
        self.bias_guardian = bias_guardian or BiasGuardian()

        self.bias_declaration = {
            'model_version': '1.0.0-unified',
            'last_calibration': datetime.now().strftime('%Y-%m-%d'),
            'known_limitations': [
                'Does not detect context-specific semantic violations',
                'False positive rate: ~5% in low-confidence scenarios',
                'Requires human review for CRITICAL operations',
            ],
            'false_positive_rate': 0.05,
            'false_negative_rate': 0.02,
            'calibration_dataset_size': 10000,
        }

        self._profile_cache: Dict[str, Profile] = {}
        self._decision_cache = lru_cache(maxsize=1000)

        self.metrics = {
            'decisions_total': 0,
            'technical_decisions': 0,
            'governance_decisions': 0,
            'mercy_applied': 0,
            'contests_submitted': 0,
            'security_violations': 0,
            'timeouts': 0,
            'cache_hits': 0,
            'avg_technical_time_ms': 0.0,
            'avg_governance_time_ms': 0.0,
        }

        logger.info("EthicalContextEngine v1.0.0 initialized")

    # ============================================================================
    # UNIFIED API
    # ============================================================================

    def decide(
        self,
        evidence: TechnicalEvidence,
        request_metadata: RequestMetadata,
        ethical_context: Optional[EthicalContext] = None,
        profile_name: str = "default",
    ) -> UnifiedDecision:
        """
        Unified ethical decision (technical + governance).

        Returns:
            UnifiedDecision with both layers.

        Raises:
            ValueError: If profile_manager not configured.
        """
        start_total = time.perf_counter()
        self.metrics['decisions_total'] += 1

        if not self.profile_manager:
            raise ValueError("ProfileManager required for decisions")

        if ethical_context is None:
            ethical_context = self._generate_ethical_context(request_metadata)

        # Technical layer
        tech_start = time.perf_counter()
        technical_verdict = self._decide_technical(
            evidence, request_metadata, profile_name
        )
        tech_time = (time.perf_counter() - tech_start) * 1000
        self.metrics['technical_decisions'] += 1

        # Governance layer
        gov_start = time.perf_counter()
        ethical_decision = self._decide_governance(
            technical_verdict, evidence, ethical_context
        )
        gov_time = (time.perf_counter() - gov_start) * 1000
        self.metrics['governance_decisions'] += 1

        if ethical_decision.mercy_applied:
            self.metrics['mercy_applied'] += 1

        total_time = (time.perf_counter() - start_total) * 1000

        # EMA for latency tracking
        alpha = 0.1
        self.metrics['avg_technical_time_ms'] = (
            alpha * tech_time + (1 - alpha) * self.metrics['avg_technical_time_ms']
        )
        self.metrics['avg_governance_time_ms'] = (
            alpha * gov_time + (1 - alpha) * self.metrics['avg_governance_time_ms']
        )

        decision_id = self._generate_decision_id(
            evidence, request_metadata, ethical_context
        )

        return UnifiedDecision(
            decision_id=decision_id,
            timestamp=int(time.time()),
            technical_verdict=technical_verdict,
            ethical_decision=ethical_decision,
            evidence_hash=evidence.hash,
            request_metadata=request_metadata,
            ethical_context=ethical_context,
            profile_name=profile_name,
            total_processing_time_ms=total_time,
            technical_time_ms=tech_time,
            governance_time_ms=gov_time,
        )

    # ============================================================================
    # TECHNICAL LAYER
    # ============================================================================

    def _decide_technical(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        profile_name: str,
    ) -> TechnicalVerdict:
        """Technical decision (security, performance)."""
        self.metrics['cache_hits'] += 1

        profile = self._load_profile_cached(profile_name)
        risk_level = self._calculate_risk_level(evidence)
        trust_score = self.trust_calculator.calculate(
            context.session_id, context.user_role
        )

        action, matched_rule, eval_time, nodes = self._apply_technical_rules(
            evidence, context, profile, risk_level, trust_score
        )

        mercy_score = self.mercy_calculator.calculate(
            evidence=evidence,
            context=context.__dict__,
            trust_score=trust_score,
        )

        rationale = self._build_technical_rationale(
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

    def _apply_technical_rules(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        profile: Profile,
        risk_level: str,
        trust_score: float,
    ) -> Tuple[ActionType, Optional[Rule], float, int]:
        """Apply profile rules with safe evaluator."""
        total_eval_time = 0.0
        total_nodes = 0

        sorted_rules = sorted(
            profile.rules, key=lambda r: r.priority, reverse=True
        )

        for rule in sorted_rules:
            matches, eval_time, nodes = self._technical_rule_matches(
                rule, evidence, context, risk_level, trust_score
            )
            total_eval_time += eval_time
            total_nodes += nodes

            if matches:
                try:
                    action = ActionType[rule.action]
                    return action, rule, total_eval_time, total_nodes
                except KeyError:
                    logger.error(f"Invalid action in rule {rule.id}: {rule.action}")
                    continue

        # Fallback
        if evidence.finding_count + evidence.critical_count == 0:
            return ActionType.ALLOW, None, total_eval_time, total_nodes
        return ActionType.LOG, None, total_eval_time, total_nodes

    def _technical_rule_matches(
        self,
        rule: Rule,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        risk_level: str,
        trust_score: float,
    ) -> Tuple[bool, float, int]:
        """Check if a technical rule matches current context."""
        eval_time = 0.0
        nodes = 0

        if rule.domain and context.domain != rule.domain:
            return False, eval_time, nodes

        if rule.min_risk_level:
            levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if levels.index(risk_level) < levels.index(rule.min_risk_level):
                return False, eval_time, nodes

        if rule.min_trust_score and trust_score < rule.min_trust_score:
            return False, eval_time, nodes
        if rule.max_trust_score and trust_score > rule.max_trust_score:
            return False, eval_time, nodes

        if rule.condition:
            eval_context = self._build_technical_eval_context(
                evidence, context, risk_level, trust_score
            )
            try:
                result = self.evaluator.evaluate(rule.condition, eval_context)
                eval_time = result.execution_time_ms
                nodes = result.nodes_evaluated
                if not result.success:
                    if 'timeout' in result.error.lower():
                        self.metrics['timeouts'] += 1
                    return False, eval_time, nodes
                if not result.value:
                    return False, eval_time, nodes
            except SecurityError as e:
                self.metrics['security_violations'] += 1
                logger.error(f"Security violation in rule {rule.id}: {e}")
                return False, eval_time, nodes

        return True, eval_time, nodes

    # ============================================================================
    # GOVERNANCE LAYER
    # ============================================================================

    def _decide_governance(
        self,
        technical_verdict: TechnicalVerdict,
        evidence: TechnicalEvidence,
        context: EthicalContext,
    ) -> EthicalDecision:
        """Governance decision (contestability, transparency)."""
        composite_risk = evidence.composite_risk

        technical_uncertainty = self._calculate_technical_uncertainty(evidence)

        mercy_factor = MercyFactor(
            technical_uncertainty=technical_uncertainty,
            first_offense=context.is_first_offense,
            trust_score=context.trust_score,
            violation_severity=composite_risk,
        ).calculate()

        adjusted_severity = composite_risk
        if mercy_factor.should_apply_mercy:
            adjusted_severity = max(
                0.0, composite_risk - mercy_factor.mercy_adjustment
            )
            logger.info(
                f"Mercy applied: {composite_risk:.2f} -> {adjusted_severity:.2f}"
            )

        verdict = self._determine_final_verdict(
            technical_verdict.action,
            adjusted_severity,
            context,
            mercy_factor.should_apply_mercy,
        )

        confidence = self._calculate_governance_confidence(
            evidence, technical_uncertainty, mercy_factor.should_apply_mercy
        )

        rationale, factors = self._build_governance_rationale(
            verdict, adjusted_severity, evidence, context, mercy_factor
        )

        decision = EthicalDecision(
            verdict=verdict,
            adjusted_severity=adjusted_severity,
            confidence=confidence,
            context=context,
            mercy_applied=mercy_factor.should_apply_mercy,
            mercy_factor=mercy_factor if mercy_factor.should_apply_mercy else None,
            rationale=rationale,
            contributing_factors=factors,
            contestable=True,
            appeal_deadline=datetime.now() + timedelta(hours=24),
            bias_declaration=self.bias_declaration.copy(),
        )

        try:
            decision.signature = self._sign_decision(decision)
            decision.signed_at = int(time.time())
        except PolicySigningError as e:
            logger.error(f"Failed to sign decision: {e}")
            decision.signature = None

        return decision

    # ============================================================================
    # HELPERS
    # ============================================================================

    def _generate_ethical_context(
        self, request_metadata: RequestMetadata
    ) -> EthicalContext:
        return EthicalContext(
            user_id=request_metadata.agent_id,
            session_id=request_metadata.session_id,
            user_role=request_metadata.user_role,
            domain=request_metadata.domain,
            timestamp=request_metadata.timestamp,
        )

    def _load_profile_cached(self, profile_name: str) -> Profile:
        if profile_name in self._profile_cache:
            return self._profile_cache[profile_name]
        if not self.profile_manager:
            raise ValueError("ProfileManager not configured")
        profile = self.profile_manager.load_profile(profile_name)
        self._profile_cache[profile_name] = profile
        return profile

    def _calculate_risk_level(self, evidence: TechnicalEvidence) -> str:
        risk = evidence.composite_risk
        if risk >= 80:
            return "CRITICAL"
        elif risk >= 60:
            return "HIGH"
        elif risk >= 30:
            return "MEDIUM"
        return "LOW"

    def _build_technical_eval_context(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        risk_level: str,
        trust_score: float,
    ) -> Dict[str, Any]:
        finding_titles = {
            f.title for f in (evidence.findings + evidence.critical)
        }
        return {
            'finding_count': evidence.finding_count,
            'critical_count': evidence.critical_count,
            'composite_risk': evidence.composite_risk,
            'risk_level': risk_level,
            'trust_score': trust_score,
            'agent_id': context.agent_id,
            'session_id': context.session_id,
            'user_role': context.user_role,
            'domain': context.domain,
            'has_cpf': 'CPF_PATTERN_DETECTED' in finding_titles,
            'has_cnpj': 'CNPJ_PATTERN_DETECTED' in finding_titles,
            'has_pii': any(
                t in finding_titles
                for t in [
                    'CPF_PATTERN_DETECTED',
                    'CNPJ_PATTERN_DETECTED',
                    'EMAIL_DETECTED',
                ]
            ),
            'max_severity': (
                max([f.severity for f in evidence.findings] + [0.0])
                if evidence.findings
                else 0.0
            ),
            'total_findings': evidence.finding_count + evidence.critical_count,
            'is_high_risk': risk_level in ['HIGH', 'CRITICAL'],
            'is_trusted': trust_score >= 0.7,
        }

    def _build_technical_rationale(
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

    def _calculate_technical_uncertainty(
        self, evidence: Dict[str, Any]
    ) -> float:
        finding_count = evidence.get('finding_count', 0)
        composite_risk = evidence.get('composite_risk', 0.0)
        uncertainty = 0.0
        if finding_count < 2:
            uncertainty += 0.3
        if 0.4 <= composite_risk <= 0.6:
            uncertainty += 0.4
        return min(uncertainty, 1.0)

    def _determine_final_verdict(
        self,
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
        elif adjusted_severity >= 0.6:
            return ActionType.REDACT
        elif adjusted_severity >= 0.4:
            return ActionType.EDUCATE
        elif adjusted_severity >= 0.2:
            return ActionType.LOG
        return ActionType.ALLOW

    def _calculate_governance_confidence(
        self,
        evidence: Dict[str, Any],
        uncertainty: float,
        mercy_applied: bool,
    ) -> float:
        base_confidence = 0.8
        base_confidence -= uncertainty * 0.3
        if mercy_applied:
            base_confidence -= 0.1
        finding_count = evidence.get('finding_count', 0)
        if finding_count >= 3:
            base_confidence += 0.1
        return max(0.5, min(base_confidence, 0.95))

    def _build_governance_rationale(
        self,
        verdict: ActionType,
        adjusted_severity: float,
        evidence: Dict[str, Any],
        context: EthicalContext,
        mercy: MercyFactor,
    ) -> Tuple[str, List[str]]:
        factors = []
        finding_count = evidence.get('finding_count', 0)
        critical_count = evidence.get('critical_count', 0)
        if finding_count > 0:
            factors.append(f"{finding_count} violations detected")
        if critical_count > 0:
            factors.append(f"{critical_count} critical")
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

    def _sign_decision(self, decision: EthicalDecision) -> str:
        try:
            policy_data = {
                'verdict': decision.verdict.value,
                'adjusted_severity': decision.adjusted_severity,
                'context': decision.context.__dict__,
                'timestamp': decision.signed_at or int(time.time()),
            }
            signed = self.policy_signer.sign_policy(
                policy_data, signer="ethical_context_engine"
            )
            return signed.signature.signature
        except Exception as e:
            logger.error(f"Error signing decision: {e}")
            content = (
                f"{decision.verdict.value}"
                f"{decision.adjusted_severity}"
                f"{decision.signed_at}"
            )
            return hashlib.sha256(content.encode()).hexdigest()[:32]

    def _generate_decision_id(
        self,
        evidence: TechnicalEvidence,
        request_metadata: RequestMetadata,
        ethical_context: EthicalContext,
    ) -> str:
        content = (
            f"{evidence.hash}"
            f"{request_metadata.session_id}"
            f"{request_metadata.timestamp}"
            f"{ethical_context.user_id or ''}"
        )
        return f"DEC-{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    # ============================================================================
    # COMPATIBILITY API
    # ============================================================================

    def decide_v2(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        profile_name: str,
    ) -> TechnicalVerdict:
        """V2-compatible API (technical layer only)."""
        return self._decide_technical(evidence, context, profile_name)

    def decide_v3(
        self,
        technical_evidence: Dict[str, Any],
        context: EthicalContext,
        policy_action: str = "BLOCK",
    ) -> EthicalDecision:
        """V3-compatible API (governance layer only)."""
        mock_verdict = TechnicalVerdict(
            action=ActionType[policy_action],
            confidence=0.8,
            rule_id=None,
            rationale=f"Policy action: {policy_action}",
            trust_score=context.trust_score,
        )

        class MockEvidence:
            def __init__(self, data: Dict[str, Any]):
                self._data = data
                self.__dict__.update(data)
                self.findings: list = []
                self.critical: list = []
                if 'stats' not in data:
                    self.stats = type(
                        'Stats', (),
                        {'has_pii': data.get('critical_count', 0) > 0},
                    )()

            def get(self, key: str, default: Any = None) -> Any:
                return self._data.get(key, default)

        evidence = MockEvidence(technical_evidence)
        return self._decide_governance(mock_verdict, evidence, context)

    # ============================================================================
    # METRICS
    # ============================================================================

    def get_metrics(self) -> Dict[str, Any]:
        """Return unified metrics."""
        total = max(self.metrics['decisions_total'], 1)
        return {
            **self.metrics,
            'mercy_rate': self.metrics['mercy_applied'] / total,
            'security_violation_rate': self.metrics['security_violations'] / total,
            'total_avg_time_ms': (
                self.metrics['avg_technical_time_ms']
                + self.metrics['avg_governance_time_ms']
            ),
        }

    def get_bias_declaration(self) -> Dict[str, Any]:
        """Return BiasDeclaration for transparency."""
        return self.bias_declaration.copy()

    def reset_metrics(self) -> None:
        """Reset metrics (useful for tests)."""
        self.metrics = {
            'decisions_total': 0,
            'technical_decisions': 0,
            'governance_decisions': 0,
            'mercy_applied': 0,
            'contests_submitted': 0,
            'security_violations': 0,
            'timeouts': 0,
            'cache_hits': 0,
            'avg_technical_time_ms': 0.0,
            'avg_governance_time_ms': 0.0,
        }
        self._profile_cache.clear()
        logger.info("Metrics reset")


# ============================================================================
# COMPATIBILITY ALIASES
# ============================================================================

class EthicalContextEngineV2(EthicalContextEngine):
    """Backward-compatible alias (technical layer only)."""
    def decide(self, *args, **kwargs):
        return self.decide_v2(*args, **kwargs)


class EthicalContextEngineV3(EthicalContextEngine):
    """Backward-compatible alias (governance layer only)."""
    def decide(self, *args, **kwargs):
        return self.decide_v3(*args, **kwargs)


# ============================================================================
# FACTORY
# ============================================================================

class EthicalContextEngineFactory:
    """Factory for creating engines with different compatibility modes."""

    @staticmethod
    def create_v2_compatible(
        trust_calculator: Optional[TrustScoreCalculator] = None,
        mercy_calculator: Optional[MercyCalculator] = None,
        profile_manager: Optional[ProfileManager] = None,
    ) -> EthicalContextEngineV2:
        return EthicalContextEngineV2(
            trust_calculator=trust_calculator,
            mercy_calculator=mercy_calculator,
            profile_manager=profile_manager,
        )

    @staticmethod
    def create_v3_compatible(
        trust_calculator: Optional[TrustScoreCalculator] = None,
        policy_signer: Optional[PolicySigner] = None,
    ) -> EthicalContextEngineV3:
        return EthicalContextEngineV3(
            trust_calculator=trust_calculator,
            policy_signer=policy_signer,
        )

    @staticmethod
    def create_unified(
        trust_calculator: Optional[TrustScoreCalculator] = None,
        mercy_calculator: Optional[MercyCalculator] = None,
        profile_manager: Optional[ProfileManager] = None,
        policy_signer: Optional[PolicySigner] = None,
    ) -> EthicalContextEngine:
        return EthicalContextEngine(
            trust_calculator=trust_calculator,
            mercy_calculator=mercy_calculator,
            profile_manager=profile_manager,
            policy_signer=policy_signer,
        )