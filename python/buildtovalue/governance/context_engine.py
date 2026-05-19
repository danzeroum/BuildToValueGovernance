"""
EthicalContextEngine v1.9.1 — Judiciary of the Algorithmic Republic.

Orchestrates: MercyCalculator → MercyScenarios → TrustScore → HMAC signing → explain_decision()

Pipeline:
  1. Receive TechnicalEvidence (from Rust) + RequestContext
  2. Calculate trust score
  3. Calculate mercy score (MercyCalculator)
  4. Apply mercy scenarios (6 calibrated)
  5. REPORT override (ADR-043)
  6. Build EthicalVerdict (signed HMAC-SHA256)
  7. explain_decision() (obrigatório — Levinas)

Filosofia: Rawls (blind eval) · Gilligan (mercy) · Levinas (explain) · Jonas (HMAC)

Decomposição T1.3 (DT-005):
  context_engine_types.py   — RequestContext, RustEvidence, EthicalVerdict
  context_engine_explain.py — dp_noise, explain_decision
  context_engine.py         — EthicalContextEngine (orquestrador puro, ~160 linhas)
"""
from __future__ import annotations

import hmac
import hashlib
import logging
import time
from typing import Any, Callable, Dict, Optional, TYPE_CHECKING

from .mercy_algorithm import MercyCalculator
from .mercy_scenarios import evaluate_scenarios, ACTION_SEVERITY, SEVERITY_ACTION
from .context_engine_types import RequestContext, RustEvidence, EthicalVerdict
from .context_engine_explain import explain_decision

if TYPE_CHECKING:
    from .policy_engine import PolicyEngine

logger = logging.getLogger("btv.governance.context_engine")

# Re-exports para backward compat: importadores que fazem
# `from .context_engine import RequestContext` continuam funcionando.
__all__ = [
    "EthicalContextEngine",
    "RequestContext",
    "RustEvidence",
    "EthicalVerdict",
]


class EthicalContextEngine:
    """
    Judiciary of the Algorithmic Republic.

    Invariantes:
    - Todo veredicto tem explain_decision() (Levinas)
    - Todo veredicto é assinado HMAC-SHA256 (Jonas)
    - Todo veredicto é contestável SLA 24h (ADR-017)
    - Mercy NUNCA escala severidade (Gilligan)
    """

    def __init__(
        self,
        signing_key: Optional[bytes] = None,
        policy_engine: "Optional[PolicyEngine]" = None,
        signing_key_fn: Optional[Callable[[], bytes]] = None,
    ) -> None:
        if signing_key_fn is not None:
            self._signing_key_fn: Callable[[], bytes] = signing_key_fn
        elif signing_key is not None:
            if len(signing_key) < 32:
                raise ValueError("Signing key must be >= 32 bytes")
            _captured = signing_key
            self._signing_key_fn = lambda: _captured
        else:
            raise ValueError("Provide signing_key or signing_key_fn")
        self._mercy_calc = MercyCalculator()
        self._trust_scores: Dict[str, float] = {}
        self._violation_counts: Dict[str, int] = {}
        self._verdict_counter = 0
        self._policy_engine: "Optional[PolicyEngine]" = policy_engine
        # ADR-043: threshold lido do PolicyEngine (YAML) se fornecido; fallback 0.65
        self.report_threshold: float = (
            policy_engine.report_threshold if policy_engine is not None else 0.65
        )

    def set_trust_score(self, session_id: str, score: float) -> None:
        """Set trust score externally (from TrustScoreCalculator)."""
        self._trust_scores[session_id] = max(0.0, min(1.0, score))

    def decide(
        self,
        evidence: RustEvidence,
        context: RequestContext,
        external_verdict_id: Optional[str] = None,
        slm_justifiability: Optional[float] = None,
    ) -> EthicalVerdict:
        """Main entry point. Produces signed, explainable verdict."""
        now = int(time.time())
        self._verdict_counter += 1
        verdict_id = external_verdict_id or f"VRD-{now}-{self._verdict_counter:06d}"

        trust = self._trust_scores.get(context.session_id, 0.5)
        violation_count = self._violation_counts.get(context.session_id, 0)
        is_first = violation_count == 0
        if evidence.policy_action in ("BLOCK", "REDACT", "EDUCATE"):
            self._violation_counts[context.session_id] = violation_count + 1

        mercy_score = self._mercy_calc.calculate(
            evidence=self._to_ffi_evidence(evidence),
            context={
                "domain": context.domain,
                "session_id": context.session_id,
                "user_role": context.user_role,
            },
            trust_score=trust,
            slm_justifiability=slm_justifiability,
        )
        scenario_result = evaluate_scenarios(
            action=evidence.policy_action,
            mercy_score=mercy_score,
            trust_score=trust,
            finding_count=evidence.finding_count,
            critical_count=evidence.critical_count,
            composite_risk=evidence.composite_risk,
            domain=context.domain,
            is_first_offense=is_first,
        )
        final_action = self._apply_risk_overrides(scenario_result.final_action, context)

        # ADR-043: REPORT override — não altera output, apenas registra
        report_triggered = False
        if (
            final_action == "ALLOW"
            and evidence.composite_risk >= self.report_threshold
            and evidence.finding_count > 0
        ):
            final_action = "REPORT"
            report_triggered = True
            logger.info(
                "REPORT emitido: risk=%.3f >= threshold=%.3f, findings=%d, session=%s",
                evidence.composite_risk, self.report_threshold,
                evidence.finding_count, context.session_id,
            )

        explanation = explain_decision(
            evidence, context, trust, mercy_score,
            scenario_result, final_action, self.report_threshold,
        )
        sign_payload = (
            f"{verdict_id}|{evidence.blake3_hash}|{final_action}|{now}"
        )
        signature = hmac.new(
            self._signing_key_fn(), sign_payload.encode(), hashlib.sha256
        ).hexdigest()

        return EthicalVerdict(
            verdict_id=verdict_id,
            timestamp=now,
            original_action=evidence.policy_action,
            final_action=final_action,
            mercy_applied=scenario_result.mercy_applied,
            mercy_scenario=scenario_result.scenario_id,
            mercy_score=mercy_score,
            trust_score=trust,
            explanation=explanation,
            hmac_signature=signature,
            blake3_hash=evidence.blake3_hash,
            report_triggered=report_triggered,
        )

    def verify_signature(self, verdict: EthicalVerdict) -> bool:
        """Recompute the signed payload and compare with constant-time HMAC.

        The verdict carries blake3_hash (the original evidence binding) so that
        verification needs only the ledger record and the current HMAC key.
        A forged verdict (e.g. BLOCK → ALLOW) cannot match a real signature
        without the signing key.
        """
        if len(verdict.hmac_signature) != 64:
            return False
        if not verdict.blake3_hash:
            # Pre-binding verdicts cannot be verified — treat as unverifiable.
            return False
        sign_payload = (
            f"{verdict.verdict_id}|{verdict.blake3_hash}|"
            f"{verdict.final_action}|{verdict.timestamp}"
        )
        expected = hmac.new(
            self._signing_key_fn(), sign_payload.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, verdict.hmac_signature)

    def _apply_risk_overrides(self, action: str, ctx: RequestContext) -> str:
        """Escalate se ip_risk ou drift forem perigosos (nunca acima do original)."""
        severity = ACTION_SEVERITY.get(action, 0)
        if ctx.ip_risk == "Critical" and severity < ACTION_SEVERITY["BLOCK"]:
            severity = min(severity + 2, ACTION_SEVERITY["BLOCK"])
        elif ctx.ip_risk == "High" and severity < ACTION_SEVERITY["REDACT"]:
            severity = min(severity + 1, ACTION_SEVERITY["REDACT"])
        if ctx.drift_level in ("High", "Critical") and severity < ACTION_SEVERITY["REDACT"]:
            severity = min(severity + 1, ACTION_SEVERITY["REDACT"])
        return SEVERITY_ACTION.get(severity, "BLOCK")

    def _to_ffi_evidence(self, evidence: RustEvidence) -> Any:
        """Adapt RustEvidence to MercyCalculator's expected format."""
        from .types import SimpleTechnicalEvidence
        return SimpleTechnicalEvidence(
            composite_risk=evidence.composite_risk,
            finding_count=evidence.finding_count,
            critical_count=evidence.critical_count,
            entropy=evidence.entropy,
            total_chars=evidence.total_chars,
            findings=evidence.findings_summary,
        )
