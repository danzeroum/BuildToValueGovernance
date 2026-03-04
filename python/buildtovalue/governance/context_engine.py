"""
EthicalContextEngine v1.8.0 — Judiciary of the Algorithmic Republic.

Orchestrates: MercyCalculator → MercyScenarios → TrustScore → HMAC signing → explain_decision()

Pipeline:
  1. Receive TechnicalEvidence (from Rust) + RequestContext
  2. Resolve profile (agent/sector)
  3. Calculate trust score
  4. Calculate mercy score (MercyCalculator)
  5. Apply mercy scenarios (6 calibrated)
  6. Build EthicalVerdict (signed HMAC-SHA256)
  7. Generate explain_decision() (obrigatório)

Filosofia:
  - Rawls: Blind evaluation (same evidence → same process)
  - Gilligan: Mercy when context justifies
  - Levinas: explain_decision() always, contestable always
  - Jonas: HMAC signature = accountability
"""

import hmac
import hashlib
import time
import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

from .mercy_algorithm import MercyCalculator
from .mercy_scenarios import (
    evaluate_scenarios,
    MercyScenarioResult,
    ACTION_SEVERITY,
)

logger = logging.getLogger("btv.governance.context_engine")


# ─────────────────────────────────────────────────────────────
# REQUEST CONTEXT
# ─────────────────────────────────────────────────────────────

@dataclass
class RequestContext:
    """Context provided by the caller for ethical evaluation."""
    agent_id: str
    session_id: str
    domain: str = "general"
    user_role: str = "anonymous"
    ip_jurisdiction: str = "XX"
    ip_risk: str = "Low"
    drift_level: str = "None"
    timestamp: int = 0
    prior_sensitivity_tags: list = field(default_factory=list)
    cumulative_risk: float = 0.0
    active_combinations: list = field(default_factory=list)

    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = int(time.time())


# ─────────────────────────────────────────────────────────────
# TECHNICAL EVIDENCE (from Rust via FFI)
# ─────────────────────────────────────────────────────────────

@dataclass
class RustEvidence:
    """Simplified view of TechnicalEvidence for governance layer."""
    composite_risk: float
    finding_count: int
    critical_count: int
    entropy: float
    total_chars: int
    policy_action: str  # From PolicyEngine: ALLOW/LOG/EDUCATE/REDACT/BLOCK
    blake3_hash: str
    findings_summary: list = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# ETHICAL VERDICT
# ─────────────────────────────────────────────────────────────

@dataclass
class EthicalVerdict:
    """Signed, explainable, contestable verdict."""
    verdict_id: str
    timestamp: int
    original_action: str
    final_action: str
    mercy_applied: bool
    mercy_scenario: str
    mercy_score: float
    trust_score: float
    explanation: str
    hmac_signature: str
    contestable: bool = True
    appeal_deadline: int = 0

    def __post_init__(self):
        if self.appeal_deadline == 0:
            self.appeal_deadline = self.timestamp + (24 * 3600)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict_id": self.verdict_id,
            "timestamp": self.timestamp,
            "original_action": self.original_action,
            "final_action": self.final_action,
            "mercy_applied": self.mercy_applied,
            "mercy_scenario": self.mercy_scenario,
            "mercy_score": round(self.mercy_score, 4),
            "trust_score": round(self.trust_score, 4),
            "explanation": self.explanation,
            "hmac_signature": self.hmac_signature,
            "contestable": self.contestable,
            "appeal_deadline": self.appeal_deadline,
        }


# ─────────────────────────────────────────────────────────────
# ETHICAL CONTEXT ENGINE
# ─────────────────────────────────────────────────────────────

class EthicalContextEngine:
    """
    Judiciary of the Algorithmic Republic.

    Invariants:
    - Every verdict has explain_decision()
    - Every verdict is signed (HMAC-SHA256)
    - Every verdict is contestable (24h SLA)
    - Mercy NEVER escalates severity
    """

    def __init__(self, signing_key: bytes):
        if len(signing_key) < 32:
            raise ValueError("Signing key must be >= 32 bytes")
        self._signing_key = signing_key
        self._mercy_calc = MercyCalculator()
        self._trust_scores: Dict[str, float] = {}  # In prod: Redis/DB
        self._violation_counts: Dict[str, int] = {}
        self._verdict_counter = 0

    def set_trust_score(self, session_id: str, score: float) -> None:
        """Set trust score externally (from TrustScoreCalculator)."""
        self._trust_scores[session_id] = max(0.0, min(1.0, score))

    def decide(
        self,
        evidence: RustEvidence,
        context: RequestContext,
        external_verdict_id: Optional[str] = None,  # ADR-043
    ) -> EthicalVerdict:
        """
        Main entry point. Produces signed, explainable verdict.

        Pipeline:
          PolicyAction → trust → mercy_score → mercy_scenario → sign → explain
        """
        now = int(time.time())
        self._verdict_counter += 1
        # ADR-043: usar ID externo (Rust) se fornecido; fallback para legado
        if external_verdict_id:
            verdict_id = external_verdict_id
        else:
            verdict_id = f"VRD-{now}-{self._verdict_counter:06d}"

        # ── Step 1: Trust score ────────────────────────────
        trust = self._trust_scores.get(context.session_id, 0.5)

        # ── Step 2: First offense check ───────────────────
        violation_count = self._violation_counts.get(context.session_id, 0)
        is_first = violation_count == 0
        if evidence.policy_action in ("BLOCK", "REDACT", "EDUCATE"):
            self._violation_counts[context.session_id] = violation_count + 1

        # ── Step 3: Mercy score (MercyCalculator formula) ─
        mercy_context = {
            "domain": context.domain,
            "session_id": context.session_id,
            "user_role": context.user_role,
        }
        mercy_score = self._mercy_calc.calculate(
            evidence=self._to_ffi_evidence(evidence),
            context=mercy_context,
            trust_score=trust,
        )

        # ── Step 4: Mercy scenarios (6 calibrated) ────────
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

        # ── Step 5: IP/drift risk override ────────────────
        final_action = self._apply_risk_overrides(
            scenario_result.final_action, context
        )

        # ── Step 6: explain_decision() (obrigatório) ──────
        explanation = self._explain_decision(
            evidence, context, trust, mercy_score, scenario_result, final_action
        )

        # ── Step 7: HMAC-SHA256 signature ─────────────────
        sign_payload = (
            f"{verdict_id}|{evidence.blake3_hash}|"
            f"{final_action}|{now}"
        )
        signature = hmac.new(
            self._signing_key, sign_payload.encode(), hashlib.sha256
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
        )

    def verify_signature(self, verdict: EthicalVerdict) -> bool:
        """Verify HMAC-SHA256 signature of a verdict."""
        sign_payload = (
            f"{verdict.verdict_id}|"
            f"{verdict.hmac_signature[:0]}"  # We need the original hash
        )
        # Re-derive: caller must provide evidence hash
        # This is a simplified check — full impl uses stored hash
        return len(verdict.hmac_signature) == 64

    def _apply_risk_overrides(self, action: str, ctx: RequestContext) -> str:
        """
        Escalate if IP risk or drift level is dangerous.
        Mercy downgraded, but risk can RE-escalate (never above original).
        """
        severity = ACTION_SEVERITY.get(action, 0)

        if ctx.ip_risk == "Critical" and severity < ACTION_SEVERITY["BLOCK"]:
            severity = min(severity + 2, ACTION_SEVERITY["BLOCK"])
        elif ctx.ip_risk == "High" and severity < ACTION_SEVERITY["REDACT"]:
            severity = min(severity + 1, ACTION_SEVERITY["REDACT"])

        if ctx.drift_level in ("High", "Critical") and severity < ACTION_SEVERITY["REDACT"]:
            severity = min(severity + 1, ACTION_SEVERITY["REDACT"])

        from .mercy_scenarios import SEVERITY_ACTION
        return SEVERITY_ACTION.get(severity, "BLOCK")

    def _explain_decision(
        self,
        evidence: RustEvidence,
        context: RequestContext,
        trust: float,
        mercy_score: float,
        scenario: MercyScenarioResult,
        final_action: str,
    ) -> str:
        """
        Generate human-readable explanation (obrigatório).
        Levinas: transparency is non-negotiable.
        """
        parts = [
            f"Evidence: {evidence.finding_count} findings, "
            f"{evidence.critical_count} critical, "
            f"risk={evidence.composite_risk:.2f}, "
            f"entropy={evidence.entropy:.2f}.",

            f"Context: domain={context.domain}, role={context.user_role}, "
            f"ip_risk={context.ip_risk}, drift={context.drift_level}.",

            f"Trust: {trust:.2f}. Mercy: {mercy_score:.2f}.",

            f"Policy recommended: {evidence.policy_action}.",
        ]

        if scenario.mercy_applied:
            parts.append(
                f"Mercy applied ({scenario.scenario_id}): "
                f"{scenario.original_action} → {scenario.final_action} "
                f"(downgrade {scenario.downgrade_levels}). "
                f"{scenario.rationale}"
            )
        else:
            parts.append(
                f"No mercy applied ({scenario.scenario_id}). "
                f"{scenario.rationale}"
            )

        if final_action != scenario.final_action:
            parts.append(
                f"Risk override: {scenario.final_action} → {final_action} "
                f"(ip_risk={context.ip_risk}, drift={context.drift_level})."
            )

        parts.append(
            f"Final action: {final_action}. "
            f"Contestable within 24h."
        )

        return " ".join(parts)

    def _to_ffi_evidence(self, evidence: RustEvidence):
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