"""
BuildToValue Grant Decision Adapter — Custom Exceptions

Defines domain-specific exceptions for the grant governance pipeline.
All exceptions preserve the full Verdict context so that upstream callers
(e.g. Gitcoin Round Manager) can surface contestability information
to applicants without re-querying the BTV kernel.

Reference: BTV SDK — Verdict model (sdk/python/buildtovalue/models.py)
           Levinas SLA principle: every blocked entity MUST know if
           they can appeal and within what timeframe.
"""

from __future__ import annotations

from typing import Optional


class GrantValidationError(ValueError):
    """Raised when a GrantProposal fails structural validation.

    Distinct from GrantBlockedError: this exception indicates the proposal
    is malformed (missing required fields, invalid values) before it even
    reaches the BTV kernel. No verdict is produced.

    Attributes:
        field: The field that failed validation.
        reason: Human-readable description of why validation failed.
    """

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"[BTV GRANT VALIDATION] field='{field}' reason='{reason}'")


class GrantBlockedError(Exception):
    """Raised when a grant proposal is blocked by the BTV governance pipeline.

    This exception captures the full Verdict context required for the
    applicant-facing response, including contestability status and the
    appeal deadline (Levinas SLA principle from the BTV separation of powers).

    Attributes:
        verdict_id: Unique ULID identifier of the verdict (VRD-[0-9A-HJKMNP-TV-Z]{26}).
        action: The governance action taken — typically 'BLOCK', but may also be
                'REDACT' or 'EDUCATE' depending on policy configuration.
        rationale: Human-readable rationale from the BTV explain module,
                   combining Rawls + Levinas + Jonas + Gilligan stages.
        contestable: Whether the applicant can file an appeal via /v1/appeals.
                     Determined by Levinas stage; False if hard_blocked is True
                     (hard blocks bypass the appeals pathway per BTV fail-secure design).
        appeal_deadline_hours: Hours remaining to file an appeal. Only meaningful
                               when contestable is True. Derived from the Levinas
                               SLA timer configured in the policy YAML.
        composite_risk: Aggregate risk score (0.0-1.0) from the BTV pipeline.
                        Useful for upstream systems to prioritize review queues.
        trust_score: Post-pipeline trust score reflecting Jonas calibration
                     and Gilligan mercy evaluation.
        mercy_applied: Whether Gilligan's mercy algorithm intervened (e.g.
                       BLOCK -> EDUCATE). Relevant for auditing and transparency.
        raw_verdict: Optional reference to the original Verdict object for
                     advanced consumers that need full explain.* fields.
    """

    def __init__(
        self,
        verdict_id: str,
        action: str,
        rationale: str,
        contestable: bool,
        appeal_deadline_hours: int,
        composite_risk: Optional[float] = None,
        trust_score: Optional[float] = None,
        mercy_applied: Optional[bool] = None,
        raw_verdict: Optional[object] = None,
    ) -> None:
        self.verdict_id = verdict_id
        self.action = action
        self.rationale = rationale
        self.contestable = contestable
        self.appeal_deadline_hours = appeal_deadline_hours
        self.composite_risk = composite_risk
        self.trust_score = trust_score
        self.mercy_applied = mercy_applied
        self.raw_verdict = raw_verdict

        appeal_info = (
            f" | Contestable: YES (appeal within {appeal_deadline_hours}h)"
            if contestable
            else " | Contestable: NO (hard block — no appeal pathway)"
        )
        mercy_info = " | Mercy: YES (Gilligan intervention)" if mercy_applied else ""

        msg = (
            f"[BTV GRANT BLOCKED] verdict={verdict_id} action={action} "
            f"risk={composite_risk or 'N/A'} trust={trust_score or 'N/A'}"
            f"{appeal_info}{mercy_info}\n"
            f"  Rationale: {rationale}"
        )
        super().__init__(msg)
