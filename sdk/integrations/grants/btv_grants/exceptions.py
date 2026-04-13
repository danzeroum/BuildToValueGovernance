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


class GrantBlockedError(Exception):
    """Raised when a grant proposal is blocked by the BTV governance pipeline.

    Attributes:
        verdict_id: Unique ULID identifier of the verdict.
        action: The governance action taken — typically 'BLOCK'.
        rationale: Human-readable rationale combining Rawls/Levinas/Jonas/Gilligan.
        contestable: Whether the applicant can file an appeal via /v1/appeals.
        appeal_deadline_hours: Hours remaining to file an appeal.
        composite_risk: Aggregate risk score (0.0–1.0).
        trust_score: Post-pipeline trust score.
        mercy_applied: Whether Gilligan's mercy algorithm intervened.
        raw_verdict: Optional reference to the original Verdict object.
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


class GrantValidationError(Exception):
    """Raised when a grant proposal fails structural validation.

    Attributes:
        field: The field name that failed validation.
        reason: Human-readable description of the failure.
        proposal_ref: Optional reference to the GrantProposal.
    """

    def __init__(
        self,
        field: str,
        reason: str,
        proposal_ref: Optional[object] = None,
    ) -> None:
        self.field = field
        self.reason = reason
        self.proposal_ref = proposal_ref
        super().__init__(f"Validation failed on '{field}': {reason}")


class GrantSanitizationError(Exception):
    """Raised when sanitization of a grant proposal fails unexpectedly.

    Attributes:
        stage: Which sanitization stage failed.
        detail: Technical detail about the failure.
    """

    def __init__(self, stage: str, detail: str) -> None:
        self.stage = stage
        self.detail = detail
        super().__init__(f"Sanitization failed at '{stage}': {detail}")


class BiasDeclarationError(Exception):
    """Raised when the BiasDeclaration for a linguistic group is misconfigured.

    Attributes:
        group: The linguistic group code (e.g. 'sw', 'pt-BR').
        reason: Description of the misconfiguration.
    """

    def __init__(self, group: str, reason: str) -> None:
        self.group = group
        self.reason = reason
        super().__init__(f"BiasDeclaration error for group '{group}': {reason}")
