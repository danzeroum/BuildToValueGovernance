"""
BuildToValue Grant Decision Adapter

Routes GrantProposal objects through the BTV ethical governance kernel,
applying the full pipeline: sanitization → language detection → policy
evaluation → Rawls/Levinas/Jonas/Gilligan ethical stages → verdict.

Key design decisions (see docs/adr/TBD-grant-decision-adapter.md):
  (a) use_decide=True — grants always use the full ethical pipeline
  (b) hard_blocked is checked BEFORE action — fail-secure gate
  (c) HMAC-SHA256 for session_id — not BLAKE3 (Rust kernel's domain)
  (d) JSON serialization for to_btv_input — avoids LanguageDetector confusion
  (e) Policy files live in data/policies/sectors/ — existing taxonomy
  (f) BiasDeclaration null for sw group — Jonas responsibility principle

BTV AI Squad role: Dev Python (Sonnet)
Required reviewer: Arquiteta (Opus) — ADR conformance
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import FrozenSet, Optional

from .exceptions import GrantBlockedError, GrantValidationError
from .models import GrantCategory, GrantProposal, GrantVerdict

logger = logging.getLogger(__name__)

# Actions that cause GrantBlockedError to be raised by default.
# EDUCATE is intentionally excluded: it is a non-blocking intervention.
# LOG is informational only.
_DEFAULT_BLOCK_ON: FrozenSet[str] = frozenset({"BLOCK", "REDACT"})

# Default Levinas SLA appeal window (hours) for policy blocks.
_DEFAULT_APPEAL_HOURS: int = 168  # 7 days


@dataclass
class AdapterConfig:
    """Configuration for GrantDecisionAdapter.

    Attributes:
        gateway_url: Base URL of the BTV governance gateway.
        policy_id: Identifier of the grant eligibility policy.
                   Maps to data/policies/sectors/grant-eligibility-v1.yaml.
        timeout_seconds: HTTP timeout for kernel requests.
        raise_on_block: If True (default), raise GrantBlockedError for blocked proposals.
                        Set to False in testing or when the caller prefers explicit checks.
        block_on: Set of actions that trigger GrantBlockedError. Defaults to BLOCK+REDACT.
        appeal_deadline_hours: Hours the applicant has to contest a policy block.
    """
    gateway_url: str
    policy_id: str = "grant-eligibility-v1"
    timeout_seconds: float = 5.0
    raise_on_block: bool = True
    block_on: FrozenSet[str] = field(default_factory=lambda: _DEFAULT_BLOCK_ON)
    appeal_deadline_hours: int = _DEFAULT_APPEAL_HOURS


class GrantDecisionAdapter:
    """Routes grant proposals through the BTV ethical governance pipeline.

    The adapter wraps the BTV Python SDK's `use_decide()` interface,
    enforcing grant-specific invariants on top of the base governance kernel.

    Thread-safety: instances are stateless after construction; safe to share
    across threads/async tasks.

    Example::

        config = AdapterConfig(gateway_url="https://btv.example.com")
        adapter = GrantDecisionAdapter(config)
        try:
            verdict = adapter.evaluate(proposal)
        except GrantBlockedError as e:
            # Surface e.contestable and e.appeal_deadline_hours to applicant
            ...
    """

    def __init__(self, config: AdapterConfig) -> None:
        self._config = config
        self._client = self._build_client()

    def _build_client(self) -> object:
        """Construct the BTV SDK client.

        In production, this wraps buildtovalue.Client with gateway_url and
        timeout. In tests, the client is replaced via dependency injection
        or patching.
        """
        try:
            from buildtovalue import Client  # type: ignore[import]
            return Client(
                gateway_url=self._config.gateway_url,
                timeout=self._config.timeout_seconds,
            )
        except ImportError:
            logger.warning(
                "buildtovalue SDK not installed. "
                "GrantDecisionAdapter running in stub mode (tests only)."
            )
            return _StubClient()

    def evaluate(
        self,
        proposal: GrantProposal,
        *,
        raise_on_block: Optional[bool] = None,
    ) -> GrantVerdict:
        """Evaluate a grant proposal through the BTV governance pipeline.

        Args:
            proposal: The GrantProposal to evaluate. Must pass structural
                      validation (GrantProposal.__post_init__) before this call.
            raise_on_block: Override config.raise_on_block for this call.
                            Useful for dry-run evaluation without exceptions.

        Returns:
            GrantVerdict when the proposal is ALLOW or EDUCATE (non-blocking).

        Raises:
            GrantBlockedError: When action is in config.block_on AND
                               raise_on_block is True.
            GrantValidationError: Should not occur here (raised by GrantProposal
                                  constructor), but propagated if caught.
        """
        should_raise = raise_on_block if raise_on_block is not None else self._config.raise_on_block

        btv_input = proposal.to_btv_input()
        session_id = proposal.to_session_id()

        logger.debug(
            "Evaluating grant proposal",
            extra={
                "session_id": session_id,
                "applicant_id": proposal.applicant_id,
                "category": proposal.category.value,
                "budget_usd": proposal.budget_usd,
            },
        )

        raw_verdict = self._client.use_decide(
            content=btv_input,
            session_id=session_id,
            policy_id=self._config.policy_id,
        )

        return self._process_verdict(
            raw_verdict=raw_verdict,
            proposal=proposal,
            should_raise=should_raise,
        )

    def _process_verdict(
        self,
        raw_verdict: object,
        proposal: GrantProposal,
        should_raise: bool,
    ) -> GrantVerdict:
        """Apply fail-secure gate and build GrantVerdict.

        ADR-TBD §(b): hard_blocked is checked BEFORE action.
        A verdict with hard_blocked=True is unconditionally blocking,
        even if action is EDUCATE or mercy_applied is True.
        """
        hard_blocked: bool = getattr(raw_verdict, "hard_blocked", False)
        action: str = getattr(raw_verdict, "action", "BLOCK")
        if hasattr(action, "value"):
            action = action.value
        verdict_id: str = getattr(raw_verdict, "verdict_id", "VRD-UNKNOWN")
        contestable: bool = getattr(raw_verdict, "contestable", True)
        appeal_hours: int = getattr(raw_verdict, "appeal_deadline_hours", self._config.appeal_deadline_hours)
        composite_risk: float = getattr(raw_verdict, "composite_risk", 0.0)
        trust_score: float = getattr(raw_verdict, "trust_score", 1.0)
        mercy_applied: bool = getattr(raw_verdict, "mercy_applied", False)
        rationale: str = getattr(raw_verdict, "rationale", "")
        rawls: str = getattr(raw_verdict, "rawls_rationale", "")
        levinas: str = getattr(raw_verdict, "levinas_rationale", "")
        jonas: str = getattr(raw_verdict, "jonas_rationale", "")
        gilligan: str = getattr(raw_verdict, "gilligan_rationale", "")

        # --- GATE 1: hard_blocked (fail-secure — checked before action) ---
        if hard_blocked:
            logger.warning(
                "Hard block applied",
                extra={
                    "verdict_id": verdict_id,
                    "applicant_id": proposal.applicant_id,
                    "mercy_applied": mercy_applied,
                },
            )
            if should_raise:
                raise GrantBlockedError(
                    verdict_id=verdict_id,
                    action=action,
                    rationale=rationale or "Hard block: sanctioned entity or critical risk pattern.",
                    contestable=False,   # Hard blocks are never contestable
                    appeal_deadline_hours=0,
                    composite_risk=composite_risk,
                    trust_score=trust_score,
                    mercy_applied=mercy_applied,
                    raw_verdict=raw_verdict,
                )
            # raise_on_block=False: return enriched verdict so caller can inspect
            return GrantVerdict(
                verdict_id=verdict_id,
                action=action,
                composite_risk=composite_risk,
                trust_score=trust_score,
                mercy_applied=mercy_applied,
                contestable=False,
                appeal_deadline_hours=0,
                rawls_rationale=rawls,
                levinas_rationale=levinas,
                jonas_rationale=jonas,
                gilligan_rationale=gilligan,
                is_hard_block=True,
            )

        # --- GATE 2: policy action (BLOCK, REDACT, etc.) ---
        if action in self._config.block_on:
            logger.info(
                "Policy block applied",
                extra={
                    "verdict_id": verdict_id,
                    "action": action,
                    "composite_risk": composite_risk,
                    "contestable": contestable,
                },
            )
            if should_raise:
                raise GrantBlockedError(
                    verdict_id=verdict_id,
                    action=action,
                    rationale=rationale or f"Policy block: action={action}.",
                    contestable=contestable,
                    appeal_deadline_hours=appeal_hours if contestable else 0,
                    composite_risk=composite_risk,
                    trust_score=trust_score,
                    mercy_applied=mercy_applied,
                    raw_verdict=raw_verdict,
                )

        # --- ALLOW / EDUCATE / INSPECT: return GrantVerdict ---
        return GrantVerdict(
            verdict_id=verdict_id,
            action=action,
            composite_risk=composite_risk,
            trust_score=trust_score,
            mercy_applied=mercy_applied,
            contestable=contestable,
            appeal_deadline_hours=appeal_hours,
            rawls_rationale=rawls,
            levinas_rationale=levinas,
            jonas_rationale=jonas,
            gilligan_rationale=gilligan,
        )


class _StubClient:
    """Minimal stub client for unit tests without the BTV SDK installed.

    Returns a permissive ALLOW verdict for all requests.
    Replace via mock.patch in test suites that need specific verdict behavior.
    """

    def use_decide(
        self,
        content: str,
        session_id: str,
        policy_id: str,
    ) -> object:
        from dataclasses import dataclass as _dc

        @_dc
        class _StubVerdict:
            verdict_id: str = "VRD-STUB000000000000000000000"
            action: str = "ALLOW"
            hard_blocked: bool = False
            contestable: bool = True
            appeal_deadline_hours: int = 168
            mercy_applied: bool = False
            composite_risk: float = 0.05
            trust_score: float = 0.95
            rationale: str = "Stub: no BTV SDK installed"
            rawls_rationale: str = ""
            levinas_rationale: str = ""
            jonas_rationale: str = ""
            gilligan_rationale: str = ""

        return _StubVerdict()
