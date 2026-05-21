"""
BuildToValue Grant Decision Adapter — Core Adapter

PATTERN: Follows the 4-element BTV adapter contract:
  1. Custom Exception  → GrantBlockedError (exceptions.py)
  2. Guard Class        → GrantGuard (this file)
  3. _validate()        → Pre-flight structural validation
  4. _sanitize()        → Input transformation for safe kernel processing

DESIGN DECISIONS (documented in ADR-043):
  - use_decide=True by default — grants carry real financial risk.
  - hard_blocked checked BEFORE action (fail-secure priority).
  - HMAC-SHA256 for session_id (kernel handles internal hashing; adapters must not re-hash).
  - JSON minified serialization (avoids English-prefix language confusion).
  - BTVClient imported lazily (TYPE_CHECKING only) so the adapter module
    can be imported in environments where buildtovalue SDK is not installed.
    This enables unit-testing, CI import checks, and dry-run usage without
    requiring the full BTV Python SDK to be present.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set

if TYPE_CHECKING:
    # These imports are used ONLY for type annotations (never executed at runtime).
    # The buildtovalue SDK is an optional runtime dependency — code that actually
    # calls BTVClient methods imports it lazily inside evaluate().
    from buildtovalue import BTVClient  # noqa: F401
    from buildtovalue.models import Verdict  # noqa: F401

from .exceptions import (
    GrantBlockedError,
    GrantSanitizationError,
    GrantValidationError,
)
from .models import (
    ActionImpact,
    BiasDeclaration,
    DEFAULT_BIAS_DECLARATIONS,
    GrantCategory,
    GrantProposal,
    GrantStage,
    LinguisticGroup,
)

logger = logging.getLogger("btv_grants")


def _require_btvclient() -> Any:
    """Lazy-load BTVClient at runtime; raises ImportError with clear message."""
    try:
        from buildtovalue import BTVClient  # type: ignore[import]
        return BTVClient
    except ImportError as exc:
        raise ImportError(
            "The 'buildtovalue' SDK is required to call the BTV kernel. "
            "Install it with: pip install buildtovalue"
        ) from exc


def _require_verdict_class() -> Any:
    """Lazy-load Verdict at runtime; raises ImportError with clear message."""
    try:
        from buildtovalue.models import Verdict  # type: ignore[import]
        return Verdict
    except ImportError as exc:
        raise ImportError(
            "The 'buildtovalue' SDK is required to call the BTV kernel. "
            "Install it with: pip install buildtovalue"
        ) from exc


class GrantGuardConfig:
    """Configuration for the GrantGuard adapter."""

    def __init__(
        self,
        block_on: Optional[Set[str]] = None,
        raise_on_block: bool = True,
        use_decide: bool = True,
        policy_path: str = "data/policies/sectors/grant-eligibility-v1.yaml",
        agent_id: str = "grant-decision-adapter",
        bias_declarations: Optional[Dict[LinguisticGroup, BiasDeclaration]] = None,
        session_salt: bytes = b"btv-grant-salt",
        sanitize_strip_emoji: bool = True,
        sanitize_max_length: int = 50_000,
        sanitize_wallet_pattern: str = r"^0x[0-9a-fA-F]{40}$",
        dry_run: bool = False,
    ) -> None:
        self.block_on = block_on or {"BLOCK", "REDACT"}
        self.raise_on_block = raise_on_block
        self.use_decide = use_decide
        self.policy_path = policy_path
        self.agent_id = agent_id
        self.bias_declarations = bias_declarations or DEFAULT_BIAS_DECLARATIONS
        self.session_salt = session_salt
        self.sanitize_strip_emoji = sanitize_strip_emoji
        self.sanitize_max_length = sanitize_max_length
        self.sanitize_wallet_pattern = sanitize_wallet_pattern
        self.dry_run = dry_run


class GrantGuard:
    """BTV Governance Guard for grant proposal evaluation.

    Usage:
        from buildtovalue import BTVClient
        from btv_grants import GrantGuard, GrantProposal, GrantCategory, LinguisticGroup

        client = BTVClient(api_key="...")
        guard = GrantGuard(client)

        proposal = GrantProposal(
            applicant_id="0xabc...123",
            title="Decentralized Water Quality Monitoring",
            description="We will deploy IoT sensors...",
            category=GrantCategory.PUBLIC_GOODS,
            budget_usd=50_000,
            linguistic_group=LinguisticGroup.PT_BR,
        )

        try:
            verdict = guard.evaluate(proposal)
        except GrantBlockedError as e:
            if e.contestable:
                print(f"Appeal within {e.appeal_deadline_hours}h")

    Note on dry_run:
        Set dry_run=True in GrantGuardConfig to skip BTV kernel calls.
        Useful for testing and CI environments without buildtovalue installed.
    """

    def __init__(
        self,
        client: Any,  # BTVClient at runtime; Any avoids forcing the import
        config: Optional[GrantGuardConfig] = None,
    ) -> None:
        self._client = client
        self._config = config or GrantGuardConfig()
        self._validate_hooks: List[Callable[[GrantProposal], None]] = []
        self._sanitize_hooks: List[Callable[[GrantProposal], GrantProposal]] = []
        logger.info(
            "GrantGuard initialized | use_decide=%s | block_on=%s | dry_run=%s",
            self._config.use_decide,
            self._config.block_on,
            self._config.dry_run,
        )

    def register_validate_hook(
        self, hook: Callable[[GrantProposal], None]
    ) -> "GrantGuard":
        self._validate_hooks.append(hook)
        return self

    def register_sanitize_hook(
        self, hook: Callable[[GrantProposal], GrantProposal]
    ) -> "GrantGuard":
        self._sanitize_hooks.append(hook)
        return self

    def _validate(self, proposal: GrantProposal) -> None:
        """Structural pre-flight checks before BTV kernel call."""
        logger.debug("Validating proposal for applicant: %s", proposal.applicant_id)

        if proposal.budget_usd > 10_000_000:
            raise GrantValidationError(
                "budget_usd",
                f"Budget ${proposal.budget_usd:,.2f} exceeds maximum of $10,000,000",
                proposal,
            )
        if proposal.wallet_address:
            if not re.match(self._config.sanitize_wallet_pattern, proposal.wallet_address):
                raise GrantValidationError(
                    "wallet_address",
                    f"Invalid Ethereum address format: {proposal.wallet_address}",
                    proposal,
                )
        if proposal.linguistic_group not in self._config.bias_declarations:
            logger.warning(
                "No BiasDeclaration for linguistic group '%s'. "
                "Governance results may be unreliable for this group.",
                proposal.linguistic_group.value,
            )
        for hook in self._validate_hooks:
            hook(proposal)
        logger.debug("Proposal passed structural validation")

    def _sanitize(self, proposal: GrantProposal) -> GrantProposal:
        """Input normalization — returns a NEW object, never mutates original."""
        logger.debug("Sanitizing proposal for applicant: %s", proposal.applicant_id)
        try:
            data = proposal.to_dict() if hasattr(proposal, "to_dict") else vars(proposal).copy()

            if self._config.sanitize_strip_emoji:
                emoji_pattern = re.compile(
                    "["
                    "\U0001F600-\U0001F64F"
                    "\U0001F300-\U0001F5FF"
                    "\U0001F680-\U0001F6FF"
                    "\U0001F1E0-\U0001F1FF"
                    "\U00002702-\U000027B0"
                    "\U000024C2-\U0001F251"
                    "\U0001f926-\U0001f937"
                    "\U00010000-\U0010ffff"
                    "\u2640-\u2642"
                    "\u2600-\u2B55"
                    "\u200d\u23cf\u23e9\u231a\ufe0f\u3030"
                    "]+",
                    flags=re.UNICODE,
                )
                data["title"] = emoji_pattern.sub("", data["title"])
                data["description"] = emoji_pattern.sub("", data["description"])

            if len(data["description"]) > self._config.sanitize_max_length:
                original_len = len(data["description"])
                data["description"] = data["description"][: self._config.sanitize_max_length]
                logger.warning(
                    "Description truncated from %d to %d characters for applicant: %s",
                    original_len,
                    self._config.sanitize_max_length,
                    proposal.applicant_id,
                )

            for text_field in ("title", "description"):
                data[text_field] = re.sub(r"\s+", " ", data[text_field]).strip()

            sanitized = GrantProposal(
                applicant_id=data["applicant_id"],
                title=data["title"],
                description=data["description"],
                category=GrantCategory(data["category"]),
                stage=GrantStage(data["stage"]),
                budget_usd=data["budget_usd"],
                team_size=data["team_size"],
                linguistic_group=LinguisticGroup(data["linguistic_group"]),
                action_impact=ActionImpact(data["action_impact"]),
                country_code=data.get("country_code"),
                wallet_address=data.get("wallet_address"),
                tags=data.get("tags", []),
                metadata=data.get("metadata", {}),
            )
            for hook in self._sanitize_hooks:
                sanitized = hook(sanitized)
            return sanitized

        except (GrantValidationError, GrantBlockedError):
            raise
        except Exception as exc:
            raise GrantSanitizationError("general", str(exc)) from exc

    def evaluate(self, proposal: GrantProposal) -> Any:
        """Evaluate a grant proposal through the BTV governance pipeline.

        Evaluation order (ADR-043):
          1. _validate()          — structural pre-flight
          2. _sanitize()          — input normalization
          3. client.decide(...)   — BTV kernel call
          4. hard_blocked check   — FAIL-SECURE GATE (priority 1)
          5. action in block_on   — POLICY GATE (priority 2)
          6. return verdict       — ALLOW/EDUCATE/INSPECT/LOG
        """
        self._validate(proposal)
        sanitized = self._sanitize(proposal)
        btv_input = sanitized.to_btv_input()
        session_id = sanitized.to_session_id()

        logger.info(
            "Evaluating grant proposal | applicant=%s | session=%s | use_decide=%s",
            sanitized.applicant_id[:12] + "...",
            session_id[:16] + "...",
            self._config.use_decide,
        )

        if self._config.dry_run:
            logger.info("DRY RUN — skipping BTV kernel call")
            Verdict = _require_verdict_class()
            mock_verdict = Verdict(
                verdict_id="VRD-DRYRUN00000000000000000000",
                action="ALLOW",
                hard_blocked=False,
                contestable=False,
                appeal_deadline_hours=0,
                mercy_applied=False,
                composite_risk=0.0,
                jurisdiction_bitmask=0,
            )
            return mock_verdict

        try:
            if self._config.use_decide:
                verdict = self._client.decide(
                    btv_input,
                    session_id=session_id,
                    agent_id=self._config.agent_id,
                    profile=self._config.policy_path,
                )
            else:
                verdict = self._client.validate(
                    btv_input,
                    session_id=session_id,
                    agent_id=self._config.agent_id,
                )
        except Exception as exc:
            logger.error(
                "BTV kernel call failed for applicant %s: %s",
                sanitized.applicant_id,
                exc,
            )
            raise

        action_str = (
            verdict.action.value
            if hasattr(verdict.action, "value")
            else str(verdict.action)
        )

        logger.info(
            "BTV verdict | verdict=%s | action=%s | hard_blocked=%s | risk=%.4f | mercy=%s",
            verdict.verdict_id,
            action_str,
            verdict.hard_blocked,
            verdict.composite_risk or 0.0,
            verdict.mercy_applied,
        )

        # HARD_BLOCKED CHECK — takes absolute precedence (ADR-043 §4)
        # Gilligan's mercy cannot override a hard block.
        if verdict.hard_blocked:
            if self._config.raise_on_block:
                raise GrantBlockedError(
                    verdict_id=verdict.verdict_id,
                    action=action_str,
                    rationale=getattr(verdict, "rationale", "Hard blocked by kernel"),
                    contestable=False,
                    appeal_deadline_hours=0,
                    composite_risk=verdict.composite_risk,
                    trust_score=getattr(verdict, "trust_score", None),
                    mercy_applied=verdict.mercy_applied,
                    raw_verdict=verdict,
                )
            return verdict

        # ACTION CHECK
        if action_str in self._config.block_on:
            if self._config.raise_on_block:
                raise GrantBlockedError(
                    verdict_id=verdict.verdict_id,
                    action=action_str,
                    rationale=getattr(verdict, "rationale", "Blocked by policy"),
                    contestable=verdict.contestable,
                    appeal_deadline_hours=verdict.appeal_deadline_hours,
                    composite_risk=verdict.composite_risk,
                    trust_score=getattr(verdict, "trust_score", None),
                    mercy_applied=verdict.mercy_applied,
                    raw_verdict=verdict,
                )
            return verdict

        return verdict

    def evaluate_batch(
        self,
        proposals: List[GrantProposal],
        parallel: bool = True,
    ) -> List[tuple]:
        """Evaluate multiple grant proposals sequentially."""
        results: List[tuple] = []
        for proposal in proposals:
            try:
                verdict = self.evaluate(proposal)
                results.append((proposal, verdict))
            except Exception as exc:
                results.append((proposal, exc))
                logger.warning(
                    "Proposal '%s' raised %s: %s",
                    proposal.title[:50],
                    type(exc).__name__,
                    exc,
                )
        # Lazy import Verdict class for isinstance check
        try:
            Verdict = _require_verdict_class()
            summary_allowed = sum(1 for _, r in results if isinstance(r, Verdict))
        except ImportError:
            summary_allowed = 0
        summary_blocked = sum(1 for _, r in results if isinstance(r, GrantBlockedError))
        logger.info(
            "Batch complete | total=%d | allowed=%d | blocked=%d",
            len(results), summary_allowed, summary_blocked,
        )
        return results

    def appeal(
        self,
        verdict_id: str,
        appellant_statement: str,
        supporting_evidence: Optional[List[str]] = None,
    ) -> Any:
        """File an appeal against a blocked verdict."""
        raise NotImplementedError(
            "Appeal support pending BTV Python SDK /v1/appeals integration."
        )

    def trust_history(self, session_id: str) -> Any:
        """Query trust history for a governance session."""
        raise NotImplementedError(
            "Trust history support pending BTV Python SDK /v1/trust integration."
        )
