"""
BuildToValue Grant Decision Adapter — Core Adapter

The GrantGuard class integrates BTV governance into grant evaluation pipelines
(e.g. Gitcoin Rounds, DAO treasury, quadratic funding platforms).

PATTERN: Follows the 4-element BTV adapter contract:
  1. Custom Exception  → GrantBlockedError (exceptions.py)
  2. Guard Class        → GrantGuard (this file)
  3. _validate()        → Pre-flight structural validation
  4. _sanitize()        → Input transformation for safe kernel processing

DESIGN DECISIONS (documented in ADR-043):
  - use_decide=True by default (intentional deviation from other adapters' False).
    Grants carry real financial risk → full ethical pipeline is warranted.
  - hard_blocked checked BEFORE action (Rust gatekeeper override takes precedence).
  - HMAC-SHA256 for session_id (Rust kernel handles BLAKE3 internally).
  - JSON minified serialization (avoids English-prefix language confusion).

Reference adapters:
  - sdk/integrations/langchain/btv_langchain/callback.py
  - sdk/integrations/crewai/btv_crewai/guard.py
  - sdk/integrations/autogen/btv_autogen/callback.py
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, List, Optional, Set

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


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class GrantGuardConfig:
    """Configuration for the GrantGuard adapter.

    Attributes:
        block_on: Set of Verdict actions that trigger GrantBlockedError.
                  Defaults to {'BLOCK', 'REDACT'}. 'EDUCATE' is NOT blocking —
                  it allows the proposal through with educational guidance.
        raise_on_block: If False, blocked proposals return the Verdict without
                        raising. Useful for dry-run / audit modes.
        use_decide: If True, calls /v1/decide (full ethical pipeline ~30ms).
                    If False, calls /v1/validate (Rust-only gatekeeper ~3ms).
                    Default is True for grants — financial risk warrants full
                    governance. Documented in ADR-043 §1 as intentional deviation
                    from other adapters (LangChain, CrewAI default to False).
        policy_path: Path to the sector-specific YAML policy file.
                     Defaults to data/policies/sectors/grant-eligibility-v1.yaml.
        agent_id: Identifier for this adapter in BTV audit logs.
        bias_declarations: Per-linguistic-group bias calibration data.
                           Defaults to DEFAULT_BIAS_DECLARATIONS from models.py.
        session_salt: HMAC-SHA256 salt for session_id derivation.
                      MUST be rotated per environment (dev/staging/prod).
        sanitize_strip_emoji: Whether to strip emoji from proposal text before
                              sending to BTV kernel.
        sanitize_max_length: Maximum character length for the description field.
        sanitize_wallet_pattern: Regex pattern for Ethereum wallet validation.
        dry_run: If True, logs what would happen without calling BTV kernel.
    """

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


# ---------------------------------------------------------------------------
# GrantGuard — Main Adapter
# ---------------------------------------------------------------------------

class GrantGuard:
    """BTV Governance Guard for grant proposal evaluation.

    Usage:
        from btv_grants import GrantGuard, GrantGuardConfig, GrantProposal, GrantCategory

        guard = GrantGuard(client, GrantGuardConfig(dry_run=True))

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
            print(f"ALLOWED — risk: {verdict.composite_risk}")
        except GrantBlockedError as e:
            print(f"BLOCKED — contestable: {e.contestable}")
            if e.contestable:
                print(f"Appeal within {e.appeal_deadline_hours}h")
    """

    def __init__(
        self,
        client: Any,  # BTVClient — kept as Any to avoid hard dependency
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

    # ------------------------------------------------------------------
    # Hook Registration
    # ------------------------------------------------------------------

    def register_validate_hook(
        self, hook: Callable[[GrantProposal], None]
    ) -> "GrantGuard":
        """Register a custom validation hook (raises GrantValidationError on failure)."""
        self._validate_hooks.append(hook)
        return self

    def register_sanitize_hook(
        self, hook: Callable[[GrantProposal], GrantProposal]
    ) -> "GrantGuard":
        """Register a custom sanitization hook (raises GrantSanitizationError on failure)."""
        self._sanitize_hooks.append(hook)
        return self

    # ------------------------------------------------------------------
    # 3. _validate() — Structural Pre-flight Checks
    # ------------------------------------------------------------------

    def _validate(self, proposal: GrantProposal) -> None:
        """Perform structural validation BEFORE sending to the BTV kernel.

        Raises:
            GrantValidationError: If any structural check fails.
        """
        logger.debug("Validating proposal for applicant: %s", proposal.applicant_id)

        # Budget sanity checks
        if proposal.budget_usd > 10_000_000:
            raise GrantValidationError(
                "budget_usd",
                f"Budget ${proposal.budget_usd:,.2f} exceeds maximum of $10,000,000",
                proposal,
            )

        # Wallet format validation
        if proposal.wallet_address:
            if not re.match(self._config.sanitize_wallet_pattern, proposal.wallet_address):
                raise GrantValidationError(
                    "wallet_address",
                    f"Invalid Ethereum address format: {proposal.wallet_address}",
                    proposal,
                )

        # Bias declaration availability check
        if proposal.linguistic_group not in self._config.bias_declarations:
            logger.warning(
                "No BiasDeclaration for linguistic group '%s'. "
                "Governance results may be unreliable for this group.",
                proposal.linguistic_group.value,
            )

        # Custom hooks
        for hook in self._validate_hooks:
            hook(proposal)

        logger.debug("Proposal passed structural validation")

    # ------------------------------------------------------------------
    # 4. _sanitize() — Input Normalization
    # ------------------------------------------------------------------

    def _sanitize(self, proposal: GrantProposal) -> GrantProposal:
        """Normalize proposal input for safe processing by the BTV kernel.

        The sanitized proposal is a NEW object — the original is not mutated.

        Raises:
            GrantSanitizationError: If sanitization encounters an unrecoverable state.
        """
        logger.debug("Sanitizing proposal for applicant: %s", proposal.applicant_id)

        try:
            data = proposal.to_dict()

            if self._config.sanitize_strip_emoji:
                emoji_pattern = re.compile(
                    "["
                    "\\U0001F600-\\U0001F64F"
                    "\\U0001F300-\\U0001F5FF"
                    "\\U0001F680-\\U0001F6FF"
                    "\\U0001F1E0-\\U0001F1FF"
                    "\\U00002702-\\U000027B0"
                    "\\U000024C2-\\U0001F251"
                    "\\U0001f926-\\U0001f937"
                    "\\U00010000-\\U0010ffff"
                    "\\u2640-\\u2642"
                    "\\u2600-\\u2B55"
                    "\\u200d"
                    "\\u23cf"
                    "\\u23e9"
                    "\\u231a"
                    "\\ufe0f"
                    "\\u3030"
                    "]+",
                    flags=re.UNICODE,
                )
                data["title"] = emoji_pattern.sub("", data["title"])
                data["description"] = emoji_pattern.sub("", data["description"])

            # Truncate description
            if len(data["description"]) > self._config.sanitize_max_length:
                original_len = len(data["description"])
                data["description"] = data["description"][: self._config.sanitize_max_length]
                logger.warning(
                    "Description truncated from %d to %d characters for applicant: %s",
                    original_len,
                    self._config.sanitize_max_length,
                    proposal.applicant_id,
                )

            # Normalize unicode whitespace
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
                deliverables=data.get("deliverables", []),
                tags=data.get("tags", []),
                extra=data.get("extra", {}),
            )

            for hook in self._sanitize_hooks:
                sanitized = hook(sanitized)

            return sanitized

        except (GrantValidationError, GrantBlockedError):
            raise
        except Exception as exc:
            raise GrantSanitizationError("general", str(exc)) from exc

    # ------------------------------------------------------------------
    # evaluate() — Main Entry Point
    # ------------------------------------------------------------------

    def evaluate(self, proposal: GrantProposal) -> Any:
        """Evaluate a grant proposal through the BTV governance pipeline.

        CRITICAL: hard_blocked is checked FIRST (fail-secure gate).
        Even if Gilligan's mercy would change BLOCK→EDUCATE, a hard block
        is final and non-contestable.

        Args:
            proposal: The grant proposal to evaluate.

        Returns:
            Verdict from BTV kernel.

        Raises:
            GrantValidationError: If structural validation fails.
            GrantSanitizationError: If sanitization fails.
            GrantBlockedError: If the proposal is blocked and raise_on_block=True.
        """
        # Step 1: Validate
        self._validate(proposal)

        # Step 2: Sanitize
        sanitized = self._sanitize(proposal)

        # Step 3: Build BTV input
        btv_input = sanitized.to_btv_input()
        session_id = sanitized.to_session_id(secret=self._config.session_salt)

        logger.info(
            "Evaluating grant proposal | applicant=%s | session=%s | use_decide=%s",
            sanitized.applicant_id[:12] + "...",
            session_id[:16] + "...",
            self._config.use_decide,
        )

        # Dry-run mode
        if self._config.dry_run:
            logger.info("DRY RUN — skipping BTV kernel call")
            from dataclasses import dataclass as _dc

            @_dc
            class _MockVerdict:
                verdict_id: str = "VRD-DRYRUN00000000000000000000"
                action: str = "ALLOW"
                hard_blocked: bool = False
                contestable: bool = False
                appeal_deadline_hours: int = 0
                mercy_applied: bool = False
                composite_risk: float = 0.0
                jurisdiction_bitmask: int = 0
                rationale: str = "DRY_RUN"
                trust_score: float = 1.0

            return _MockVerdict()

        # Step 4: Call BTV kernel
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

        # Step 5: Evaluate verdict — hard_blocked FIRST (fail-secure)
        action_str = (
            verdict.action.value
            if hasattr(verdict.action, "value")
            else str(verdict.action)
        )

        logger.info(
            "BTV verdict received | verdict=%s | action=%s | hard_blocked=%s "
            "| risk=%.4f | trust=%.4f | mercy=%s",
            verdict.verdict_id,
            action_str,
            verdict.hard_blocked,
            verdict.composite_risk or 0.0,
            getattr(verdict, "trust_score", 0.0),
            verdict.mercy_applied,
        )

        # HARD_BLOCKED CHECK — absolute precedence
        if verdict.hard_blocked:
            if self._config.raise_on_block:
                raise GrantBlockedError(
                    verdict_id=verdict.verdict_id,
                    action=action_str,
                    rationale=getattr(verdict, "rationale", "Hard blocked by kernel"),
                    contestable=False,  # Hard blocks are NEVER contestable
                    appeal_deadline_hours=0,
                    composite_risk=verdict.composite_risk,
                    trust_score=getattr(verdict, "trust_score", None),
                    mercy_applied=verdict.mercy_applied,
                    hard_blocked=True,
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
                    hard_blocked=False,
                    raw_verdict=verdict,
                )
            return verdict

        logger.info(
            "Grant proposal ALLOWED | applicant=%s | action=%s | risk=%.4f",
            sanitized.applicant_id[:12] + "...",
            action_str,
            verdict.composite_risk or 0.0,
        )
        return verdict
