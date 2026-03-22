"""
NegotiationGuard — A2A message safety wrapper.

Sanitizes and validates NegotiationMessages during agent-to-agent negotiation.
Thin composition of existing BTV capabilities for a new use case (A2A negotiation).
The value is the composition, not new detection logic.

Detection pipeline:
  1. YAML injection check on policy dict values (Python-level)
  2. PersuasionGuard on reason field (regex patterns from paper 209)
  3. FFI deobfuscation scan if available (Base64, Hex, Unicode, Leetspeak)
     — graceful degradation if Rust kernel not loaded (logs warning)

BiasDeclaration (Jonas principle):
  FPR on legitimate negotiation messages: TBD (measured during M7-M8 calibration).
  FNR on adversarial messages: TBD (measured via red-team suite).
  Calibration expiry: 90 days.

Invariants:
  - Fail-secure: any exception → SanitizeResult(allowed=False)
  - PersuasionGuard UNAVAILABLE → block (ADR-0049 D3)
  - YAML injection in policy values → block
  - High-suspicion persuasion in reason field → block
  - FFIClient is optional — missing Rust kernel logs warning, skips FFI scan
  - explain_decision mandatory in every SanitizeResult (Levinas)
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Optional

from buildtovalue.governance.persuasion_guard import (
    PersuasionGuard,
    PersuasionGuardUnavailableError,
)

from .types import NegotiationMessage

logger = logging.getLogger("btv.agentic.negotiation_guard")

_DEFAULT_HMAC_KEY: bytes = b"btv-negotiation-guard-v1"

# YAML injection patterns — sequences that can escape YAML context in values
_YAML_INJECTION_PATTERNS = [
    re.compile(r"^\s*---\s*\n"),           # YAML document separator
    re.compile(r"\|\s*\n\s*system:"),      # Block scalar + system key
    re.compile(r"!python/"),               # YAML deserialization gadgets
    re.compile(r"!!python/"),
    re.compile(r"__import__"),             # Python exec injection
    re.compile(r"eval\s*\("),
    re.compile(r"exec\s*\("),
    re.compile(r"<script\b", re.I),        # XSS in embedded HTML
    re.compile(r"\bignore\b.{0,60}\binstructions?\b", re.I),  # Jailbreak attempt
    re.compile(r"\boverride\b.{0,60}\b(policy|rule|constraint)\b", re.I),
]

# Persuasion score threshold — above this → block
_PERSUASION_SCORE_THRESHOLD: float = 0.5


# ─── Result Type ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SanitizeResult:
    """
    Result of NegotiationGuard.sanitize().

    allowed=True:  clean_message is populated, message may proceed.
    allowed=False: clean_message is None, reason explains why it was blocked.
    explain_decision: mandatory (Levinas — full transparency).
    signature: HMAC-SHA256 of result (Jonas — responsibility).
    """
    allowed: bool
    clean_message: Optional[NegotiationMessage]
    reason: Optional[str]
    explain_decision: str
    timestamp: float
    signature: str


# ─── NegotiationGuard ────────────────────────────────────────────────────────

class NegotiationGuard:
    """
    Thin composition of existing BTV safety primitives for A2A use.

    Args:
        persuasion_guard: PersuasionGuard instance (required for CoT defense).
        ffi_client: Optional FFIClient for Rust deobfuscation scan.
                    If None, FFI scan is skipped (graceful degradation).
        hmac_key: Key for HMAC-SHA256 signing of SanitizeResult.
        persuasion_threshold: Block if persuasion_score > threshold.
    """

    def __init__(
        self,
        persuasion_guard: PersuasionGuard,
        ffi_client: Optional[object] = None,  # FFIClient, optional for testability
        hmac_key: bytes = _DEFAULT_HMAC_KEY,
        persuasion_threshold: float = _PERSUASION_SCORE_THRESHOLD,
    ) -> None:
        self._persuasion_guard = persuasion_guard
        self._ffi_client = ffi_client
        self._hmac_key = hmac_key
        self._persuasion_threshold = persuasion_threshold

        if ffi_client is None:
            logger.warning(
                "NegotiationGuard: FFIClient not provided — "
                "Rust deobfuscation scan will be skipped (degraded mode)."
            )

    def sanitize(self, message: NegotiationMessage) -> SanitizeResult:
        """
        Sanitize a NegotiationMessage before processing.

        Pipeline:
          1. YAML injection check on policy dict values
          2. PersuasionGuard on reason field
          3. FFI scan if available (deobfuscation: Base64/Hex/Unicode/Leetspeak)

        Returns SanitizeResult(allowed=True, clean_message=message) if safe,
        or SanitizeResult(allowed=False, reason=...) if blocked.
        On any exception: fail-secure block.
        """
        try:
            return self._sanitize(message)
        except PersuasionGuardUnavailableError as exc:
            logger.error("NegotiationGuard: PersuasionGuard unavailable: %s", exc)
            return self._fail_secure(
                f"PersuasionGuard unavailable (ADR-0049 D3): {exc}"
            )
        except Exception as exc:
            logger.error("NegotiationGuard.sanitize exception: %s", exc)
            return self._fail_secure(str(exc))

    def _sanitize(self, message: NegotiationMessage) -> SanitizeResult:
        timestamp = time.time()

        # Step 1: YAML injection check on policy values
        if message.policy is not None:
            injection_reason = self._check_yaml_injection(message.policy)
            if injection_reason:
                explain = (
                    f"NegotiationGuard BLOCK: YAML injection detected in policy. "
                    f"Reason: {injection_reason}. "
                    f"Round: {message.round_number}, Type: {message.type}."
                )
                sig = self._sign(False, injection_reason, timestamp)
                return SanitizeResult(
                    allowed=False,
                    clean_message=None,
                    reason=injection_reason,
                    explain_decision=explain,
                    timestamp=timestamp,
                    signature=sig,
                )

        # Step 2: PersuasionGuard on reason field
        if message.reason is not None:
            annotated = self._persuasion_guard.annotate_cot(message.reason)
            if annotated.persuasion_score > self._persuasion_threshold:
                reason = (
                    f"Persuasion score {annotated.persuasion_score:.2f} > "
                    f"threshold {self._persuasion_threshold:.2f}. "
                    f"High suspicion flags: {annotated.high_suspicion_count}."
                )
                explain = (
                    f"NegotiationGuard BLOCK: adversarial persuasion in reason field. "
                    f"{reason} Round: {message.round_number}, Type: {message.type}. "
                    f"Persuasion guard: {annotated.to_explain_dict()}"
                )
                sig = self._sign(False, reason, timestamp)
                return SanitizeResult(
                    allowed=False,
                    clean_message=None,
                    reason=reason,
                    explain_decision=explain,
                    timestamp=timestamp,
                    signature=sig,
                )

        # Step 3: FFI scan (optional)
        if self._ffi_client is not None:
            ffi_reason = self._run_ffi_scan(message)
            if ffi_reason:
                explain = (
                    f"NegotiationGuard BLOCK: FFI kernel detected threat. "
                    f"Reason: {ffi_reason}. "
                    f"Round: {message.round_number}, Type: {message.type}."
                )
                sig = self._sign(False, ffi_reason, timestamp)
                return SanitizeResult(
                    allowed=False,
                    clean_message=None,
                    reason=ffi_reason,
                    explain_decision=explain,
                    timestamp=timestamp,
                    signature=sig,
                )

        # All checks passed
        explain = (
            f"NegotiationGuard ALLOW: message passed all safety checks. "
            f"Round: {message.round_number}, Type: {message.type}. "
            f"FFI scan: {'active' if self._ffi_client is not None else 'degraded (no FFI)'}."
        )
        sig = self._sign(True, "allowed", timestamp)
        return SanitizeResult(
            allowed=True,
            clean_message=message,
            reason=None,
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )

    def _check_yaml_injection(self, policy: dict) -> Optional[str]:
        """
        Check policy dict values for YAML injection / jailbreak patterns.
        Recursively checks string values in nested dicts and lists.
        Returns reason string if injection detected, None if clean.
        """
        def check_value(v: object, path: str) -> Optional[str]:
            if isinstance(v, str):
                for pattern in _YAML_INJECTION_PATTERNS:
                    if pattern.search(v):
                        return f"Injection pattern '{pattern.pattern[:40]}' in field '{path}'"
            elif isinstance(v, dict):
                for k, sub_v in v.items():
                    result = check_value(sub_v, f"{path}.{k}")
                    if result:
                        return result
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    result = check_value(item, f"{path}[{i}]")
                    if result:
                        return result
            return None

        for key, value in policy.items():
            result = check_value(value, str(key))
            if result:
                return result
        return None

    def _run_ffi_scan(self, message: NegotiationMessage) -> Optional[str]:
        """
        Run Rust kernel scan on message text fields.
        Returns reason string if threat detected, None if clean.
        Logs error and returns None on FFIError (fail-open for FFI, fail-secure elsewhere).
        """
        try:
            # Serialize message fields to scan
            text_to_scan = json.dumps({
                "reason": message.reason,
                "policy_str": str(message.policy) if message.policy else "",
            })
            evidence = self._ffi_client.scan(text_to_scan)  # type: ignore[union-attr]
            if evidence.critical_count > 0:
                titles = [f.title for f in evidence.critical[:3]]
                return f"Rust kernel: {evidence.critical_count} critical finding(s): {titles}"
            return None
        except Exception as exc:
            logger.warning("NegotiationGuard: FFI scan failed (non-blocking): %s", exc)
            return None  # FFI failure is not itself a block reason

    def _sign(self, allowed: bool, reason: str, timestamp: float) -> str:
        content = f"{allowed}:{reason}:{timestamp}"
        return _hmac.new(self._hmac_key, content.encode(), hashlib.sha256).hexdigest()

    def _fail_secure(self, reason: str) -> SanitizeResult:
        """Fail-secure: block on any unexpected exception."""
        timestamp = time.time()
        explain = (
            f"NegotiationGuard FAIL-SECURE: {reason}. "
            f"Message blocked — manual review required (Jonas principle)."
        )
        sig = self._sign(False, reason, timestamp)
        return SanitizeResult(
            allowed=False,
            clean_message=None,
            reason=reason,
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )
