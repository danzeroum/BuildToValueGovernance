"""ToolOutputSanitizer — PROP-034 Estágio 2 (CommandSans / GIRA)

Responsável pela sanitização semântica de tool outputs, invocado apenas
quando Estágio 1 (Rust fast_injection_screen) retornar InjectionSignal::Suspicious.

Arquitetura dois estágios (RESEARCH_GAPS_v3 v3.1):
  Estágio 1 — Rust hot path: heurísticas rápidas, zero heap, zero alloc
  Estágio 2 — Python (este módulo): classificação semântica, timeout ≤10ms

Invariantes:
  - Fail-secure: BLOCK em erro ou timeout (fail_secure_on_error=True por padrão)
  - explain_decision obrigatório em todo SanitizedOutput
  - Invocado apenas quando stage1_signal != "Clean"
  - removed_tokens_count sempre preenchido
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional
import re
import time


class SanitizerDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


_INJECTION_PATTERNS: tuple[str, ...] = (
    r"(?i)\bignore\b.*\binstruction",
    r"(?i)<\s*system\s*>",
    r"(?i)<\s*instruction\s*>",
    r"(?i)<\s*prompt\s*>",
    r"(?i)\byou are\b.{0,60}\bsystem\b",
    r"(?i)\bdo not follow\b",
    r"(?i)\bdeveloper\s+message\b",
    r"(?i)\bnew\s+instruction\b",
    r"(?i)\bassistant\s*:\s*",
    r"(?i)\bsystem\s*:\s*",
)

_RE_SCREEN: re.Pattern[str] = re.compile("|".join(_INJECTION_PATTERNS))
_RE_LINE: re.Pattern[str] = re.compile("|".join(_INJECTION_PATTERNS))

_CONFIDENCE_THRESHOLD: float = 0.70


@dataclass(frozen=True)
class SanitizedOutput:
    sanitized_output: str
    decision: SanitizerDecision
    is_error: bool
    removed_tokens_count: int
    explain_decision: Mapping[str, object]

    @property
    def reason(self) -> str:
        return str(self.explain_decision.get("reason", ""))


class ToolOutputClassifier:
    def classify(self, text: str) -> tuple[bool, float, str]:
        """Returns (is_instruction_like, confidence_0_to_1, model_id)."""
        raise NotImplementedError


def _screen_suspicious(text: str) -> bool:
    return bool(_RE_SCREEN.search(text))


def _strip_injection_lines(text: str) -> tuple[str, int]:
    lines = text.splitlines()
    kept: list[str] = []
    removed = 0
    for ln in lines:
        if _RE_LINE.search(ln):
            removed += len(ln)
        else:
            kept.append(ln)
    return "\n".join(kept).strip(), removed


def _make_explain(
    action: str,
    reason: str,
    tool_id: str,
    stage2_invoked: int,
    *,
    confidence: float = 0.0,
    classifier: str = "none",
    latency_ms: float = 0.0,
    removed: int = 0,
) -> dict[str, object]:
    d: dict[str, object] = {
        "action": action,
        "reason": reason,
        "tool_id": tool_id,
        "stage2_invoked": stage2_invoked,
        "removed_tokens_count": removed,
    }
    if classifier != "none":
        d["classifier"] = classifier
        d["confidence"] = confidence
        d["latency_ms"] = latency_ms
    return d


class ToolOutputSanitizer:
    def __init__(
        self,
        classifier: Optional[ToolOutputClassifier] = None,
        classifier_timeout_ms: float = 10.0,
        fail_secure_on_error: bool = True,
    ) -> None:
        self._classifier = classifier
        self._timeout_ms = classifier_timeout_ms
        self._fail_secure = fail_secure_on_error

    def sanitize(
        self,
        raw_output: str,
        tool_id: str = "unknown",
        *,
        stage1_signal: str = "Suspicious",
    ) -> SanitizedOutput:
        if stage1_signal == "Clean":
            return SanitizedOutput(
                sanitized_output=raw_output,
                decision=SanitizerDecision.ALLOW,
                is_error=False,
                removed_tokens_count=0,
                explain_decision=_make_explain("ALLOW", "stage1_clean", tool_id, 0),
            )

        if stage1_signal == "Confirmed":
            return SanitizedOutput(
                sanitized_output="",
                decision=SanitizerDecision.BLOCK,
                is_error=False,
                removed_tokens_count=len(raw_output),
                explain_decision=_make_explain(
                    "BLOCK",
                    "stage1_confirmed_injection",
                    tool_id,
                    0,
                    removed=len(raw_output),
                ),
            )

        if not raw_output:
            return SanitizedOutput(
                sanitized_output="",
                decision=SanitizerDecision.ALLOW,
                is_error=False,
                removed_tokens_count=0,
                explain_decision=_make_explain("ALLOW", "empty_output", tool_id, 0),
            )

        suspicious = _screen_suspicious(raw_output)
        stripped, removed = _strip_injection_lines(raw_output)

        if not suspicious:
            return SanitizedOutput(
                sanitized_output=raw_output,
                decision=SanitizerDecision.ALLOW,
                is_error=False,
                removed_tokens_count=0,
                explain_decision=_make_explain(
                    "ALLOW", "no_suspicious_patterns", tool_id, 1
                ),
            )

        if self._classifier is None:
            decision = SanitizerDecision.ALLOW if stripped else SanitizerDecision.BLOCK
            return SanitizedOutput(
                sanitized_output=stripped,
                decision=decision,
                is_error=False,
                removed_tokens_count=removed,
                explain_decision=_make_explain(
                    decision.value, "heuristic_strip_only", tool_id, 1, removed=removed
                ),
            )

        t0 = time.perf_counter()
        try:
            is_instr, conf, model_id = self._classifier.classify(raw_output)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            if elapsed_ms > self._timeout_ms:
                raise TimeoutError("classifier_timeout")

            if is_instr and conf >= _CONFIDENCE_THRESHOLD:
                return SanitizedOutput(
                    sanitized_output="",
                    decision=SanitizerDecision.BLOCK,
                    is_error=False,
                    removed_tokens_count=len(raw_output),
                    explain_decision=_make_explain(
                        "BLOCK",
                        "classified_instruction_like",
                        tool_id,
                        1,
                        confidence=conf,
                        classifier=model_id,
                        latency_ms=elapsed_ms,
                        removed=len(raw_output),
                    ),
                )

            decision = SanitizerDecision.ALLOW if stripped else SanitizerDecision.BLOCK
            return SanitizedOutput(
                sanitized_output=stripped,
                decision=decision,
                is_error=False,
                removed_tokens_count=removed,
                explain_decision=_make_explain(
                    decision.value,
                    "classified_not_instruction_like",
                    tool_id,
                    1,
                    confidence=conf,
                    classifier=model_id,
                    latency_ms=elapsed_ms,
                    removed=removed,
                ),
            )

        except Exception as exc:
            reason = f"sanitizer_error:{type(exc).__name__}"
            if self._fail_secure:
                return SanitizedOutput(
                    sanitized_output="",
                    decision=SanitizerDecision.BLOCK,
                    is_error=True,
                    removed_tokens_count=len(raw_output),
                    explain_decision=_make_explain("BLOCK", reason, tool_id, 1),
                )
            return SanitizedOutput(
                sanitized_output=stripped,
                decision=SanitizerDecision.ALLOW,
                is_error=True,
                removed_tokens_count=removed,
                explain_decision=_make_explain("ALLOW", reason, tool_id, 1),
            )
