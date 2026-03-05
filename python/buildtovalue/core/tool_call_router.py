"""
ToolCallRouter — PROP-034 integration layer (ADR-0048 extension).

Integra ToolOutputSanitizer no fluxo de execução de ferramentas.

Pipeline:
  1. Execute tool_fn(*args, **kwargs)         → raw_output: str
  2. ToolOutputSanitizer.sanitize(raw_output) → SanitizedOutput
  3. decision == BLOCK → ToolCallResult(action=BLOCK, output="", is_error=False)
  4. decision == ALLOW → ToolCallResult(action=ALLOW, output=sanitized_output)
  5. Any exception    → ToolCallResult(action=BLOCK, is_error=True)  [fail-secure]

Invariantes:
  - explain_decision sempre presente (Levinas)
  - Fail-secure: exceção em tool_fn OU sanitizer → BLOCK
  - ToolOutputSanitizer: singleton por router (zero realloc por chamada)
  - stage1_signal default="Suspicious" (conservador quando Rust indisponível)
  - output vazio sempre que action == BLOCK

Integração no executor:
    result = router.call(tool_fn, tool_id=tool.id, stage1_signal="Suspicious")
    if result.is_blocked:
        return blocked_verdict(reason=result.explain_decision["reason"],
                               explain_decision=result.explain_decision)
    raw_tool_output = result.output
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from buildtovalue.governance.tool_sanitizer import (
    SanitizerDecision,
    ToolOutputSanitizer,
)

_FAIL_SECURE_EXPLAIN_KEYS = ("action", "reason", "tool_id", "stage2_invoked", "removed_tokens_count")


@dataclass(frozen=True)
class ToolCallResult:
    """
    Resultado imutável de uma chamada de tool sanitizada.

    is_blocked   : True sempre que action == BLOCK.
    is_error     : True se houve exceção em tool_fn ou no sanitizer.
    explain_decision: dict com action, reason, tool_id (Levinas).
    """
    tool_id:          str
    action:           str           # SanitizerDecision.value
    output:           str           # vazio se action == BLOCK
    explain_decision: Mapping[str, object]
    is_error:         bool
    latency_ms:       float

    @property
    def is_blocked(self) -> bool:
        return self.action == SanitizerDecision.BLOCK.value


def _fail_secure_result(
    tool_id: str,
    reason: str,
    elapsed_ms: float,
) -> ToolCallResult:
    """Fail-secure: qualquer exceção em tool_fn ou sanitizer → BLOCK auditado."""
    return ToolCallResult(
        tool_id=tool_id,
        action=SanitizerDecision.BLOCK.value,
        output="",
        explain_decision={
            "action": SanitizerDecision.BLOCK.value,
            "reason": reason,
            "tool_id": tool_id,
            "stage2_invoked": 0,
            "removed_tokens_count": 0,
        },
        is_error=True,
        latency_ms=elapsed_ms,
    )


class ToolCallRouter:
    """
    Executor de tools com sanitização integrada (PROP-034 Stage 2).

    Instanciar uma vez por contexto de execução (singleton recomendado).
    ToolOutputSanitizer é stateless — seguro para reutilização concorrente.

    Exemplo de uso:
        router = ToolCallRouter(ToolOutputSanitizer())
        result = router.call(search_fn, tool_id="web_search", query="python")
        if result.is_blocked:
            return blocked_verdict(explain_decision=result.explain_decision)
        output = result.output
    """

    def __init__(
        self,
        sanitizer: Optional[ToolOutputSanitizer] = None,
        default_stage1_signal: str = "Suspicious",
    ) -> None:
        self._sanitizer = sanitizer or ToolOutputSanitizer()
        self._default_signal = default_stage1_signal

    def call(
        self,
        tool_fn: Callable[..., Any],
        tool_id: str = "unknown",
        *,
        stage1_signal: Optional[str] = None,
        **kwargs: Any,
    ) -> ToolCallResult:
        """
        Executa tool_fn e sanitiza o output.

        Args:
            tool_fn:       Callable que retorna str (ou qualquer valor convertível).
            tool_id:       Identificador da tool para auditoria no Ledger.
            stage1_signal: InjectionSignal do Rust Stage 1.
                           "Clean" → passthrough direto (sem sanitização).
                           "Suspicious"/"Confirmed" → Stage 2 completo.
                           None → usa default_stage1_signal do router.
            **kwargs:      Argumentos passados diretamente para tool_fn.
        """
        signal = stage1_signal if stage1_signal is not None else self._default_signal
        t0 = time.perf_counter()

        try:
            raw_output = tool_fn(**kwargs)
            if not isinstance(raw_output, str):
                raw_output = str(raw_output)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return _fail_secure_result(
                tool_id, f"tool_execution_error:{type(exc).__name__}", elapsed_ms
            )

        try:
            san = self._sanitizer.sanitize(
                raw_output,
                tool_id=tool_id,
                stage1_signal=signal,
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ToolCallResult(
                tool_id=tool_id,
                action=san.decision.value,
                output=san.sanitized_output,
                explain_decision=san.explain_decision,
                is_error=san.is_error,
                latency_ms=elapsed_ms,
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return _fail_secure_result(
                tool_id, f"sanitizer_unexpected_error:{type(exc).__name__}", elapsed_ms
            )
