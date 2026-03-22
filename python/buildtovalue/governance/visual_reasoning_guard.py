"""VisualReasoningGuard — Detecção MM-Plan (ADR-053).

Detecta escalada de escopo e síntese cross-modal adversarial quando um agente
gera um plano de ação a partir de input visual. Complementa o VisualInputFirewall
(Cenário 32), que cobre apenas padrões adversariais no texto OCR.

Vetor coberto: MM-Plan ICLR 2026 — 46.3% de taxa de sucesso contra modelos frontier.

Invariantes:
- Heurística determinística: sem LLM no hot-path
- Fail-secure do guard: exceção interna → allowed=True (não penalizar por falha do guard)
- explain obrigatório (Levinas)
- Funções ≤ 50 linhas, arquivo ≤ 200 linhas
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("btv.governance.visual_reasoning_guard")

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

_DEFAULT_SCOPE_THRESHOLD = 0.5
_MIN_TASK_TOKENS = 2

# Stopwords PT + EN removidas antes da comparação de tokens
_STOPWORDS = frozenset({
    # Português
    "a", "o", "e", "de", "da", "do", "em", "um", "uma", "para", "com", "por",
    "mas", "se", "ou", "não", "que", "no", "na", "os", "as", "ao", "aos", "às",
    "é", "são", "foi", "ser", "ter", "tem", "há", "isso", "este", "esta",
    # Inglês
    "the", "an", "and", "or", "in", "on", "at", "to", "of", "for", "with",
    "is", "it", "be", "as", "by", "from", "that", "this", "not", "are", "was",
    "will", "i", "you", "we", "they", "do", "did", "has", "have", "then",
})

# Termos que indicam referência a conteúdo visual no plano gerado
_VISUAL_TERMS = frozenset({
    "imagem", "visual", "figura", "image", "figure", "foto", "photo",
    "screenshot", "captura", "picture", "pic", "tela", "screen",
})

# Tokenizador: palavras de 3+ chars
_TOKEN_RE = re.compile(r"[a-záàâãéèêíïóôõöúüçñA-ZÁÀÂÃÉÈÊÍÏÓÔÕÖÚÜÇÑ]{3,}")


# ---------------------------------------------------------------------------
# Tipos
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReasoningGuardResult:
    """Resultado da verificação de escopo do plano gerado."""
    allowed: bool
    attack_vector: Optional[str]  # "MM_PLAN_SCOPE_ESCALATION" | "CROSS_MODAL_SYNTHESIS" | None
    explain: str


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------

class VisualReasoningGuard:
    """Detecta MM-Plan: escalada de escopo e síntese cross-modal adversarial.

    Uso:
        guard = VisualReasoningGuard()
        result = guard.check_plan_scope(declared_task, generated_plan)
        if not result.allowed:
            # bloquear
    """

    def __init__(self, scope_threshold: float = _DEFAULT_SCOPE_THRESHOLD) -> None:
        self._threshold = scope_threshold

    def check_plan_scope(
        self,
        declared_task: str,
        generated_plan: str,
    ) -> ReasoningGuardResult:
        """Verifica se o plano gerado excede o escopo da tarefa declarada.

        Fail-secure do guard: qualquer exceção interna → allowed=True.
        Ausência de dados suficientes (task < MIN_TASK_TOKENS) → allowed=True.
        """
        try:
            return self._check_inner(declared_task, generated_plan)
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro interno em VisualReasoningGuard: %s", exc)
            return ReasoningGuardResult(
                allowed=True,
                attack_vector=None,
                explain=f"[visual_reasoning_guard] Erro interno ignorado (fail-open): {exc}",
            )

    def _check_inner(
        self,
        declared_task: str,
        generated_plan: str,
    ) -> ReasoningGuardResult:
        if not declared_task or not generated_plan:
            return ReasoningGuardResult(
                allowed=True,
                attack_vector=None,
                explain="[visual_reasoning_guard] Dados insuficientes — guard não acionado",
            )

        task_tokens = _normalize_tokens(declared_task)
        plan_tokens = _normalize_tokens(generated_plan)

        if len(task_tokens) < _MIN_TASK_TOKENS:
            return ReasoningGuardResult(
                allowed=True,
                attack_vector=None,
                explain=(
                    "[visual_reasoning_guard] Tarefa com tokens insuficientes "
                    f"({len(task_tokens)} < {_MIN_TASK_TOKENS}) — guard não acionado"
                ),
            )

        # Verificação 1: Cross-modal synthesis
        visual_in_plan = _VISUAL_TERMS & plan_tokens
        visual_in_task = _VISUAL_TERMS & task_tokens
        if visual_in_plan and not visual_in_task:
            return ReasoningGuardResult(
                allowed=False,
                attack_vector="CROSS_MODAL_SYNTHESIS",
                explain=(
                    f"[visual_reasoning_guard] BLOCK — CROSS_MODAL_SYNTHESIS: "
                    f"plano referencia conteúdo visual {sorted(visual_in_plan)} "
                    "ausente na tarefa declarada. Possível MM-Plan adversarial."
                ),
            )

        # Verificação 2: Scope escalation
        excess = plan_tokens - task_tokens
        scope_ratio = len(excess) / max(len(task_tokens), 1)
        if scope_ratio > self._threshold:
            return ReasoningGuardResult(
                allowed=False,
                attack_vector="MM_PLAN_SCOPE_ESCALATION",
                explain=(
                    f"[visual_reasoning_guard] BLOCK — MM_PLAN_SCOPE_ESCALATION: "
                    f"scope_ratio={scope_ratio:.2f} > threshold={self._threshold:.2f}. "
                    f"Excesso de tokens: {sorted(excess)[:10]}. "
                    "Plano excede escopo da tarefa declarada."
                ),
            )

        return ReasoningGuardResult(
            allowed=True,
            attack_vector=None,
            explain=(
                f"[visual_reasoning_guard] ALLOW — "
                f"scope_ratio={scope_ratio:.2f} ≤ threshold={self._threshold:.2f}. "
                "Nenhum padrão MM-Plan detectado."
            ),
        )


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------

def _normalize_tokens(text: str) -> frozenset[str]:
    """Extrai tokens normalizados (lower, ≥3 chars, sem stopwords)."""
    raw = _TOKEN_RE.findall(text.lower())
    return frozenset(t for t in raw if t not in _STOPWORDS)
