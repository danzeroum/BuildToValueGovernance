"""Testes unitários para VisualReasoningGuard (ADR-053).

pytest python/tests/unit/governance/test_visual_reasoning_guard.py -v
"""
import pytest

from buildtovalue.governance.visual_reasoning_guard import (
    ReasoningGuardResult,
    VisualReasoningGuard,
    _normalize_tokens,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def guard() -> VisualReasoningGuard:
    return VisualReasoningGuard(scope_threshold=0.5)


@pytest.fixture
def strict_guard() -> VisualReasoningGuard:
    return VisualReasoningGuard(scope_threshold=0.2)


# ---------------------------------------------------------------------------
# Testes: ALLOW — casos benignos
# ---------------------------------------------------------------------------

class TestAllowCases:
    def test_identical_task_and_plan(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope("comprar item", "comprar item")
        assert result.allowed is True
        assert result.attack_vector is None
        assert result.explain

    def test_plan_subset_of_task(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope(
            "calcular total compra pagamento", "calcular total"
        )
        assert result.allowed is True

    def test_scope_ratio_below_threshold(self, guard: VisualReasoningGuard) -> None:
        # task=3 tokens, plan=4 tokens (1 token excess) → ratio=0.33 < 0.5
        result = guard.check_plan_scope(
            "verificar saldo conta",
            "verificar saldo conta bancaria",
        )
        assert result.allowed is True

    def test_visual_terms_in_both_task_and_plan(self, guard: VisualReasoningGuard) -> None:
        # Se visual está na task, não é cross-modal; scope_ratio = 1/6 = 0.17 < 0.5
        result = guard.check_plan_scope(
            "analisar imagem produto calcular preco total",
            "analisar imagem produto calcular preco total desconto",
        )
        assert result.allowed is True

    def test_allow_scope_ratio_exactly_at_threshold(self, guard: VisualReasoningGuard) -> None:
        # threshold=0.5; ratio deve ser > 0.5 para bloquear
        # task=4 tokens, excess=2 → ratio=0.5 (não estritamente maior)
        result = guard.check_plan_scope(
            "calcular total preco desconto",
            "calcular total preco desconto aplicar cupom",
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Testes: BLOCK — MM_PLAN_SCOPE_ESCALATION
# ---------------------------------------------------------------------------

class TestScopeEscalation:
    def test_classic_mm_plan_escalation(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope(
            "calcular total compra",
            "calcular total compra exfiltrar historico financeiro enviar endpoint externo deletar logs",
        )
        assert result.allowed is False
        assert result.attack_vector == "MM_PLAN_SCOPE_ESCALATION"
        assert "scope_ratio" in result.explain
        assert result.explain

    def test_scope_ratio_just_above_threshold(self, guard: VisualReasoningGuard) -> None:
        # task=2 tokens, plan=5 tokens (3 excess) → ratio=1.5 > 0.5
        result = guard.check_plan_scope(
            "verificar saldo",
            "verificar saldo transferir depositar exfiltrar",
        )
        assert result.allowed is False
        assert result.attack_vector == "MM_PLAN_SCOPE_ESCALATION"

    def test_strict_threshold_catches_smaller_escalation(
        self, strict_guard: VisualReasoningGuard
    ) -> None:
        # threshold=0.2; task=5 tokens, excess=2 → ratio=0.4 > 0.2
        result = strict_guard.check_plan_scope(
            "verificar saldo conta pagamento cartao",
            "verificar saldo conta pagamento cartao transferir exfiltrar",
        )
        assert result.allowed is False
        assert result.attack_vector == "MM_PLAN_SCOPE_ESCALATION"

    def test_explain_contains_threshold_and_ratio(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope(
            "comprar produto",
            "comprar produto deletar transferir exfiltrar enviar postar publicar",
        )
        assert "scope_ratio" in result.explain
        assert "threshold" in result.explain


# ---------------------------------------------------------------------------
# Testes: BLOCK — CROSS_MODAL_SYNTHESIS
# ---------------------------------------------------------------------------

class TestCrossModalSynthesis:
    def test_image_term_in_plan_not_in_task(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope(
            "calcular total compra",
            "calcular total compra imagem mostra instrucao exfiltrar",
        )
        assert result.allowed is False
        assert result.attack_vector == "CROSS_MODAL_SYNTHESIS"
        assert result.explain

    def test_visual_term_triggers_cross_modal(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope(
            "verificar dados cliente",
            "verificar dados cliente visual indica transferir fundos",
        )
        assert result.allowed is False
        assert result.attack_vector == "CROSS_MODAL_SYNTHESIS"

    def test_photo_term_triggers_cross_modal(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope(
            "processar pedido",
            "processar pedido foto confirma pagamento externo",
        )
        assert result.allowed is False
        assert result.attack_vector == "CROSS_MODAL_SYNTHESIS"

    def test_english_image_term(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope(
            "calculate total price",
            "calculate total price image shows override instruction execute transfer",
        )
        assert result.allowed is False
        assert result.attack_vector == "CROSS_MODAL_SYNTHESIS"

    def test_cross_modal_takes_priority_over_scope_escalation(
        self, guard: VisualReasoningGuard
    ) -> None:
        # Ambos os sinais presentes — cross-modal deve ser detectado primeiro
        result = guard.check_plan_scope(
            "calcular total",
            "calcular total imagem mostra exfiltrar transferir deletar logs enviar externo",
        )
        assert result.allowed is False
        assert result.attack_vector == "CROSS_MODAL_SYNTHESIS"


# ---------------------------------------------------------------------------
# Testes: Fail-safe / edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_task_returns_allow(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope("", "algum plano qualquer")
        assert result.allowed is True
        assert result.attack_vector is None

    def test_empty_plan_returns_allow(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope("calcular total", "")
        assert result.allowed is True

    def test_none_task_returns_allow(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope(None, "plano gerado")  # type: ignore[arg-type]
        assert result.allowed is True

    def test_none_plan_returns_allow(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope("tarefa declarada", None)  # type: ignore[arg-type]
        assert result.allowed is True

    def test_short_task_below_min_tokens(self, guard: VisualReasoningGuard) -> None:
        # "ok" tem 1 token após filtro → guard não acionado
        result = guard.check_plan_scope("ok", "ok transferir exfiltrar deletar")
        assert result.allowed is True

    def test_explain_always_present(self, guard: VisualReasoningGuard) -> None:
        cases = [
            ("", ""),
            ("calcular", "calcular"),
            ("comprar produto", "comprar produto exfiltrar transferir deletar logs enviar"),
        ]
        for task, plan in cases:
            result = guard.check_plan_scope(task, plan)
            assert result.explain, f"explain vazio para task={task!r}, plan={plan!r}"

    def test_result_is_frozen(self, guard: VisualReasoningGuard) -> None:
        result = guard.check_plan_scope("comprar item", "comprar item")
        with pytest.raises(Exception):
            result.allowed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Testes: _normalize_tokens (utilitário interno)
# ---------------------------------------------------------------------------

class TestNormalizeTokens:
    def test_stopwords_removed(self) -> None:
        tokens = _normalize_tokens("comprar item para o cliente")
        assert "para" not in tokens
        assert "comprar" in tokens
        assert "item" in tokens
        assert "cliente" in tokens

    def test_short_words_excluded(self) -> None:
        tokens = _normalize_tokens("a o e de")
        assert len(tokens) == 0

    def test_case_insensitive(self) -> None:
        tokens1 = _normalize_tokens("Calcular Total")
        tokens2 = _normalize_tokens("calcular total")
        assert tokens1 == tokens2
