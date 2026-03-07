# python/tests/unit/governance/test_bias_guardian.py
"""
Testes Unitários para BiasGuardian.
Valida a aplicação de políticas de segurança e exceções.
"""

import pytest
from buildtovalue.governance.bias_guardian import (
    BiasGuardian,
    check_model,
    run_safe
)
from buildtovalue.governance.exceptions import (
    SecurityViolation,
    IntegrityCheckFailed
)


# ==========================================
# FIXTURES
# ==========================================

@pytest.fixture
def strict_guardian():
    """Guardião configurado para rejeitar modelos desconhecidos."""
    return BiasGuardian(fail_on_unknown=True)


@pytest.fixture
def loose_guardian():
    """Guardião configurado para avisar sobre modelos desconhecidos."""
    return BiasGuardian(fail_on_unknown=False)


@pytest.fixture
def abliterated_model():
    return "heretic-llama-3.1-8b"


@pytest.fixture
def legitimate_model():
    return "llama-3.1-8b-instruct"


@pytest.fixture
def unknown_model():
    return "experimental-mistral-7b"


# ==========================================
# TESTES: VERIFICAÇÃO DE ELEGIBILIDADE
# ==========================================

class TestBiasGuardianEligibility:
    """Testa a lógica de elegibilidade."""

    def test_legitimate_model_allowed(self, loose_guardian, legitimate_model):
        """Modelo legítimo deve ser permitido."""
        verdict = loose_guardian.check_eligibility(legitimate_model)
        assert verdict.allowed is True
        assert "Verified legitimate" in verdict.reason

    def test_abliterated_model_blocked(self, loose_guardian, abliterated_model):
        """Modelo abliterated deve ser bloqueado com SecurityViolation."""
        with pytest.raises(SecurityViolation) as exc_info:
            loose_guardian.check_eligibility(abliterated_model)

        assert abliterated_model in str(exc_info.value)

    def test_unknown_model_warned_in_loose_mode(self, loose_guardian, unknown_model):
        """Modelo desconhecido deve ser permitido com aviso em modo loose."""
        verdict = loose_guardian.check_eligibility(unknown_model)
        assert verdict.allowed is True
        assert len(verdict.warnings) > 0
        assert "Unknown model" in verdict.warnings[0]

    def test_unknown_model_blocked_in_strict_mode(self, strict_guardian, unknown_model):
        """Modelo desconhecido deve ser bloqueado em modo strict."""
        with pytest.raises(IntegrityCheckFailed) as exc_info:
            strict_guardian.check_eligibility(unknown_model)

        assert unknown_model in str(exc_info.value)


# ==========================================
# TESTES: EXECUÇÃO SEGURA
# ==========================================

class TestSafeEvaluation:
    """Testa a função run_safe."""

    def test_safe_eval_runs_for_legitimate(self, loose_guardian, legitimate_model):
        """Deve executar a função para modelo legítimo."""
        mock_func = lambda: "result"
        result = loose_guardian.safe_evaluate(legitimate_model, mock_func)
        assert result == "result"

    def test_safe_eval_blocks_for_abliterated(self, loose_guardian, abliterated_model):
        """Deve levantar exceção antes de executar para modelo abliterated."""
        mock_func = Mock()

        with pytest.raises(SecurityViolation):
            loose_guardian.safe_evaluate(abliterated_model, mock_func)

        # Garante que a função NUNCA foi chamada
        mock_func.assert_not_called()


# ==========================================
# TESTES: API GLOBAL
# ==========================================

class TestGlobalAPI:
    """Testa os atalhos globais."""

    def test_check_model_returns_verdict(self, legitimate_model):
        verdict = check_model(legitimate_model)
        assert verdict.allowed is True

    def test_run_safe_executes_function(self, legitimate_model):
        result = run_safe(legitimate_model, lambda x: x * 2, 10)
        assert result == 20