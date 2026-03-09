# python/tests/unit/governance/test_bias_guardian.py
"""
Testes Unitarios para BiasGuardian.
Valida a aplicacao de politicas de seguranca e excecoes.
"""

import pytest
from unittest.mock import Mock
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
    return BiasGuardian(fail_on_unknown=True)


@pytest.fixture
def loose_guardian():
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
# TESTES: VERIFICACAO DE ELEGIBILIDADE
# ==========================================

class TestBiasGuardianEligibility:

    def test_legitimate_model_allowed(self, loose_guardian, legitimate_model):
        verdict = loose_guardian.check_eligibility(legitimate_model)
        assert verdict.allowed is True
        assert "Verified legitimate" in verdict.reason

    def test_abliterated_model_blocked(self, loose_guardian, abliterated_model):
        with pytest.raises(SecurityViolation) as exc_info:
            loose_guardian.check_eligibility(abliterated_model)
        assert abliterated_model in str(exc_info.value)

    def test_unknown_model_warned_in_loose_mode(self, loose_guardian, unknown_model):
        """Modelo desconhecido deve ser permitido com aviso em modo loose."""
        verdict = loose_guardian.check_eligibility(unknown_model)
        assert verdict.allowed is True
        assert len(verdict.warnings) > 0
        # Mensagem atual (v1.1+): 'Model not in trusted registry.'
        assert "trusted registry" in verdict.warnings[0]

    def test_unknown_model_blocked_in_strict_mode(self, strict_guardian, unknown_model):
        with pytest.raises(IntegrityCheckFailed) as exc_info:
            strict_guardian.check_eligibility(unknown_model)
        assert unknown_model in str(exc_info.value)


# ==========================================
# TESTES: EXECUCAO SEGURA
# ==========================================

class TestSafeEvaluation:

    def test_safe_eval_runs_for_legitimate(self, loose_guardian, legitimate_model):
        mock_func = lambda: "result"
        result = loose_guardian.safe_evaluate(legitimate_model, mock_func)
        assert result == "result"

    def test_safe_eval_blocks_for_abliterated(self, loose_guardian, abliterated_model):
        """Deve levantar excecao antes de executar para modelo abliterated."""
        mock_func = Mock()
        with pytest.raises(SecurityViolation):
            loose_guardian.safe_evaluate(abliterated_model, mock_func)
        mock_func.assert_not_called()


# ==========================================
# TESTES: API GLOBAL
# ==========================================

class TestGlobalAPI:

    def test_check_model_returns_verdict(self, legitimate_model):
        verdict = check_model(legitimate_model)
        assert verdict.allowed is True

    def test_run_safe_executes_function(self, legitimate_model):
        result = run_safe(legitimate_model, lambda x: x * 2, 10)
        assert result == 20
