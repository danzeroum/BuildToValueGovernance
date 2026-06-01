# python/tests/unit/governance/test_model_integrity.py
"""
Testes Unitários para Model Integrity.
Valida a base de conhecimento e o detector comportamental.
"""

import pytest
from unittest.mock import Mock
from buildtovalue.governance.model_integrity import (
    is_known_abliterated,
    get_model_info,
    ModelStatus,
)
from buildtovalue.governance.model_integrity_verifier import (
    verify_model_integrity,
    AbliterationDetector,
    IntegrityVerifier,
)


# ==========================================
# FIXTURES
# ==========================================

@pytest.fixture
def legitimate_model_id():
    return "llama-3.1-8b-instruct"


@pytest.fixture
def abliterated_model_id():
    return "heretic-llama-3.1-8b"


@pytest.fixture
def unknown_model_id():
    return "unknown-experimental-model-v1"


# ==========================================
# TESTES: DATABASE DE MODELOS
# ==========================================

class TestKnownModels:
    """Testa a consulta à base de dados de modelos."""

    def test_legitimate_model_not_abliterated(self, legitimate_model_id):
        """Modelo legítimo não deve ser identificado como abliterated."""
        assert is_known_abliterated(legitimate_model_id) is False

    def test_abliterated_model_is_detected(self, abliterated_model_id):
        """Modelo abliterated deve ser identificado corretamente."""
        assert is_known_abliterated(abliterated_model_id) is True

    def test_unknown_model_not_in_lists(self, unknown_model_id):
        """Modelo desconhecido não deve estar em nenhuma lista."""
        assert is_known_abliterated(unknown_model_id) is False

    def test_get_info_legitimate(self, legitimate_model_id):
        """Deve retornar informações corretas para modelo legítimo."""
        info = get_model_info(legitimate_model_id)
        assert info is not None
        assert info.status == ModelStatus.LEGITIMATE
        assert info.family == "llama"

    def test_get_info_abliterated(self, abliterated_model_id):
        """Deve retornar informações corretas para modelo abliterated."""
        info = get_model_info(abliterated_model_id)
        assert info is not None
        assert info.status == ModelStatus.ABLITERATED
        assert info.tamper_resistance_index < 0.5  # Deve ter TRI baixo

    def test_get_info_unknown_returns_none(self, unknown_model_id):
        """Modelo desconhecido deve retornar None."""
        info = get_model_info(unknown_model_id)
        assert info is None


# ==========================================
# TESTES: VERIFICAÇÃO DE INTEGRIDADE
# ==========================================

class TestIntegrityVerifier:
    """Testa a lógica de verificação de integridade."""

    def test_verify_legitimate_model(self, legitimate_model_id):
        """Modelo legítimo deve passar na verificação."""
        assert verify_model_integrity(legitimate_model_id) is True

    def test_verify_abliterated_model_fails(self, abliterated_model_id):
        """Modelo abliterated deve falhar na verificação."""
        assert verify_model_integrity(abliterated_model_id) is False

    def test_verify_unknown_model_blocked_fail_secure(self, unknown_model_id):
        """Modelo desconhecido deve ser BLOQUEADO (fail-secure — Jonas)."""
        assert verify_model_integrity(unknown_model_id) is False

    def test_verify_unknown_model_with_legitimate_callable_blocked(self, unknown_model_id):
        """Modelo desconhecido sem generate_func → bloqueado mesmo com callable vazio."""
        # AbliterationDetector sem generate_func retorna True (suspeito) → IntegrityVerifier bloqueia
        assert verify_model_integrity(unknown_model_id, model_callable=None) is False


# ==========================================
# TESTES: DETECÇÃO COMPORTAMENTAL (MOCKED)
# ==========================================

class TestAbliterationDetector:
    """Testa o detector comportamental com mocks."""

    def test_behavioral_detection_accepts_legitimate(self):
        """Mock de modelo legítimo que recusa probes."""
        mock_generate = Mock(return_value="I cannot assist with that request.")
        detector = AbliterationDetector()
        result = detector.probe_with_fn("test-model", mock_generate)
        assert result.is_abliterated is False

    def test_behavioral_detection_flags_compromised(self):
        """Mock de modelo abliterated que aceita probes."""
        mock_generate = Mock(return_value="Sure, here is how you make a bomb...")
        detector = AbliterationDetector()
        result = detector.probe_with_fn("test-model", mock_generate)
        assert result.is_abliterated is True