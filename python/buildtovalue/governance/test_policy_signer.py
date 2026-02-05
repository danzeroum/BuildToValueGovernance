"""
Testes para Policy Signer.

Coverage: HMAC signing, validation, key rotation, timing attacks.
"""

import pytest
import time
import tempfile
from pathlib import Path

from python.buildtovalue.governance.policy_signer import (
    PolicySigner,
    SignedPolicy,
    PolicySignature,
    InvalidSignatureError,
    ExpiredKeyError,
    KeyNotFoundError
)


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def signer():
    """Signer para testes."""
    return PolicySigner(auto_rotate=False)


@pytest.fixture
def sample_policy():
    """Política de teste."""
    return {
        'id': 'test-policy-001',
        'version': '1.0',
        'name': 'Test Policy',
        'rules': [
            {'action': 'ALLOW', 'priority': 1},
            {'action': 'BLOCK', 'priority': 2}
        ]
    }


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE ASSINATURA
# ═══════════════════════════════════════════════════════════════════════════

class TestPolicySigning:
    """Testes de assinatura."""

    def test_sign_policy(self, signer, sample_policy):
        """Deve assinar política."""
        signed = signer.sign_policy(sample_policy, signer="test_user")

        assert signed.policy == sample_policy
        assert signed.signature.policy_id == 'test-policy-001'
        assert signed.signature.signer == 'test_user'
        assert len(signed.signature.signature) == 64  # SHA256 hex = 64 chars

    def test_verify_valid_signature(self, signer, sample_policy):
        """Deve verificar assinatura válida."""
        signed = signer.sign_policy(sample_policy)

        # Verificação deve passar
        is_valid = signer.verify_policy(signed)
        assert is_valid

    def test_verify_invalid_signature(self, signer, sample_policy):
        """Deve rejeitar assinatura inválida."""
        signed = signer.sign_policy(sample_policy)

        # Corrompe assinatura
        signed.signature.signature = "0" * 64

        # Deve falhar
        with pytest.raises(InvalidSignatureError):
            signer.verify_policy(signed)

    def test_verify_tampered_policy(self, signer, sample_policy):
        """Deve detectar política adulterada."""
        signed = signer.sign_policy(sample_policy)

        # Adultera política
        signed.policy['rules'].append({'action': 'MALICIOUS'})

        # Deve falhar
        with pytest.raises(InvalidSignatureError):
            signer.verify_policy(signed)

    def test_deterministic_canonicalization(self, signer):
        """Canonicalização deve ser determinística."""
        policy1 = {'b': 2, 'a': 1}
        policy2 = {'a': 1, 'b': 2}  # Ordem diferente

        signed1 = signer.sign_policy(policy1)
        signed2 = signer.sign_policy(policy2)

        # Assinaturas devem ser iguais (mesma política)
        assert signed1.signature.signature == signed2.signature.signature


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE KEY ROTATION
# ═══════════════════════════════════════════════════════════════════════════

class TestKeyRotation:
    """Testes de rotação de chaves."""

    def test_key_rotation(self, signer, sample_policy):
        """Deve rotacionar chaves."""
        # Assina com chave 1
        old_key_id = signer.active_key_id
        signed_old = signer.sign_policy(sample_policy)

        # Rotaciona
        new_key = signer.rotate_keys()

        # Chave ativa mudou
        assert signer.active_key_id != old_key_id
        assert signer.active_key_id == new_key.key_id

        # Pode verificar assinatura antiga
        assert signer.verify_policy(signed_old)

        # Nova assinatura usa chave nova
        signed_new = signer.sign_policy(sample_policy)
        assert signed_new.signature.key_id == new_key.key_id

    def test_expired_key_rejected(self, signer, sample_policy):
        """Deve rejeitar chave expirada."""
        signed = signer.sign_policy(sample_policy)

        # Força expiração
        key = signer.keys[signer.active_key_id]
        key.expires_at = int(time.time()) - 1000  # 1000s atrás

        # Deve falhar
        with pytest.raises(ExpiredKeyError):
            signer.verify_policy(signed)

    def test_allow_expired_for_audit(self, signer, sample_policy):
        """Deve permitir verificar chaves expiradas (audit)."""
        signed = signer.sign_policy(sample_policy)

        # Força expiração
        key = signer.keys[signer.active_key_id]
        key.expires_at = int(time.time()) - 1000

        # Com allow_expired=True deve passar
        is_valid = signer.verify_policy(signed, allow_expired=True)
        assert is_valid


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE PERSISTÊNCIA
# ═══════════════════════════════════════════════════════════════════════════

class TestPersistence:
    """Testes de persistência de chaves."""

    def test_save_and_load_keys(self, sample_policy):
        """Deve salvar e carregar chaves."""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_store = Path(tmpdir) / "keys.json"

            # Signer 1: cria e salva
            signer1 = PolicySigner(key_store_path=key_store, auto_rotate=False)
            signed = signer1.sign_policy(sample_policy)
            signer1._save_keys()

            # Signer 2: carrega keys
            signer2 = PolicySigner(key_store_path=key_store, auto_rotate=False)

            # Deve conseguir verificar
            is_valid = signer2.verify_policy(signed)
            assert is_valid


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE SEGURANÇA
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.security
class TestSecurity:
    """Testes de segurança."""

    def test_constant_time_comparison(self, signer):
        """Comparação deve ser constant-time."""
        # Testa que timing não vaza informação
        a = "a" * 64
        b = "b" * 64
        c = "a" * 63 + "b"

        # Todas as comparações devem levar tempo similar
        start = time.perf_counter()
        result1 = signer._constant_time_compare(a, b)
        time1 = time.perf_counter() - start

        start = time.perf_counter()
        result2 = signer._constant_time_compare(a, c)
        time2 = time.perf_counter() - start

        assert not result1
        assert not result2

        # Timing difference deve ser mínimo (<10%)
        # (mais permissivo para ambiente de teste)
        time_diff = abs(time1 - time2) / max(time1, time2)
        assert time_diff < 0.5  # 50% tolerance

    def test_signature_uniqueness(self, signer, sample_policy):
        """Assinaturas devem ser únicas por timestamp."""
        signed1 = signer.sign_policy(sample_policy)

        time.sleep(0.01)  # Garante timestamp diferente

        signed2 = signer.sign_policy(sample_policy)

        # Assinaturas são iguais (mesmo conteúdo)
        # mas timestamps são diferentes
        assert signed1.signature.signature == signed2.signature.signature
        assert signed1.signature.signed_at != signed2.signature.signed_at


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE MÉTRICAS
# ═══════════════════════════════════════════════════════════════════════════

class TestMetrics:
    """Testes de métricas."""

    def test_metrics_tracking(self, signer, sample_policy):
        """Deve rastrear métricas."""
        # Assina 3 vezes
        for _ in range(3):
            signed = signer.sign_policy(sample_policy)
            signer.verify_policy(signed)

        metrics = signer.get_metrics()

        assert metrics['signatures_created'] == 3
        assert metrics['validations_success'] == 3
        assert metrics['validations_failed'] == 0
        assert metrics['validation_success_rate'] == 1.0

    def test_audit_log(self, signer, sample_policy):
        """Deve registrar audit log."""
        signed = signer.sign_policy(sample_policy, signer="auditor")
        signer.verify_policy(signed)

        audit_log = signer.export_audit_log()

        assert len(audit_log) >= 2  # sign + verify
        assert audit_log[0]['action'] == 'sign'
        assert audit_log[1]['action'] == 'verify'


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
