"""
Policy Signer v1.0 - HMAC-SHA256 signing for policies.

Implementa:
- HMAC-SHA256 assinatura de políticas
- Validação de integridade
- Key rotation support
- Audit trail

Security Level: MAXIMUM
Gate: G3 (HMAC Signing Review)
"""

import hmac
import hashlib
import json
import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO
# ═══════════════════════════════════════════════════════════════════════════

HMAC_ALGORITHM = "sha256"
SIGNATURE_VERSION = "v1"
KEY_ROTATION_DAYS = 90  # Rotação a cada 90 dias


# ═══════════════════════════════════════════════════════════════════════════
# TIPOS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SigningKey:
    """Chave de assinatura."""
    key_id: str
    key_material: bytes
    created_at: int
    expires_at: int
    algorithm: str = HMAC_ALGORITHM
    version: str = SIGNATURE_VERSION

    def is_expired(self) -> bool:
        """Verifica se chave expirou."""
        return time.time() > self.expires_at

    def days_until_expiry(self) -> int:
        """Dias até expiração."""
        remaining = self.expires_at - time.time()
        return max(0, int(remaining / 86400))


@dataclass
class PolicySignature:
    """Assinatura de política."""
    policy_id: str
    signature: str
    key_id: str
    algorithm: str
    version: str
    signed_at: int
    signer: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PolicySignature':
        """Cria de dicionário."""
        return cls(**data)


@dataclass
class SignedPolicy:
    """Política assinada."""
    policy: Dict[str, Any]
    signature: PolicySignature

    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário."""
        return {
            'policy': self.policy,
            'signature': self.signature.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SignedPolicy':
        """Cria de dicionário."""
        return cls(
            policy=data['policy'],
            signature=PolicySignature.from_dict(data['signature'])
        )


# ═══════════════════════════════════════════════════════════════════════════
# EXCEÇÕES
# ═══════════════════════════════════════════════════════════════════════════

class PolicySigningError(Exception):
    """Erro base de assinatura."""
    pass


class InvalidSignatureError(PolicySigningError):
    """Assinatura inválida."""
    pass


class ExpiredKeyError(PolicySigningError):
    """Chave expirada."""
    pass


class KeyNotFoundError(PolicySigningError):
    """Chave não encontrada."""
    pass


# ═══════════════════════════════════════════════════════════════════════════
# POLICY SIGNER
# ═══════════════════════════════════════════════════════════════════════════

class PolicySigner:
    """
    Assinador de políticas com HMAC-SHA256.

    Features:
    - HMAC-SHA256 assinatura
    - Key rotation automático
    - Validação de integridade
    - Audit trail
    - Non-repudiation
    """

    def __init__(
            self,
            key_store_path: Optional[Path] = None,
            auto_rotate: bool = True,
            rotation_days: int = KEY_ROTATION_DAYS
    ):
        """
        Inicializa signer.

        Args:
            key_store_path: Path para key store (opcional)
            auto_rotate: Rotacionar chaves automaticamente
            rotation_days: Dias para rotação
        """
        self.key_store_path = key_store_path
        self.auto_rotate = auto_rotate
        self.rotation_days = rotation_days

        # Key store (em produção usar HSM ou KMS)
        self.keys: Dict[str, SigningKey] = {}
        self.active_key_id: Optional[str] = None

        # Audit trail
        self.audit_log: List[Dict[str, Any]] = []

        # Métricas
        self.metrics = {
            'signatures_created': 0,
            'validations_success': 0,
            'validations_failed': 0,
            'keys_rotated': 0,
        }

        # Carrega keys existentes
        if key_store_path and key_store_path.exists():
            self._load_keys()
        else:
            # Gera chave inicial
            self._generate_key()

    def sign_policy(
            self,
            policy: Dict[str, Any],
            signer: str = "system"
    ) -> SignedPolicy:
        """
        Assina política com HMAC-SHA256.

        Args:
            policy: Política a assinar (dict)
            signer: Identificador do assinante

        Returns:
            SignedPolicy com assinatura

        Raises:
            ExpiredKeyError: Se chave ativa expirou
        """
        # Verifica key rotation
        if self.auto_rotate:
            self._check_rotation()

        # Obtém chave ativa
        key = self._get_active_key()

        # Canonicaliza política (JSON determinístico)
        canonical = self._canonicalize(policy)

        # Calcula HMAC
        signature_bytes = hmac.new(
            key.key_material,
            canonical.encode('utf-8'),
            hashlib.sha256
        ).digest()

        # Converte para hex
        signature_hex = signature_bytes.hex()

        # Cria assinatura
        signature = PolicySignature(
            policy_id=policy.get('id', 'unknown'),
            signature=signature_hex,
            key_id=key.key_id,
            algorithm=key.algorithm,
            version=key.version,
            signed_at=int(time.time()),
            signer=signer,
            metadata={
                'policy_version': policy.get('version', '1.0'),
                'canonical_size': len(canonical)
            }
        )

        # Audit log
        self._audit('sign', {
            'policy_id': signature.policy_id,
            'key_id': key.key_id,
            'signer': signer
        })

        self.metrics['signatures_created'] += 1

        return SignedPolicy(policy=policy, signature=signature)

    def verify_policy(
            self,
            signed_policy: SignedPolicy,
            allow_expired: bool = False
    ) -> bool:
        """
        Verifica assinatura de política.

        Args:
            signed_policy: Política assinada
            allow_expired: Permitir chaves expiradas (para audit)

        Returns:
            True se assinatura válida

        Raises:
            InvalidSignatureError: Se assinatura inválida
            KeyNotFoundError: Se chave não existe
        """
        signature = signed_policy.signature
        policy = signed_policy.policy

        # Obtém chave
        try:
            key = self.keys[signature.key_id]
        except KeyError:
            self.metrics['validations_failed'] += 1
            raise KeyNotFoundError(f"Key not found: {signature.key_id}")

        # Verifica expiração
        if key.is_expired() and not allow_expired:
            self.metrics['validations_failed'] += 1
            raise ExpiredKeyError(
                f"Key expired {key.days_until_expiry()} days ago"
            )

        # Canonicaliza política
        canonical = self._canonicalize(policy)

        # Calcula HMAC esperado
        expected_signature = hmac.new(
            key.key_material,
            canonical.encode('utf-8'),
            hashlib.sha256
        ).digest().hex()

        # Compara usando constant-time
        is_valid = self._constant_time_compare(
            signature.signature,
            expected_signature
        )

        # Audit log
        self._audit('verify', {
            'policy_id': signature.policy_id,
            'key_id': signature.key_id,
            'valid': is_valid
        })

        if is_valid:
            self.metrics['validations_success'] += 1
        else:
            self.metrics['validations_failed'] += 1
            raise InvalidSignatureError("Signature verification failed")

        return is_valid

    def rotate_keys(self) -> SigningKey:
        """
        Rotaciona chaves (gera nova).

        Returns:
            Nova chave ativa
        """
        logger.info("Rotating signing keys...")

        new_key = self._generate_key()

        self.metrics['keys_rotated'] += 1

        # Audit log
        self._audit('rotate', {
            'old_key_id': self.active_key_id,
            'new_key_id': new_key.key_id
        })

        # Salva keys
        if self.key_store_path:
            self._save_keys()

        logger.info(f"Keys rotated: {new_key.key_id}")

        return new_key

    def _generate_key(self) -> SigningKey:
        """Gera nova chave de assinatura."""
        import secrets

        # Gera key material (32 bytes = 256 bits)
        key_material = secrets.token_bytes(32)

        # Gera key ID
        key_id = f"key-{int(time.time())}-{secrets.token_hex(4)}"

        # Calcula timestamps
        now = int(time.time())
        expires = now + (self.rotation_days * 86400)

        key = SigningKey(
            key_id=key_id,
            key_material=key_material,
            created_at=now,
            expires_at=expires,
            algorithm=HMAC_ALGORITHM,
            version=SIGNATURE_VERSION
        )

        # Adiciona ao store
        self.keys[key_id] = key
        self.active_key_id = key_id

        logger.info(
            f"Generated key: {key_id} "
            f"(expires in {self.rotation_days} days)"
        )

        return key

    def _get_active_key(self) -> SigningKey:
        """Obtém chave ativa."""
        if not self.active_key_id:
            raise PolicySigningError("No active key")

        key = self.keys[self.active_key_id]

        if key.is_expired():
            raise ExpiredKeyError(
                f"Active key expired {key.days_until_expiry()} days ago"
            )

        return key

    def _check_rotation(self):
        """Verifica se precisa rotacionar."""
        if not self.active_key_id:
            return

        key = self.keys[self.active_key_id]

        # Rotaciona se faltam menos de 7 dias
        if key.days_until_expiry() < 7:
            logger.warning(
                f"Key expires in {key.days_until_expiry()} days, rotating..."
            )
            self.rotate_keys()

    def _canonicalize(self, policy: Dict[str, Any]) -> str:
        """
        Canonicaliza política (JSON determinístico).

        Garante que mesma política sempre gera mesmo hash.
        """
        # JSON com keys ordenadas e sem espaços
        return json.dumps(
            policy,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True
        )

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """
        Comparação constant-time (timing attack protection).

        Args:
            a: String 1
            b: String 2

        Returns:
            True se iguais
        """
        if len(a) != len(b):
            return False

        # XOR bit-a-bit
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)

        return result == 0

    def _audit(self, action: str, details: Dict[str, Any]):
        """Registra ação no audit log."""
        entry = {
            'timestamp': time.time(),
            'action': action,
            'details': details
        }
        self.audit_log.append(entry)

        # Limita tamanho do log (últimas 1000 entradas)
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:]

    def _save_keys(self):
        """Salva keys em disco (encrypted em produção)."""
        if not self.key_store_path:
            return

        # WARNING: Em produção, keys devem ser encrypted!
        # Usar KMS (AWS KMS, GCP KMS, Azure Key Vault) ou HSM

        data = {
            'keys': {
                kid: {
                    'key_id': k.key_id,
                    'key_material': k.key_material.hex(),
                    'created_at': k.created_at,
                    'expires_at': k.expires_at,
                    'algorithm': k.algorithm,
                    'version': k.version
                }
                for kid, k in self.keys.items()
            },
            'active_key_id': self.active_key_id
        }

        with open(self.key_store_path, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Keys saved to {self.key_store_path}")

    def _load_keys(self):
        """Carrega keys de disco."""
        if not self.key_store_path or not self.key_store_path.exists():
            return

        with open(self.key_store_path, 'r') as f:
            data = json.load(f)

        for kid, k in data['keys'].items():
            self.keys[kid] = SigningKey(
                key_id=k['key_id'],
                key_material=bytes.fromhex(k['key_material']),
                created_at=k['created_at'],
                expires_at=k['expires_at'],
                algorithm=k['algorithm'],
                version=k['version']
            )

        self.active_key_id = data['active_key_id']

        logger.info(f"Loaded {len(self.keys)} keys from {self.key_store_path}")

    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas."""
        active_key = self.keys.get(self.active_key_id) if self.active_key_id else None

        return {
            **self.metrics,
            'active_key_id': self.active_key_id,
            'active_key_expires_days': (
                active_key.days_until_expiry() if active_key else None
            ),
            'total_keys': len(self.keys),
            'validation_success_rate': (
                    self.metrics['validations_success'] /
                    max(
                        self.metrics['validations_success'] +
                        self.metrics['validations_failed'],
                        1
                    )
            )
        }

    def export_audit_log(self) -> List[Dict[str, Any]]:
        """Exporta audit log."""
        return self.audit_log.copy()
