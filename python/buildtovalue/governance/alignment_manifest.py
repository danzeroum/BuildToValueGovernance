"""AlignmentManifest — Cenário 28: Aquecimento da Rã (Goal Drift Gradual).

Define e verifica "regras de ouro" imutáveis do agente que não podem ser
alteradas por aprendizado, histórico de interação ou pressão gradual de
parceiros confiáveis ("gaslighting agêntico").

Gap 5 — Mecanismo de atualização com rastreabilidade:
  - AlignmentManifest é frozen (imutável após criação)
  - revoke_and_replace() registra revogação no DurableLedger (nunca apaga)
    e cria novo objeto — cadeia auditável de versões

Invariantes:
  - Frozen dataclass: imutável após criação
  - HMAC-SHA256(canonical JSON, sort_keys=True) para autenticidade
  - Fail-secure: assinatura inválida → (False, motivo)
  - explain_decision em todas as entradas do ledger
  - Funções ≤ 50 linhas
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .durable_ledger import DurableLedger

logger = logging.getLogger("btv.governance.alignment_manifest")


@dataclass(frozen=True)
class AlignmentManifest:
    """Manifesto de regras de ouro do agente — imutável após criação.

    `signature` = HMAC-SHA256(canonical JSON de {agent_id, golden_rules, created_at}).
    """
    agent_id: str
    golden_rules: tuple           # tuple[str, ...] — imutável
    created_at: str               # UTC ISO 8601
    signature: str                # HMAC-SHA256 (Jonas)
    version: int = 1              # versão monotônica
    supersedes: Optional[str] = None  # signature do manifesto revogado


class AlignmentManifestVerifier:
    """Cria, verifica e atualiza manifestos de alinhamento de agentes."""

    def create_manifest(
        self,
        agent_id: str,
        golden_rules: List[str],
        hmac_key: bytes,
        ledger: DurableLedger,
        supersedes: Optional[str] = None,
        version: int = 1,
    ) -> AlignmentManifest:
        """Cria, assina e persiste manifesto no DurableLedger.

        Fail-secure: erro ao persistir → propaga exceção.
        """
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        rules_tuple = tuple(golden_rules)
        sig = self._sign_manifest(agent_id, rules_tuple, now_iso, hmac_key)

        manifest = AlignmentManifest(
            agent_id=agent_id,
            golden_rules=rules_tuple,
            created_at=now_iso,
            signature=sig,
            version=version,
            supersedes=supersedes,
        )

        ledger.append({
            "type": "alignment_manifest_created",
            "agent_id": agent_id,
            "signature": sig,
            "version": version,
            "supersedes": supersedes,
            "created_at_iso": now_iso,
            "explain_decision": (
                f"Manifesto v{version} criado para agente '{agent_id}' "
                f"com {len(rules_tuple)} regra(s) de ouro."
            ),
        })
        return manifest

    def verify_action(
        self,
        action_description: str,
        manifest: AlignmentManifest,
        hmac_key: bytes,
    ) -> Tuple[bool, str]:
        """Verifica se a ação respeita as regras de ouro do manifesto.

        Retorna (allowed, reason).
        Fail-secure: assinatura inválida → (False, motivo).
        """
        # Valida integridade da assinatura do manifesto
        expected_sig = self._sign_manifest(
            manifest.agent_id,
            manifest.golden_rules,
            manifest.created_at,
            hmac_key,
        )
        if not hmac_lib.compare_digest(manifest.signature, expected_sig):
            return (
                False,
                f"Manifesto adulterado — assinatura inválida para agente '{manifest.agent_id}'",
            )

        # Verifica cada regra de ouro contra a descrição da ação
        action_lower = action_description.lower()
        for rule in manifest.golden_rules:
            if _rule_violated(rule, action_lower):
                return (
                    False,
                    f"Regra de ouro violada: '{rule}' — ação '{action_description[:60]}' não permitida.",
                )

        return True, "Ação compatível com todas as regras de ouro"

    def revoke_and_replace(
        self,
        current_manifest: AlignmentManifest,
        new_rules: List[str],
        hmac_key: bytes,
        ledger: DurableLedger,
    ) -> AlignmentManifest:
        """Revoga manifesto atual e cria novo com novas regras.

        Gap 5: o manifesto anterior é preservado no ledger (nunca apagado).
        O novo objeto é imutável e referencia o signature anterior via `supersedes`.
        """
        # Persiste revogação (auditável, imutável)
        ledger.append({
            "type": "manifest_revocation",
            "revoked_signature": current_manifest.signature,
            "agent_id": current_manifest.agent_id,
            "revoked_version": current_manifest.version,
            "explain_decision": (
                f"Manifesto v{current_manifest.version} revogado pelo usuário. "
                "Versão anterior preservada no ledger para auditoria."
            ),
        })

        new_version = current_manifest.version + 1
        return self.create_manifest(
            agent_id=current_manifest.agent_id,
            golden_rules=new_rules,
            hmac_key=hmac_key,
            ledger=ledger,
            supersedes=current_manifest.signature,
            version=new_version,
        )

    def _sign_manifest(
        self,
        agent_id: str,
        golden_rules: tuple,
        created_at: str,
        hmac_key: bytes,
    ) -> str:
        canonical = json.dumps(
            {"agent_id": agent_id, "golden_rules": list(golden_rules), "created_at": created_at},
            sort_keys=True,
        ).encode()
        return hmac_lib.new(hmac_key, canonical, hashlib.sha256).hexdigest()


def _rule_violated(rule: str, action_lower: str) -> bool:
    """Verifica se a ação viola a regra.

    Heurística: se a regra contém "never_" ou "proibido_", extrai a keyword
    e verifica se está na descrição da ação.
    """
    rule_lower = rule.lower()
    if rule_lower.startswith(("never_", "proibido_", "block_", "nao_")):
        keyword = rule_lower.split("_", 1)[-1].replace("_", " ")
        return keyword in action_lower
    return False


# ---------------------------------------------------------------------------
# Testes unitários
# ---------------------------------------------------------------------------

class TestAlignmentManifest:
    """pytest: pytest -k AlignmentManifest"""

    def _make_ledger(self) -> DurableLedger:
        return DurableLedger(hmac_key=b"test-key")

    def test_create_and_verify_valid(self) -> None:
        key = b"agent-key"
        verifier = AlignmentManifestVerifier()
        ledger   = self._make_ledger()
        manifest = verifier.create_manifest(
            "agent-1", ["never_sell_long_term_assets"], key, ledger
        )
        ok, reason = verifier.verify_action(
            "Buy stock XYZ", manifest, key
        )
        assert ok, reason

    def test_rule_violation_blocked(self) -> None:
        key = b"agent-key"
        verifier = AlignmentManifestVerifier()
        ledger   = self._make_ledger()
        manifest = verifier.create_manifest(
            "agent-1", ["never_sell_long_term_assets"], key, ledger
        )
        ok, reason = verifier.verify_action(
            "Sell long term assets for gas fee", manifest, key
        )
        assert not ok
        assert "Regra de ouro violada" in reason

    def test_tampered_manifest_rejected(self) -> None:
        key = b"agent-key"
        verifier = AlignmentManifestVerifier()
        ledger   = self._make_ledger()
        manifest = verifier.create_manifest(
            "agent-1", ["never_sell_long_term_assets"], key, ledger
        )
        tampered = AlignmentManifest(
            agent_id=manifest.agent_id,
            golden_rules=("allow_everything",),  # alterado
            created_at=manifest.created_at,
            signature=manifest.signature,  # assinatura original
        )
        ok, reason = verifier.verify_action("anything", tampered, key)
        assert not ok
        assert "adulterado" in reason.lower()

    def test_revoke_and_replace_creates_new_version(self) -> None:
        key = b"agent-key"
        verifier = AlignmentManifestVerifier()
        ledger   = self._make_ledger()
        v1 = verifier.create_manifest(
            "agent-1", ["never_sell_long_term_assets"], key, ledger
        )
        v2 = verifier.revoke_and_replace(v1, ["never_transfer_reserve_funds"], key, ledger)
        assert v2.version == 2
        assert v2.supersedes == v1.signature
        assert "never_transfer_reserve_funds" in v2.golden_rules
