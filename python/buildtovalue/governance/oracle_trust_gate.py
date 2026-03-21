"""OracleTrustGate — Cenário 34: O Boato Digital (Contaminação P2P).

Valida claims críticos contra oráculos regulatórios oficiais, impedindo que
o agente aja com base em boatos propagados por outros agentes pessoais.

Design (invariante BTV): o BTV NÃO faz I/O de rede.
O agente obtém a resposta do oráculo externamente e submete ao BTV para
verificação de assinatura HMAC e registro no DurableLedger.

Gap 3 — Registro e revogação de chaves de oráculos:
  OracleRegistry mapeia oracle_id → (hmac_key, valid_until, revoked).
  Novas rotas API: POST /v1/oracles/{id}/register e POST /v1/oracles/{id}/revoke.

Invariantes:
  - Fail-secure: HMAC inválido, oráculo revogado ou expirado → verified=False
  - explain_decision obrigatório em OracleVerdict
  - Funções ≤ 50 linhas
"""
from __future__ import annotations

import hashlib
import hmac as hmac_lib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from .durable_ledger import DurableLedger

logger = logging.getLogger("btv.governance.oracle_trust_gate")

# Trigger sources que requerem verificação de oráculo para transferências
_P2P_TRIGGERS = frozenset({"peer_agent", "agent_broadcast", "social_consensus"})


@dataclass(frozen=True)
class OracleEntry:
    """Entrada do registry de oráculos regulatórios."""
    oracle_id: str
    hmac_key: bytes
    valid_until: datetime
    revoked: bool = False

    def is_valid(self) -> bool:
        """Retorna True se o oráculo não foi revogado e não expirou."""
        if self.revoked:
            return False
        return datetime.now(timezone.utc) <= self.valid_until


class OracleRegistry:
    """Registry de chaves HMAC de oráculos regulatórios.

    Análogo ao CapabilityRegistry existente: mapeia oracle_id → OracleEntry.
    Suporta revogação com rastreabilidade via DurableLedger (Gap 3).
    """

    def __init__(self) -> None:
        self._entries: Dict[str, OracleEntry] = {}

    def register(self, entry: OracleEntry) -> None:
        """Registra ou atualiza um oráculo."""
        self._entries[entry.oracle_id] = entry

    def get(self, oracle_id: str) -> Optional[OracleEntry]:
        """Retorna a entrada do oráculo ou None se ausente."""
        return self._entries.get(oracle_id)

    def revoke(self, oracle_id: str, ledger: DurableLedger) -> None:
        """Marca oráculo como revogado e persiste rastreabilidade no ledger.

        Fail-secure: oráculo ausente → sem erro (idempotente).
        """
        entry = self._entries.get(oracle_id)
        if entry is None:
            return

        revoked_entry = OracleEntry(
            oracle_id=entry.oracle_id,
            hmac_key=entry.hmac_key,
            valid_until=entry.valid_until,
            revoked=True,
        )
        self._entries[oracle_id] = revoked_entry

        ledger.append({
            "type": "oracle_revocation",
            "oracle_id": oracle_id,
            "revoked_at_iso": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "explain_decision": (
                f"Oráculo '{oracle_id}' revogado. Chave HMAC invalidada."
            ),
        })
        logger.info("Oráculo revogado: %s", oracle_id)


@dataclass(frozen=True)
class OracleVerdict:
    """Resultado da verificação de um claim contra um oráculo regulatório."""
    claim: str
    verified: bool
    oracle_id: str
    confidence: float       # 0.0 – 1.0
    hmac_signature: str     # assinatura HMAC fornecida pelo oráculo
    explain_decision: str   # obrigatório (Levinas)


class OracleTrustGate:
    """Verifica claims contra oráculos regulatórios via HMAC.

    Uso:
        gate = OracleTrustGate(registry)
        verdict = gate.verify_and_record(
            claim="banco_y_solvente",
            oracle_id="bacen_api_v1",
            oracle_response={"solvente": True, "confidence": 0.99},
            oracle_hmac_key=bacen_key,
            ledger=ledger,
        )
        blocked, reason = gate.is_action_blocked("peer_agent", "Irreversible", verdict)
    """

    def __init__(self, registry: OracleRegistry) -> None:
        self._registry = registry

    def verify_and_record(
        self,
        claim: str,
        oracle_id: str,
        oracle_response: dict,
        oracle_hmac_key: bytes,
        ledger: DurableLedger,
    ) -> OracleVerdict:
        """Verifica HMAC da resposta do oráculo e registra no ledger.

        Fail-secure: falha de HMAC, oráculo revogado/expirado → verified=False.
        """
        try:
            return self._verify_inner(
                claim, oracle_id, oracle_response, oracle_hmac_key, ledger
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Erro em OracleTrustGate.verify_and_record: %s", exc)
            return OracleVerdict(
                claim=claim, verified=False, oracle_id=oracle_id,
                confidence=0.0, hmac_signature="",
                explain_decision=f"Erro interno na verificação: {exc}. BLOCK fail-secure.",
            )

    def _verify_inner(
        self,
        claim: str,
        oracle_id: str,
        oracle_response: dict,
        oracle_hmac_key: bytes,
        ledger: DurableLedger,
    ) -> OracleVerdict:
        """Lógica de verificação HMAC."""
        # Valida que o oráculo está registrado e não revogado
        entry = self._registry.get(oracle_id)
        if entry is None or not entry.is_valid():
            return self._unverified(claim, oracle_id, "Oráculo ausente, revogado ou expirado")

        # Extrai assinatura fornecida pelo oráculo na resposta
        provided_sig = oracle_response.get("hmac_signature", "")
        if not provided_sig:
            return self._unverified(claim, oracle_id, "Assinatura HMAC ausente na resposta")

        # Reconstrói payload canônico para verificação
        payload_for_hmac = {k: v for k, v in oracle_response.items() if k != "hmac_signature"}
        canonical = json.dumps(payload_for_hmac, sort_keys=True).encode()
        expected_sig = hmac_lib.new(oracle_hmac_key, canonical, hashlib.sha256).hexdigest()

        if not hmac_lib.compare_digest(provided_sig, expected_sig):
            return self._unverified(claim, oracle_id, "HMAC inválido — resposta possivelmente adulterada")

        confidence = float(oracle_response.get("confidence", 0.5))
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        explain = (
            f"Claim '{claim}' verificado pelo oráculo '{oracle_id}' "
            f"(confidence={confidence:.2f}) em {now_iso}."
        )

        ledger.append({
            "type": "oracle_verification",
            "claim": claim,
            "oracle_id": oracle_id,
            "verified": True,
            "confidence": confidence,
            "verified_at_iso": now_iso,
            "explain_decision": explain,
        })

        return OracleVerdict(
            claim=claim, verified=True, oracle_id=oracle_id,
            confidence=confidence, hmac_signature=provided_sig,
            explain_decision=explain,
        )

    def is_action_blocked(
        self,
        trigger_source: str,
        action_impact: str,
        oracle_verdict: Optional[OracleVerdict],
    ) -> Tuple[bool, str]:
        """Decide se ação deve ser bloqueada conforme política P2P.

        Regra: transferência financeira de peer_agent sem verificação → BLOCK.
        """
        is_p2p = trigger_source in _P2P_TRIGGERS
        is_financial = action_impact in ("Irreversible", "IRREVERSIBLE", "financial_transfer")

        if is_p2p and is_financial:
            if oracle_verdict is None or not oracle_verdict.verified:
                reason = (
                    f"Transferência financeira de '{trigger_source}' sem "
                    "verificação de oráculo regulatório — BLOCK (Cenário 34)."
                )
                return True, reason

        return False, "Ação permitida"

    def _unverified(self, claim: str, oracle_id: str, reason: str) -> OracleVerdict:
        logger.warning("OracleTrustGate UNVERIFIED: oracle=%s reason=%s", oracle_id, reason)
        return OracleVerdict(
            claim=claim, verified=False, oracle_id=oracle_id,
            confidence=0.0, hmac_signature="",
            explain_decision=f"[oracle_trust_gate] {reason}",
        )


# ---------------------------------------------------------------------------
# Testes unitários
# ---------------------------------------------------------------------------

class TestOracleTrustGate:
    """pytest: pytest -k OracleTrustGate"""

    def _make_ledger(self) -> DurableLedger:
        return DurableLedger(hmac_key=b"test-key")

    def _make_registry(self, oracle_id: str, key: bytes) -> OracleRegistry:
        from datetime import timedelta
        reg = OracleRegistry()
        reg.register(OracleEntry(
            oracle_id=oracle_id,
            hmac_key=key,
            valid_until=datetime.now(timezone.utc) + timedelta(days=365),
        ))
        return reg

    def test_valid_hmac_verified(self) -> None:
        key = b"bacen-secret-key"
        reg = self._make_registry("bacen_api_v1", key)
        gate = OracleTrustGate(reg)
        ledger = self._make_ledger()

        payload = {"solvente": True, "confidence": 0.99}
        canonical = json.dumps(payload, sort_keys=True).encode()
        sig = hmac_lib.new(key, canonical, hashlib.sha256).hexdigest()

        oracle_response = {**payload, "hmac_signature": sig}
        verdict = gate.verify_and_record(
            "banco_y_solvente", "bacen_api_v1", oracle_response, key, ledger
        )
        assert verdict.verified
        assert verdict.confidence == 0.99

    def test_invalid_hmac_unverified(self) -> None:
        key = b"bacen-secret-key"
        reg = self._make_registry("bacen_api_v1", key)
        gate = OracleTrustGate(reg)
        ledger = self._make_ledger()

        oracle_response = {"solvente": True, "confidence": 0.99, "hmac_signature": "bad_sig"}
        verdict = gate.verify_and_record(
            "banco_y_solvente", "bacen_api_v1", oracle_response, key, ledger
        )
        assert not verdict.verified

    def test_p2p_financial_without_oracle_blocked(self) -> None:
        reg = OracleRegistry()
        gate = OracleTrustGate(reg)
        blocked, reason = gate.is_action_blocked("peer_agent", "Irreversible", None)
        assert blocked
        assert "oráculo" in reason.lower()

    def test_user_direct_financial_allowed(self) -> None:
        reg = OracleRegistry()
        gate = OracleTrustGate(reg)
        blocked, _ = gate.is_action_blocked("user_direct", "Irreversible", None)
        assert not blocked

    def test_revoke_oracle_fails_verification(self) -> None:
        key = b"bacen-key"
        reg = self._make_registry("bacen_api_v1", key)
        ledger = self._make_ledger()
        reg.revoke("bacen_api_v1", ledger)

        gate = OracleTrustGate(reg)
        payload = {"solvente": True, "confidence": 0.99}
        canonical = json.dumps(payload, sort_keys=True).encode()
        sig = hmac_lib.new(key, canonical, hashlib.sha256).hexdigest()
        oracle_response = {**payload, "hmac_signature": sig}

        verdict = gate.verify_and_record(
            "banco_y", "bacen_api_v1", oracle_response, key, ledger
        )
        assert not verdict.verified
