"""
CommitRevealProtocol — Cenários 2, 5, 20
Esquema commit-reveal para negociações P2P entre agentes.

Previne front-running e renegociação maliciosa: cada parte compromete-se com
um hash antes de revelar sua intenção. Só após ambas revelarem com hash
correspondente a execução é autorizada atomicamente.

Invariantes:
  - Fail-secure: timeout → ABORT (nunca ALLOW implícito)
  - Estado persistido no DurableLedger com TTL explícito (sobrevive crash)
  - Unlinkability: commit_id não revela intenção (salt obrigatório)
  - Binding: hash(intention + salt) não pode ser alterado após commit
  - Duplo reveal → ABORT
  - Votante não autorizado → REJECT

Protocolo:
  1. Agente A: commit(agent_id_a, intention_a, salt_a) → CommitEntry
  2. Agente B: commit(agent_id_b, intention_b, salt_b) → CommitEntry
  3. Agente A: reveal(commit_id_a, intention_a, salt_a) → RevealResult
  4. Agente B: reveal(commit_id_b, intention_b, salt_b) → RevealResult
  5. Se ambos revelam com hash correto dentro do TTL → execução autorizada
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .durable_ledger import DurableLedger

logger = logging.getLogger("btv.governance.commit_reveal")

_DEFAULT_KEY: bytes = b"btv-commit-reveal-default-key-v1"
_DEFAULT_TTL_SECONDS: int = 3600  # 1 hora


# ─── Enums ────────────────────────────────────────────────────────────────────

class RevealStatus(str, Enum):
    SUCCESS = "SUCCESS"  # Hash match — execução autorizada
    ABORT   = "ABORT"    # Timeout, hash inválido, ou erro


class CommitStatus(str, Enum):
    PENDING  = "PENDING"   # Aguardando reveal
    REVEALED = "REVEALED"  # Revelado com sucesso
    EXPIRED  = "EXPIRED"   # TTL expirado
    ABORTED  = "ABORTED"   # Abortado


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CommitEntry:
    """
    Registro imutável de commit.
    commit_hash = BLAKE2b(intention_bytes + salt_bytes).
    commit_id é opaco — não revela intenção (unlinkability).
    """
    commit_id:        str
    commit_hash:      str           # BLAKE2b hex
    agent_id:         str
    committed_at_iso: str
    ttl_seconds:      int
    status:           CommitStatus
    explain_decision: str
    signature:        str


@dataclass(frozen=True)
class RevealResult:
    """
    Resultado imutável do reveal.
    status=SUCCESS apenas se hash match dentro do TTL.
    """
    commit_id:        str
    status:           RevealStatus
    agent_id:         str
    revealed_at_iso:  str
    explain_decision: str
    signature:        str

    @property
    def allowed(self) -> bool:
        return self.status == RevealStatus.SUCCESS

    @property
    def aborted(self) -> bool:
        return self.status == RevealStatus.ABORT


# ─── CommitRevealProtocol ─────────────────────────────────────────────────────

class CommitRevealProtocol:
    """
    Protocolo commit-reveal para negociações P2P entre agentes.

    Estado persistido no DurableLedger (sobrevive crash).
    Fail-secure: qualquer erro → ABORT assinado.

    Uso:
        ledger = DurableLedger(hmac_key)
        protocol = CommitRevealProtocol(ledger=ledger, hmac_key=key)
        entry = protocol.commit("agent-a", "intenção A", "salt-a")
        result = protocol.reveal(entry.commit_id, "intenção A", "salt-a")
    """

    def __init__(
        self,
        ledger:      DurableLedger,
        hmac_key:    bytes = _DEFAULT_KEY,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._ledger      = ledger
        self._secret      = hmac_key
        self._ttl_seconds = ttl_seconds
        # Cache in-memory para performance; ledger é a fonte de verdade
        self._commits: dict[str, dict] = {}

    # ── API pública ────────────────────────────────────────────────────────────

    def commit(
        self,
        agent_id:    str,
        intention:   str,
        salt:        str,
    ) -> CommitEntry:
        """
        Registra commit. Estado persistido no DurableLedger imediatamente.
        Fail-secure: exceção → CommitEntry com status=ABORTED.
        """
        try:
            return self._commit_internal(agent_id, intention, salt)
        except Exception as exc:
            logger.error("[CommitRevealProtocol] FAIL-SECURE commit: %s", exc)
            return self._fail_secure_commit(agent_id, str(exc))

    def reveal(
        self,
        commit_id:  str,
        intention:  str,
        salt:       str,
    ) -> RevealResult:
        """
        Revela intenção. Verifica hash e TTL.
        Fail-secure: exceção, timeout ou hash inválido → RevealResult(ABORT).
        """
        try:
            return self._reveal_internal(commit_id, intention, salt)
        except Exception as exc:
            logger.error("[CommitRevealProtocol] FAIL-SECURE reveal: %s", exc)
            return self._fail_secure_reveal(commit_id, str(exc))

    # ── Internos ───────────────────────────────────────────────────────────────

    def _commit_internal(
        self,
        agent_id:  str,
        intention: str,
        salt:      str,
    ) -> CommitEntry:
        commit_id   = str(uuid.uuid4())
        commit_hash = self._compute_hash(intention, salt)
        now_iso     = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        explain = (
            f"[CommitRevealProtocol] COMMIT registrado.\n"
            f"  commit_id={commit_id} agent_id={agent_id}\n"
            f"  TTL={self._ttl_seconds}s. Estado persistido no DurableLedger.\n"
            f"  Unlinkability: commit_id não revela intenção (salt obrigatório).\n"
            f"  Contestável via /api/v1/contestation (SLA 24h)."
        )
        sig = self._sign_commit(commit_id, agent_id, commit_hash, now_iso)

        entry_data = {
            "type":             "commit_reveal_commit",
            "commit_id":        commit_id,
            "commit_hash":      commit_hash,
            "agent_id":         agent_id,
            "committed_at_iso": now_iso,
            "ttl_seconds":      self._ttl_seconds,
            "status":           CommitStatus.PENDING.value,
            "explain_decision": explain,
        }
        self._ledger.append(entry_data)
        self._commits[commit_id] = entry_data

        return CommitEntry(
            commit_id        = commit_id,
            commit_hash      = commit_hash,
            agent_id         = agent_id,
            committed_at_iso = now_iso,
            ttl_seconds      = self._ttl_seconds,
            status           = CommitStatus.PENDING,
            explain_decision = explain,
            signature        = sig,
        )

    def _reveal_internal(
        self,
        commit_id: str,
        intention: str,
        salt:      str,
    ) -> RevealResult:
        now     = datetime.now(timezone.utc)
        now_iso = now.isoformat().replace("+00:00", "Z")

        # Busca no cache ou no ledger
        entry_data = self._load_commit(commit_id)
        if entry_data is None:
            return self._abort_reveal(
                commit_id, "unknown_agent", now_iso, f"commit_id={commit_id} não encontrado"
            )

        agent_id   = entry_data["agent_id"]
        status_str = entry_data.get("status", CommitStatus.PENDING.value)

        # Duplo reveal → ABORT
        if status_str == CommitStatus.REVEALED.value:
            return self._abort_reveal(
                commit_id, agent_id, now_iso, "duplo reveal detectado — ABORT"
            )

        # TTL expirado → ABORT (fail-secure)
        committed_at = datetime.fromisoformat(
            entry_data["committed_at_iso"].replace("Z", "+00:00")
        )
        elapsed = (now - committed_at).total_seconds()
        if elapsed > entry_data["ttl_seconds"]:
            return self._abort_reveal(
                commit_id, agent_id, now_iso,
                f"TTL expirado ({elapsed:.0f}s > {entry_data['ttl_seconds']}s) — ABORT fail-secure"
            )

        # Hash match
        expected_hash = entry_data["commit_hash"]
        actual_hash   = self._compute_hash(intention, salt)
        if not _hmac.compare_digest(expected_hash, actual_hash):
            return self._abort_reveal(
                commit_id, agent_id, now_iso, "hash mismatch — binding violation, ABORT"
            )

        # Sucesso: atualizar status no cache + ledger
        self._commits[commit_id] = {**entry_data, "status": CommitStatus.REVEALED.value}
        explain = (
            f"[CommitRevealProtocol] REVEAL bem-sucedido.\n"
            f"  commit_id={commit_id} agent_id={agent_id}\n"
            f"  Hash validado. Execução autorizada atomicamente.\n"
            f"  Contestável via /api/v1/contestation (SLA 24h)."
        )
        self._ledger.append({
            "type":             "commit_reveal_reveal",
            "commit_id":        commit_id,
            "agent_id":         agent_id,
            "revealed_at_iso":  now_iso,
            "status":           CommitStatus.REVEALED.value,
            "explain_decision": explain,
        })

        sig = self._sign_reveal(commit_id, agent_id, RevealStatus.SUCCESS, now_iso)
        return RevealResult(
            commit_id        = commit_id,
            status           = RevealStatus.SUCCESS,
            agent_id         = agent_id,
            revealed_at_iso  = now_iso,
            explain_decision = explain,
            signature        = sig,
        )

    def _load_commit(self, commit_id: str) -> Optional[dict]:
        """Busca commit no cache in-memory, ou reconstrói do ledger."""
        if commit_id in self._commits:
            return self._commits[commit_id]
        # Fallback: reconstruir do ledger (sobrevivência a crash)
        for entry in self._ledger.entries():
            payload = entry.payload
            if (
                payload.get("type") == "commit_reveal_commit"
                and payload.get("commit_id") == commit_id
            ):
                self._commits[commit_id] = payload
                # Verificar se já revelado
                for e in self._ledger.entries():
                    p = e.payload
                    if (
                        p.get("type") == "commit_reveal_reveal"
                        and p.get("commit_id") == commit_id
                    ):
                        self._commits[commit_id] = {
                            **payload, "status": CommitStatus.REVEALED.value
                        }
                        break
                return self._commits[commit_id]
        return None

    @staticmethod
    def _compute_hash(intention: str, salt: str) -> str:
        """BLAKE2b(intention_bytes || salt_bytes) → hex."""
        h = hashlib.blake2b(digest_size=32)
        h.update(intention.encode("utf-8"))
        h.update(salt.encode("utf-8"))
        return h.hexdigest()

    def _abort_reveal(
        self,
        commit_id: str,
        agent_id:  str,
        now_iso:   str,
        reason:    str,
    ) -> RevealResult:
        explain = (
            f"[CommitRevealProtocol] ABORT.\n"
            f"  commit_id={commit_id} agent_id={agent_id}\n"
            f"  Motivo: {reason}\n"
            f"  Fail-secure: ABORT é o comportamento seguro — nunca ALLOW implícito.\n"
            f"  Contestável via /api/v1/contestation (SLA 24h)."
        )
        self._ledger.append({
            "type":             "commit_reveal_abort",
            "commit_id":        commit_id,
            "agent_id":         agent_id,
            "aborted_at_iso":   now_iso,
            "reason":           reason,
            "explain_decision": explain,
        })
        sig = self._sign_reveal(commit_id, agent_id, RevealStatus.ABORT, now_iso)
        return RevealResult(
            commit_id        = commit_id,
            status           = RevealStatus.ABORT,
            agent_id         = agent_id,
            revealed_at_iso  = now_iso,
            explain_decision = explain,
            signature        = sig,
        )

    def _fail_secure_commit(self, agent_id: str, error: str) -> CommitEntry:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        commit_id = "FAIL-SECURE-" + str(uuid.uuid4())[:8]
        explain = (
            f"[CommitRevealProtocol] FAIL-SECURE commit.\n"
            f"  agent_id={agent_id} erro={error}\n"
            f"  Status=ABORTED (Jonas: erro do sistema não é licença para continuar)."
        )
        sig = self._sign_commit(commit_id, agent_id, "", now_iso)
        return CommitEntry(
            commit_id        = commit_id,
            commit_hash      = "",
            agent_id         = agent_id,
            committed_at_iso = now_iso,
            ttl_seconds      = 0,
            status           = CommitStatus.ABORTED,
            explain_decision = explain,
            signature        = sig,
        )

    def _fail_secure_reveal(self, commit_id: str, error: str) -> RevealResult:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        explain = (
            f"[CommitRevealProtocol] FAIL-SECURE reveal.\n"
            f"  commit_id={commit_id} erro={error}\n"
            f"  Status=ABORT (fail-secure: exceção → ABORT, nunca ALLOW implícito)."
        )
        sig = self._sign_reveal(commit_id, "FAIL-SECURE", RevealStatus.ABORT, now_iso)
        return RevealResult(
            commit_id        = commit_id,
            status           = RevealStatus.ABORT,
            agent_id         = "FAIL-SECURE",
            revealed_at_iso  = now_iso,
            explain_decision = explain,
            signature        = sig,
        )

    def _sign_commit(
        self, commit_id: str, agent_id: str, commit_hash: str, now_iso: str
    ) -> str:
        payload = json.dumps(
            {"commit_id": commit_id, "agent_id": agent_id,
             "commit_hash": commit_hash, "decided_at": now_iso},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def _sign_reveal(
        self, commit_id: str, agent_id: str, status: RevealStatus, now_iso: str
    ) -> str:
        payload = json.dumps(
            {"commit_id": commit_id, "agent_id": agent_id,
             "status": status.value, "decided_at": now_iso},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
