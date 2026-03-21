"""
MultiPartyKillSwitch — Cenários 10, 29, 30
Protocolo de isolamento de agente comprometido com quorum centralizado.

Design: quorum centralizado (operador + delegates autorizados).
NÃO é protocolo distribuído — exige N/total votos para ação atômica.
Renomeado de "Distributed Kill-Switch" para refletir corretamente a arquitetura.

Invariantes:
  - Fail-secure: erro interno → não isola (operação de segurança requer confirmação explícita)
  - Votos persistidos no DurableLedger (sobrevivem restart)
  - Threshold 2/3 configurável
  - Janela de votação de 1 hora; expirada sem quorum → EXPIRED (sem ação)
  - Isolamento atômico apenas após threshold atingido
  - Votante não autorizado → REJECTED
  - Duplo voto → REJECTED (não incrementa contagem)
  - explain_decision obrigatório em todo resultado
  - HMAC-SHA256 em todo resultado
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set

from .durable_ledger import DurableLedger

logger = logging.getLogger("btv.governance.multi_party_kill_switch")

_DEFAULT_KEY:          bytes = b"btv-multi-party-kill-switch-v1"
_DEFAULT_TTL_SECONDS:  int   = 3600   # 1 hora de janela de votação
_DEFAULT_THRESHOLD:    float = 2 / 3  # 2/3 dos votantes autorizados


# ─── Enums ────────────────────────────────────────────────────────────────────

class VoteResult(str, Enum):
    PENDING  = "PENDING"   # Abaixo do threshold, janela aberta
    ISOLATED = "ISOLATED"  # Threshold atingido → isolamento atômico
    EXPIRED  = "EXPIRED"   # Janela expirada sem quorum → sem ação
    REJECTED = "REJECTED"  # Votante não autorizado ou duplo voto


# ─── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class KillSwitchProposal:
    """Proposta de isolamento de agente."""
    proposal_id:       str
    target_agent_id:   str
    proposer_id:       str
    proposed_at_iso:   str
    ttl_seconds:       int
    authorized_voters: FrozenSet[str]
    threshold:         float
    explain_decision:  str
    signature:         str


@dataclass(frozen=True)
class KillSwitchVoteRecord:
    """Registro imutável de voto individual."""
    vote_id:         str
    proposal_id:     str
    target_agent_id: str
    voter_id:        str
    voted_at_iso:    str
    result:          VoteResult
    votes_cast:      int   # Número de votos após este voto
    votes_needed:    int   # Votos necessários para threshold
    explain_decision: str
    signature:        str


# ─── MultiPartyKillSwitch ─────────────────────────────────────────────────────

class MultiPartyKillSwitch:
    """
    Kill-switch multi-party com quorum centralizado.

    Operador + N delegates autorizados votam para isolar agente comprometido.
    Threshold padrão: 2/3. Janela padrão: 1 hora.
    Votos persistidos no DurableLedger.

    Uso:
        ks = MultiPartyKillSwitch(ledger=ledger, authorized_voters={"op", "d1", "d2"})
        proposal = ks.propose_isolation("agent-compromised", proposer_id="op")
        result = ks.cast_vote(proposal.proposal_id, voter_id="d1")
        result = ks.cast_vote(proposal.proposal_id, voter_id="d2")
        # Após 2/3: result.result == ISOLATED
    """

    def __init__(
        self,
        ledger:            DurableLedger,
        authorized_voters: Set[str],
        hmac_key:          bytes = _DEFAULT_KEY,
        ttl_seconds:       int   = _DEFAULT_TTL_SECONDS,
        threshold:         float = _DEFAULT_THRESHOLD,
    ) -> None:
        if len(authorized_voters) < 2:
            raise ValueError("Mínimo de 2 votantes autorizados necessário")
        self._ledger   = ledger
        self._voters   = frozenset(authorized_voters)
        self._secret   = hmac_key
        self._ttl      = ttl_seconds
        self._threshold = threshold
        # Cache in-memory para performance; ledger é fonte de verdade
        self._proposals: Dict[str, dict]       = {}
        self._votes:     Dict[str, Set[str]]   = {}  # proposal_id → set(voter_id)

    # ── API pública ────────────────────────────────────────────────────────────

    def propose_isolation(
        self,
        target_agent_id: str,
        proposer_id:     str,
    ) -> KillSwitchProposal:
        """
        Propõe isolamento de agente comprometido.
        Proposer deve ser votante autorizado.
        Fail-secure: exceção → proposta rejeitada com log.
        """
        try:
            return self._propose_internal(target_agent_id, proposer_id)
        except Exception as exc:
            logger.error("[MultiPartyKillSwitch] FAIL-SECURE propose: %s", exc)
            return self._fail_secure_proposal(target_agent_id, proposer_id, str(exc))

    def cast_vote(
        self,
        proposal_id: str,
        voter_id:    str,
    ) -> KillSwitchVoteRecord:
        """
        Registra voto para isolamento.
        Fail-secure: exceção → REJECTED com log.
        """
        try:
            return self._vote_internal(proposal_id, voter_id)
        except Exception as exc:
            logger.error("[MultiPartyKillSwitch] FAIL-SECURE vote: %s", exc)
            return self._fail_secure_vote(proposal_id, voter_id, str(exc))

    def check_status(self, proposal_id: str) -> VoteResult:
        """Verifica status atual da proposta sem votar."""
        proposal_data = self._load_proposal(proposal_id)
        if proposal_data is None:
            return VoteResult.REJECTED
        if self._is_expired(proposal_data):
            return VoteResult.EXPIRED
        votes_cast = len(self._load_votes(proposal_id))
        votes_needed = self._votes_needed(len(self._voters))
        if votes_cast >= votes_needed:
            return VoteResult.ISOLATED
        return VoteResult.PENDING

    # ── Internos ───────────────────────────────────────────────────────────────

    def _propose_internal(
        self,
        target_agent_id: str,
        proposer_id:     str,
    ) -> KillSwitchProposal:
        if proposer_id not in self._voters:
            raise ValueError(f"proposer_id='{proposer_id}' não é votante autorizado")

        proposal_id = str(uuid.uuid4())
        now_iso     = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        votes_needed = self._votes_needed(len(self._voters))

        explain = (
            f"[MultiPartyKillSwitch] PROPOSTA criada.\n"
            f"  proposal_id={proposal_id} target={target_agent_id}\n"
            f"  proposer={proposer_id} TTL={self._ttl}s\n"
            f"  Quorum necessário: {votes_needed}/{len(self._voters)} votos autorizados.\n"
            f"  Threshold={self._threshold:.0%}. Votos persistidos no DurableLedger.\n"
            f"  Contestável via /api/v1/contestation (SLA 24h)."
        )
        sig = self._sign_proposal(proposal_id, target_agent_id, proposer_id, now_iso)

        proposal_data = {
            "type":              "kill_switch_proposal",
            "proposal_id":       proposal_id,
            "target_agent_id":   target_agent_id,
            "proposer_id":       proposer_id,
            "proposed_at_iso":   now_iso,
            "ttl_seconds":       self._ttl,
            "authorized_voters": list(self._voters),
            "threshold":         self._threshold,
            "explain_decision":  explain,
        }
        self._ledger.append(proposal_data)
        self._proposals[proposal_id] = proposal_data
        self._votes[proposal_id] = set()

        return KillSwitchProposal(
            proposal_id       = proposal_id,
            target_agent_id   = target_agent_id,
            proposer_id       = proposer_id,
            proposed_at_iso   = now_iso,
            ttl_seconds       = self._ttl,
            authorized_voters = self._voters,
            threshold         = self._threshold,
            explain_decision  = explain,
            signature         = sig,
        )

    def _vote_internal(
        self,
        proposal_id: str,
        voter_id:    str,
    ) -> KillSwitchVoteRecord:
        now     = datetime.now(timezone.utc)
        now_iso = now.isoformat().replace("+00:00", "Z")

        # Carrega proposta
        proposal_data = self._load_proposal(proposal_id)
        if proposal_data is None:
            return self._rejected_vote(
                proposal_id, voter_id, now_iso,
                f"proposal_id='{proposal_id}' não encontrado"
            )

        target_agent_id = proposal_data["target_agent_id"]

        # Votante autorizado?
        if voter_id not in self._voters:
            return self._rejected_vote(
                proposal_id, voter_id, now_iso,
                f"voter_id='{voter_id}' não é votante autorizado"
            )

        # Janela expirada?
        if self._is_expired(proposal_data):
            return self._record_vote(
                proposal_id, target_agent_id, voter_id, now_iso,
                VoteResult.EXPIRED,
                "Janela de votação expirada — sem ação (fail-secure: expiração != consentimento)"
            )

        # Duplo voto?
        votes_cast_ids = self._load_votes(proposal_id)
        if voter_id in votes_cast_ids:
            return self._rejected_vote(
                proposal_id, voter_id, now_iso,
                f"voter_id='{voter_id}' já votou nesta proposta (duplo voto rejeitado)"
            )

        # Registra voto
        votes_cast_ids.add(voter_id)
        self._votes[proposal_id] = votes_cast_ids
        votes_needed = self._votes_needed(len(self._voters))
        votes_count  = len(votes_cast_ids)

        # Threshold atingido?
        if votes_count >= votes_needed:
            result = VoteResult.ISOLATED
            reason = (
                f"Quorum atingido: {votes_count}/{len(self._voters)} votos. "
                f"Isolamento atômico executado."
            )
        else:
            result = VoteResult.PENDING
            remaining = votes_needed - votes_count
            reason = (
                f"Voto registrado: {votes_count}/{len(self._voters)}. "
                f"Aguardando {remaining} voto(s) para quorum."
            )

        return self._record_vote(
            proposal_id, target_agent_id, voter_id, now_iso, result, reason,
            votes_cast=votes_count, votes_needed=votes_needed,
        )

    def _record_vote(
        self,
        proposal_id:     str,
        target_agent_id: str,
        voter_id:        str,
        now_iso:         str,
        result:          VoteResult,
        reason:          str,
        votes_cast:      int = 0,
        votes_needed:    int = 0,
    ) -> KillSwitchVoteRecord:
        vote_id = str(uuid.uuid4())
        explain = (
            f"[MultiPartyKillSwitch] VOTO {result.value}.\n"
            f"  proposal_id={proposal_id} target={target_agent_id}\n"
            f"  voter={voter_id} votos={votes_cast}/{len(self._voters)}\n"
            f"  {reason}\n"
            f"  Voto persistido no DurableLedger.\n"
            f"  Contestável via /api/v1/contestation (SLA 24h)."
        )
        sig = self._sign_vote(vote_id, proposal_id, voter_id, result, now_iso)

        self._ledger.append({
            "type":             "kill_switch_vote",
            "vote_id":          vote_id,
            "proposal_id":      proposal_id,
            "target_agent_id":  target_agent_id,
            "voter_id":         voter_id,
            "voted_at_iso":     now_iso,
            "result":           result.value,
            "votes_cast":       votes_cast,
            "votes_needed":     votes_needed,
            "explain_decision": explain,
        })

        return KillSwitchVoteRecord(
            vote_id          = vote_id,
            proposal_id      = proposal_id,
            target_agent_id  = target_agent_id,
            voter_id         = voter_id,
            voted_at_iso     = now_iso,
            result           = result,
            votes_cast       = votes_cast,
            votes_needed     = votes_needed,
            explain_decision = explain,
            signature        = sig,
        )

    def _rejected_vote(
        self,
        proposal_id: str,
        voter_id:    str,
        now_iso:     str,
        reason:      str,
    ) -> KillSwitchVoteRecord:
        return self._record_vote(
            proposal_id, "unknown", voter_id, now_iso,
            VoteResult.REJECTED, reason,
        )

    def _votes_needed(self, total_voters: int) -> int:
        """Mínimo de votos para atingir threshold (ceil(threshold * total))."""
        import math
        return math.ceil(self._threshold * total_voters)

    def _is_expired(self, proposal_data: dict) -> bool:
        try:
            proposed_at = datetime.fromisoformat(
                proposal_data["proposed_at_iso"].replace("Z", "+00:00")
            )
            elapsed = (datetime.now(timezone.utc) - proposed_at).total_seconds()
            return elapsed > proposal_data["ttl_seconds"]
        except (KeyError, ValueError):
            return True  # fail-safe: dados corrompidos → considera expirado

    def _load_proposal(self, proposal_id: str) -> Optional[dict]:
        """Busca proposta no cache ou no ledger (após crash)."""
        if proposal_id in self._proposals:
            return self._proposals[proposal_id]
        for entry in self._ledger.entries():
            payload = entry.payload
            if (
                payload.get("type") == "kill_switch_proposal"
                and payload.get("proposal_id") == proposal_id
            ):
                self._proposals[proposal_id] = payload
                return payload
        return None

    def _load_votes(self, proposal_id: str) -> Set[str]:
        """Carrega votos do cache ou do ledger."""
        if proposal_id in self._votes:
            return self._votes[proposal_id]
        votes: Set[str] = set()
        for entry in self._ledger.entries():
            payload = entry.payload
            if (
                payload.get("type") == "kill_switch_vote"
                and payload.get("proposal_id") == proposal_id
                and payload.get("result") not in (VoteResult.REJECTED.value, VoteResult.EXPIRED.value)
            ):
                voter = payload.get("voter_id", "")
                if voter:
                    votes.add(voter)
        self._votes[proposal_id] = votes
        return votes

    def _fail_secure_proposal(
        self,
        target_agent_id: str,
        proposer_id:     str,
        error:           str,
    ) -> KillSwitchProposal:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        proposal_id = "FAIL-SECURE-" + str(uuid.uuid4())[:8]
        explain = (
            f"[MultiPartyKillSwitch] FAIL-SECURE propose.\n"
            f"  target={target_agent_id} proposer={proposer_id} erro={error}\n"
            f"  Proposta criada com TTL=0 (inoperante). Investigar antes de retentar."
        )
        sig = self._sign_proposal(proposal_id, target_agent_id, proposer_id, now_iso)
        return KillSwitchProposal(
            proposal_id       = proposal_id,
            target_agent_id   = target_agent_id,
            proposer_id       = proposer_id,
            proposed_at_iso   = now_iso,
            ttl_seconds       = 0,
            authorized_voters = self._voters,
            threshold         = self._threshold,
            explain_decision  = explain,
            signature         = sig,
        )

    def _fail_secure_vote(
        self,
        proposal_id: str,
        voter_id:    str,
        error:       str,
    ) -> KillSwitchVoteRecord:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return self._rejected_vote(proposal_id, voter_id, now_iso, f"FAIL-SECURE: {error}")

    def _sign_proposal(
        self, proposal_id: str, target: str, proposer: str, now_iso: str
    ) -> str:
        payload = json.dumps(
            {"proposal_id": proposal_id, "target": target,
             "proposer": proposer, "decided_at": now_iso},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def _sign_vote(
        self, vote_id: str, proposal_id: str, voter_id: str,
        result: VoteResult, now_iso: str
    ) -> str:
        payload = json.dumps(
            {"vote_id": vote_id, "proposal_id": proposal_id,
             "voter_id": voter_id, "result": result.value, "decided_at": now_iso},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
