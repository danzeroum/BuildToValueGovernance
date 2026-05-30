"""Agent-ecosystem routes (ADR-0093 Phase 2, Passo 3 — router 4).

Agrupa 4 domínios coesos do ciclo de vida de agentes (10 rotas):
- `/v1/agents/*`     — registro/consulta/revogação de chaves Ed25519 (C3, C10)
- `/v1/oracles/*`    — registro/revogação de oráculos regulatórios (C34)
- `/v1/a2a/*`        — correlação e scan agent-to-agent (C6)
- `/v1/delegation/*` — ledger de delegação encadeada (C6)

Decisão de estado (documentada no commit):
- `_cross_agent` (CrossAgentCorrelator) e `_delegation_ledger`
  (DelegationLedger): **app.state** — instanciados no lifespan e compartilhados;
  lidos via `Depends(get_cross_agent)` / `Depends(get_delegation_ledger)` para
  garantir a MESMA instância do hot path. Sem import reverso de `app.py`.
- `_ORACLE_REGISTRY_STORE`: **module-level local** — registro em memória
  exclusivo do domínio de oráculos (nenhum outro módulo o consome), espelhando
  o padrão de `COMPLIANCE_PLUGINS` em `routes/compliance.py`.
- `durable_ledger`: lido de `request.app.state` com guarda `getattr` (dormente
  até ser provisionado no lifespan — comportamento idêntico ao original).

Topologia: arquivo único com regiões delimitadas (`# ── Region: ...`). Os
domínios compartilham a categoria semântica "agente" e os singletons de
app.state; split por sub-arquivos foi avaliado e descartado (10 rotas finas,
sem ganho de coesão — ver handoff Router 4).
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from buildtovalue.api._db import DB_PATH
from buildtovalue.api.auth import require_api_key
from buildtovalue.governance.cross_agent_correlator import CrossAgentCorrelator
from buildtovalue.governance.delegation_ledger import DelegationLedger
from buildtovalue.security import sqlite_connect_wal

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────────────────────────
# Provedores estritos de singletons (Fail-Secure 503 — ADR-0093)
# ─────────────────────────────────────────────────────────────────
def get_cross_agent(request: Request) -> CrossAgentCorrelator:
    ca = getattr(request.app.state, "cross_agent", None)
    if not isinstance(ca, CrossAgentCorrelator):
        raise HTTPException(status_code=503, detail="CrossAgentCorrelator not initialized")
    return ca


def get_delegation_ledger(request: Request) -> DelegationLedger:
    dl = getattr(request.app.state, "delegation_ledger", None)
    if not isinstance(dl, DelegationLedger):
        raise HTTPException(status_code=503, detail="DelegationLedger not initialized")
    return dl


# ═════════════════════════════════════════════════════════════════
# Region: Agents — C3 Agent Public Key Registration / C10 Identity Anchor
# ═════════════════════════════════════════════════════════════════

class AgentRegisterRequest(BaseModel):
    public_key_hex: str = Field(..., min_length=64, max_length=64, description="Ed25519 public key (32 bytes hex)")
    registration_proof: Optional[str] = Field(None, description="Identity proof for anti-Sybil (C10)")


def _load_identity_anchor_policy() -> Dict[str, object]:
    import yaml
    candidates = [
        Path(os.environ.get("BTV_POLICY_DIR", "data/policies")) / "core" / "identity_anchor.yaml",
        Path(__file__).resolve().parent.parent.parent.parent.parent / "data" / "policies" / "core" / "identity_anchor.yaml",
    ]
    for p in candidates:
        try:
            if p.exists():
                with open(p) as f:
                    return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {"require_identity_anchor": False}


@router.post("/v1/agents/{agent_id}/register", status_code=201)
def agent_register(
    agent_id: str, req: AgentRegisterRequest, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    """Register an Ed25519 public key for an agent (C3)."""
    # C10: identity anchor enforcement
    policy = _load_identity_anchor_policy()
    if policy.get("require_identity_anchor", False) and not req.registration_proof:
        raise HTTPException(status_code=403, detail="registration_proof required (identity_anchor policy)")

    try:
        bytes.fromhex(req.public_key_hex)
    except ValueError:
        raise HTTPException(status_code=422, detail="public_key_hex must be valid hex")

    key_fingerprint = hashlib.sha256(bytes.fromhex(req.public_key_hex)).hexdigest()[:16]
    registered_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    conn = sqlite_connect_wal(DB_PATH)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO agent_pubkeys (agent_id, public_key_hex, registered_at, revoked_at, registration_proof) "
            "VALUES (?, ?, ?, NULL, ?)",
            (agent_id, req.public_key_hex, registered_at, req.registration_proof),
        )
        conn.commit()
    finally:
        conn.close()

    return {"agent_id": agent_id, "registered_at": registered_at, "key_fingerprint": key_fingerprint}


@router.get("/v1/agents/{agent_id}/pubkey")
def agent_get_pubkey(
    agent_id: str, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    """Retrieve registered public key for an agent (C3)."""
    conn = sqlite_connect_wal(DB_PATH)
    row = conn.execute(
        "SELECT public_key_hex, registered_at, revoked_at FROM agent_pubkeys WHERE agent_id = ?",
        (agent_id,),
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not registered")
    if row[2]:
        raise HTTPException(status_code=410, detail=f"Agent {agent_id} key revoked at {row[2]}")

    return {"agent_id": agent_id, "public_key_hex": row[0], "registered_at": row[1]}


@router.delete("/v1/agents/{agent_id}/revoke")
def agent_revoke(
    agent_id: str, _: None = Depends(require_api_key)
) -> Dict[str, object]:
    """Revoke the public key of an agent (C3)."""
    revoked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn = sqlite_connect_wal(DB_PATH)
    cur = conn.execute(
        "UPDATE agent_pubkeys SET revoked_at = ? WHERE agent_id = ? AND revoked_at IS NULL",
        (revoked_at, agent_id),
    )
    conn.commit()
    conn.close()

    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found or already revoked")

    return {"agent_id": agent_id, "revoked_at": revoked_at}


# ═════════════════════════════════════════════════════════════════
# Region: Oracles — C34 OracleTrustGate (Cenário 34: Boato Digital P2P)
# Segue padrão /v1/agents/{id}/register e /v1/agents/{id}/revoke
# ═════════════════════════════════════════════════════════════════

class OracleRegisterRequest(BaseModel):
    hmac_key_hex: str       # chave HMAC do oráculo (hex)
    valid_until_iso: str    # data de expiração UTC ISO 8601
    description: str = ""


class OracleRevokeRequest(BaseModel):
    reason: str = "Revogação solicitada via API"


# oracle_id → {hmac_key_hex, valid_until, revoked, ...}
_ORACLE_REGISTRY_STORE: Dict[str, Dict[str, object]] = {}


@router.post("/v1/oracles/{oracle_id}/register", status_code=201)
def oracle_register(
    oracle_id: str,
    req: OracleRegisterRequest,
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    """Registra chave HMAC de um oráculo regulatório (Cenário 34).

    Segue padrão de /v1/agents/{id}/register.
    """
    registered_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _ORACLE_REGISTRY_STORE[oracle_id] = {
        "oracle_id": oracle_id,
        "hmac_key_hex": req.hmac_key_hex,
        "valid_until_iso": req.valid_until_iso,
        "description": req.description,
        "registered_at": registered_at,
        "revoked": False,
    }
    logger.info("Oracle registrado: oracle_id=%s", oracle_id)
    return {
        "oracle_id": oracle_id,
        "registered_at": registered_at,
        "valid_until_iso": req.valid_until_iso,
    }


@router.post("/v1/oracles/{oracle_id}/revoke", status_code=200)
def oracle_revoke(
    oracle_id: str,
    req: OracleRevokeRequest,
    request: Request,
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    """Revoga chave HMAC de um oráculo regulatório (Cenário 34).

    Persiste rastreabilidade no ledger (Gap 3).
    Segue padrão de /v1/agents/{id}/revoke.
    """
    entry = _ORACLE_REGISTRY_STORE.get(oracle_id)
    if entry is None or entry.get("revoked", False):
        raise HTTPException(
            status_code=404,
            detail=f"Oracle '{oracle_id}' não encontrado ou já revogado",
        )

    entry["revoked"] = True
    revoked_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry["revoked_at"] = revoked_at
    entry["revocation_reason"] = req.reason

    # Persiste rastreabilidade no DurableLedger global (se disponível)
    try:
        durable_ledger = getattr(request.app.state, "durable_ledger", None)
        if durable_ledger is not None:
            durable_ledger.append({
                "type": "oracle_revocation_api",
                "oracle_id": oracle_id,
                "revoked_at_iso": revoked_at,
                "reason": req.reason,
                "explain_decision": (
                    f"Oráculo '{oracle_id}' revogado via API em {revoked_at}. "
                    f"Motivo: {req.reason}"
                ),
            })
    except Exception as exc:  # noqa: BLE001
        logger.warning("Falha ao registrar revogação no ledger: %s", exc)

    logger.info("Oracle revogado: oracle_id=%s reason=%s", oracle_id, req.reason)
    return {"oracle_id": oracle_id, "revoked_at": revoked_at}


# ═════════════════════════════════════════════════════════════════
# Region: A2A — C6 CrossAgentCorrelator
# ═════════════════════════════════════════════════════════════════

class A2ACorrelateRequest(BaseModel):
    agent_id: str
    action: str


class A2AScanRequest(BaseModel):
    src: str
    dst: str
    payload: str


@router.post("/v1/a2a/correlate")
def a2a_correlate(
    req: A2ACorrelateRequest,
    cross_agent: CrossAgentCorrelator = Depends(get_cross_agent),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    """Check agent action for conflicts (C6 — CrossAgentCorrelator)."""
    result = cross_agent.correlate(req.agent_id, req.action)
    return {
        "allowed": result.allowed,
        "conflict": result.conflict,
        "circuit_state": result.circuit_state.value if hasattr(result.circuit_state, "value") else str(result.circuit_state),
        "explain": result.explain,
    }


@router.post("/v1/a2a/scan")
def a2a_scan(
    req: A2AScanRequest,
    cross_agent: CrossAgentCorrelator = Depends(get_cross_agent),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    """Scan an agent-to-agent payload for injection patterns (C6)."""
    result = cross_agent.scan_a2a_payload(req.src, req.dst, req.payload)
    # Auto-trigger collusion detection after scan (C6 — internal, no separate endpoint abuse)
    # NOTE (extração Router 4): preserva o comportamento exato do app.py original.
    # detect_collusion espera Dict[str, List[str]], mas o original passa str
    # (payload[:64]) — mismatch latente pré-existente. Mudar para [payload[:64]]
    # alteraria a semântica de detecção; preservado como-está e sinalizado ao
    # comitê para tratamento fora deste refactor.
    collusion = cross_agent.detect_collusion(
        {req.src: req.payload[:64], req.dst: req.payload[:64]}  # type: ignore[dict-item]
    )
    return {
        "allowed": result.allowed if hasattr(result, "allowed") else True,
        "explain": result.explain if hasattr(result, "explain") else "",
        "collusion_detected": not collusion.get("allowed", True) if isinstance(collusion, dict) else False,
    }


# ═════════════════════════════════════════════════════════════════
# Region: Delegation — C6 DelegationLedger
# ═════════════════════════════════════════════════════════════════

class DelegationRecordRequest(BaseModel):
    parent_agent: str
    child_agent: str
    scope: str
    capabilities: Optional[List[str]] = None


class DelegationRevokeRequest(BaseModel):
    record_id: str


@router.post("/v1/delegation/record", status_code=201)
def delegation_record(
    req: DelegationRecordRequest,
    delegation_ledger: DelegationLedger = Depends(get_delegation_ledger),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    """Record a new agent delegation (C6 — DelegationLedger)."""
    try:
        rec = delegation_ledger.record_delegation(
            req.parent_agent, req.child_agent, req.scope, req.capabilities
        )
        return {
            "record_id": rec.record_id,
            "parent_agent": rec.parent_agent,
            "child_agent": rec.child_agent,
            "scope": rec.scope,
            "created_at": rec.created_at,
            "chain_hash": rec.chain_hash,
        }
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/v1/delegation/{agent_id}/chain")
def delegation_chain(
    agent_id: str,
    delegation_ledger: DelegationLedger = Depends(get_delegation_ledger),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    """Verify the delegation chain for an agent (C6)."""
    result = delegation_ledger.verify_chain(agent_id)
    return {
        "agent_id": agent_id,
        "valid": result.valid,
        "depth": result.depth,
        "chain": result.chain,
        "explain": result.explain,
    }


@router.post("/v1/delegation/{agent_id}/revoke")
def delegation_revoke(
    agent_id: str,
    req: DelegationRevokeRequest,
    delegation_ledger: DelegationLedger = Depends(get_delegation_ledger),
    _: None = Depends(require_api_key),
) -> Dict[str, object]:
    """Revoke a delegation record (C6)."""
    try:
        delegation_ledger.revoke_delegation(req.record_id)
        return {"record_id": req.record_id, "revoked": True}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
