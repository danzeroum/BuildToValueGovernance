"""
model_integrity_contestability.py — ModelIntegrityContestabilityFlow v1.0.0
ADR-051 Fase 3: contestability flow para MODEL_INTEGRITY_VIOLATION.

Permite ao operador submeter manifesto alternativo assinado dentro do SLA 24h
para contestar um bloqueio por hash divergente ou manifesto indisponível.

Design: composição sobre ContestabilityLoop v3.1 (ADR-017 + ADR-047).
Nenhum arquivo existente foi modificado.

Filosofia:
  Jonas:   BLOCK mantido durante pendência — aceite só após reviewer humano
  Levinas: explain_decision() obrigatório em ManifestAppealResult
  Rawls:   SLA 24h idêntico para todos os operadores
  ADR-047: grounds=[\"technical_error\"], mediator_recommendation persistido
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import logging
import time
from dataclasses import dataclass
from typing import List, Optional

from .contestability_loop import Appeal, AppealStatus, ContestabilityLoop

logger = logging.getLogger("btv.governance.model_integrity_contestability")

# Ground do vocabulário ADR-047 usado para appeals de manifesto
MANIFEST_GROUND = "technical_error"


# ─── Tipos ───────────────────────────────────────────────────────────────────────────────────

@dataclass
class ManifestAppealResult:
    """Resultado da resolução de appeal de manifesto (ADR-051 §6).

    Se accepted=True e new_expected_hash presente:
      → operador deve reconfigurar ModelIntegrityVerifier com este hash.
      → ADR-042: hash deve ser lido de Policy YAML, não hardcoded.
    Se accepted=False:
      → BLOCK permanece. Modelo requer re-certificação.
    """
    appeal_id:        str
    model_id:         str
    accepted:         bool
    new_expected_hash: Optional[str]  # hex 64 chars (BLAKE3/SHA3-256 32 bytes)
    explanation:      str             # obrigatório — Levinas
    timestamp:        int
    contestable:      bool = False    # resolução final, não contestável


# ─── Flow principal ──────────────────────────────────────────────────────────────────────

class ModelIntegrityContestabilityFlow:
    """Contestability flow para MODEL_INTEGRITY_VIOLATION (ADR-051 Fase 3).

    Composição sobre ContestabilityLoop (não herança) para preservar o
    design existente e evitar acoplamento.

    Invariantes:
    - Jonas:   BLOCK mantido até resolver humano aceitar — não há auto-lift
    - Levinas: explain_decision() em todo ManifestAppealResult
    - Rawls:   SLA 24h idêntico para todos os operadores, sem exceção
    - Fail-secure: exception → BLOCK mantido, erro logado
    """

    def __init__(
        self,
        contestability_loop: Optional[ContestabilityLoop] = None,
        db_path: Optional[str] = None,
    ) -> None:
        self._loop = contestability_loop or ContestabilityLoop(
            sla_hours=24,
            db_path=db_path or "data/manifest_appeals.db",
        )

    def submit_manifest_appeal(
        self,
        model_id: str,
        violation_type: str,
        alternative_manifest_bytes: bytes,
        operator_signing_key: bytes,
        reason: str,
        operator_id: str = "operator",
    ) -> Appeal:
        """Submete appeal com manifesto alternativo assinado (ADR-051 §6).

        Fail-secure (Jonas): exception → BLOCK mantido; nunca silenciado.
        O appeal não levanta o BLOCK — isso só ocorre após aceite humano.

        Args:
            model_id:                  identificador do modelo bloqueado.
            violation_type:            "HashMismatch" | "ManifestUnavailable".
            alternative_manifest_bytes: conteúdo do manifesto alternativo.
            operator_signing_key:      chave HMAC-SHA256 do operador (32+ bytes).
            reason:                    justificativa (≥20 chars, Levinas).
            operator_id:               identificador do operador.
        """
        if not alternative_manifest_bytes:
            raise ValueError("alternative_manifest_bytes não pode ser vazio")
        if len(reason) < 20:
            raise ValueError("reason deve ter ao menos 20 caracteres")

        manifest_hash = _blake3_hex(alternative_manifest_bytes)
        hmac_sig      = _sign_manifest(alternative_manifest_bytes, operator_signing_key)
        evidence = (
            f"model_id={model_id} violation={violation_type} "
            f"manifest_blake3={manifest_hash[:16]}... "
            f"operator_hmac={hmac_sig[:16]}..."
        )
        audit_trail_id = abs(hash(f"{model_id}:{int(time.time())}")) % (2 ** 31)

        appeal = self._loop.submit_appeal(
            audit_trail_id=audit_trail_id,
            user_id=operator_id,
            reason=reason,
            evidence=evidence,
        )
        appeal.grounds       = [MANIFEST_GROUND]
        appeal.evidence_hash = manifest_hash
        self._loop._save_appeal(appeal)

        logger.info(
            "ManifestAppeal submitted: appeal=%s model=%s violation=%s hash=%s...",
            appeal.appeal_id, model_id, violation_type, manifest_hash[:16],
        )
        return appeal

    def resolve_manifest_appeal(
        self,
        appeal_id: str,
        model_id: str,
        accepted: bool,
        reviewer_notes: str,
        reviewer_id: str = "reviewer",
        new_manifest_bytes: Optional[bytes] = None,
    ) -> ManifestAppealResult:
        """Resolve appeal de manifesto — requer decisão humana explícita.

        Se accepted=True, new_manifest_bytes é obrigatório para derivar
        o novo hash que o operador deve configurar no ModelIntegrityVerifier
        (ADR-042: via Policy YAML, não hardcode).
        """
        if accepted and new_manifest_bytes is None:
            raise ValueError(
                "new_manifest_bytes obrigatório quando accepted=True"
            )

        new_hash: Optional[str] = None
        if accepted and new_manifest_bytes:
            new_hash = _blake3_hex(new_manifest_bytes)

        self._loop.resolve_appeal(
            appeal_id=appeal_id,
            accepted=accepted,
            reviewer_notes=reviewer_notes,
            reviewer_id=reviewer_id,
            mediator_recommendation="accept_appeal" if accepted else "reject_appeal",
        )
        explanation = _explain(
            model_id, appeal_id, accepted, new_hash, reviewer_notes
        )
        result = ManifestAppealResult(
            appeal_id=appeal_id,
            model_id=model_id,
            accepted=accepted,
            new_expected_hash=new_hash,
            explanation=explanation,
            timestamp=int(time.time()),
        )
        logger.info(
            "ManifestAppeal resolved: appeal=%s model=%s accepted=%s",
            appeal_id, model_id, accepted,
        )
        return result

    def get_pending_manifest_appeals(self) -> List[Appeal]:
        """Lista appeals de manifesto pendentes (ground=technical_error)."""
        return [
            a for a in self._loop.list_pending_appeals()
            if MANIFEST_GROUND in (a.grounds or [])
        ]


# ─── Funções puras (testáveis de forma isolada) ────────────────────────────────────────

def _blake3_hex(data: bytes) -> str:
    """BLAKE3 nativo (py blake3) ou SHA3-256 como fallback."""
    try:
        import blake3 as _b3
        return _b3.blake3(data).hexdigest()
    except ImportError:
        return hashlib.sha3_256(data).hexdigest()


def _sign_manifest(data: bytes, key: bytes) -> str:
    """HMAC-SHA256 do manifesto com chave do operador (ADR-017)."""
    return _hmac.new(key, data, digestmod=hashlib.sha256).hexdigest()


def _explain(
    model_id: str,
    appeal_id: str,
    accepted: bool,
    new_hash: Optional[str],
    reviewer_notes: str,
) -> str:
    """explain_decision() obrigatório — Levinas."""
    verdict = "ACCEPTED" if accepted else "REJECTED"
    parts = [
        f"Model: {model_id}. Appeal: {appeal_id}. Verdict: {verdict}.",
        f"Reviewer: {reviewer_notes}",
    ]
    if accepted and new_hash:
        parts.append(
            f"New BLAKE3 hash: {new_hash[:16]}... "
            "Configure ModelIntegrityVerifier via Policy YAML (ADR-042). "
            "BLOCK is lifted upon reconfiguration and restart."
        )
    else:
        parts.append(
            "BLOCK remains in effect. "
            "Model requires re-alignment and re-certification (ADR-051 §6)."
        )
    parts.append("Resolution is final and non-contestable.")
    return " ".join(parts)
