"""
MemoryConsistencyValidator — Cenários 31, 28, 11
Validação de consistência de memória persistida no DurableLedger.

Detecta quatro tipos determinísticos de inconsistência (v1):
  1. DIRECT_CONTRADICTION: A=X, novo: A=Y (mesma entidade, valor conflitante)
  2. TEMPORAL_VIOLATION:   evento B registrado antes de A, mas B referencia A
  3. SOURCE_CONFLICT:      fonte A diz X, fonte B diz Y para a mesma entidade
  4. ENTITY_DUPLICATION:   mesma entidade com IDs distintos

Nota: IMPLICIT_OVERRIDE (novo fato invalida inferência passada) requer motor
de inferência/ML e foi postergado para v2.

Invariantes:
  - Fail-secure: exceção → ConsistencyReport(consistent=False, flagged=True)
  - explain_decision obrigatório em todo resultado
  - HMAC-SHA256 em todo ConsistencyReport
  - Memórias suspeitas marcadas com flagged_for_review=True, não silenciadas
  - O DurableLedger permanece append-only: memórias conflitantes são marcadas,
    não removidas
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from .durable_ledger import DurableLedger

logger = logging.getLogger("btv.governance.memory_consistency")

_DEFAULT_KEY: bytes = b"btv-memory-consistency-default-v1"


# ─── Tipos de inconsistência (v1 — apenas determinísticos) ────────────────────

class InconsistencyType(str, Enum):
    DIRECT_CONTRADICTION = "DIRECT_CONTRADICTION"
    # A=X, novo: A=Y — mesma chave, valor conflitante
    # Detectado: comparação direta de valores

    TEMPORAL_VIOLATION = "TEMPORAL_VIOLATION"
    # Evento B registrado antes de A, mas B referencia A como pré-requisito
    # Detectado: comparação de timestamps + referências

    SOURCE_CONFLICT = "SOURCE_CONFLICT"
    # Fonte A diz X, fonte B diz Y para mesma entidade
    # Detectado: mesmo entity_key, fontes distintas, valores distintos

    ENTITY_DUPLICATION = "ENTITY_DUPLICATION"
    # Mesma entidade (pelo conteúdo) com IDs distintos
    # Detectado: normalização de campos canônicos + comparação


class InconsistencySeverity(str, Enum):
    HIGH   = "high"    # DIRECT_CONTRADICTION
    MEDIUM = "medium"  # TEMPORAL_VIOLATION, SOURCE_CONFLICT, ENTITY_DUPLICATION
    LOW    = "low"


_TYPE_SEVERITY: dict[InconsistencyType, InconsistencySeverity] = {
    InconsistencyType.DIRECT_CONTRADICTION: InconsistencySeverity.HIGH,
    InconsistencyType.TEMPORAL_VIOLATION:   InconsistencySeverity.MEDIUM,
    InconsistencyType.SOURCE_CONFLICT:      InconsistencySeverity.MEDIUM,
    InconsistencyType.ENTITY_DUPLICATION:   InconsistencySeverity.MEDIUM,
}


# ─── Resultado imutável ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ConsistencyReport:
    """
    Resultado imutável da validação de consistência de memória.
    consistent=False + flagged_for_review=True → memória marcada para revisão humana.
    """
    consistent:          bool
    inconsistency_type:  Optional[InconsistencyType]
    severity:            InconsistencySeverity
    conflicting_key:     Optional[str]       # campo/entidade em conflito
    existing_value:      Optional[str]       # valor existente no ledger
    new_value:           Optional[str]       # valor que causou conflito
    flagged_for_review:  bool
    explain_decision:    str
    decided_at_iso:      str
    signature:           str

    @property
    def should_block(self) -> bool:
        """Inconsistência de alta severidade deve bloquear ingestão."""
        return self.inconsistency_type == InconsistencyType.DIRECT_CONTRADICTION


# ─── MemoryFact — estrutura de fato de memória ────────────────────────────────

@dataclass
class MemoryFact:
    """
    Fato de memória a ser validado antes de persistir.

    entity_key: identificador canônico da entidade (ex: "user:123", "contract:abc")
    attribute:  atributo que está sendo definido (ex: "status", "value")
    value:      novo valor proposto
    source:     quem está gerando este fato (ex: "agent-a", "oracle-b")
    timestamp_iso: quando o evento ocorreu (não quando foi registrado)
    event_references: lista de entity_keys de eventos pré-requisito
    """
    entity_key:         str
    attribute:          str
    value:              str
    source:             str
    timestamp_iso:      str
    event_references:   List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.event_references is None:
            self.event_references = []


# ─── MemoryConsistencyValidator ───────────────────────────────────────────────

class MemoryConsistencyValidator:
    """
    Valida consistência de novos fatos de memória contra o DurableLedger.

    Detecta os 4 tipos determinísticos de inconsistência (v1).
    Fail-secure: exceção → ConsistencyReport(consistent=False, flagged=True).

    Uso:
        validator = MemoryConsistencyValidator(ledger=ledger)
        report = validator.validate(new_fact)
        if not report.consistent:
            # marcar para revisão humana — nunca silenciar
            logger.warning(report.explain_decision)
    """

    def __init__(
        self,
        ledger:   DurableLedger,
        hmac_key: bytes = _DEFAULT_KEY,
    ) -> None:
        self._ledger  = ledger
        self._secret  = hmac_key

    # ── API pública ────────────────────────────────────────────────────────────

    def validate(self, fact: MemoryFact) -> ConsistencyReport:
        """
        Valida novo fato contra memórias existentes.
        Fail-secure: exceção → ConsistencyReport(consistent=False, flagged=True).
        """
        try:
            return self._validate_internal(fact)
        except Exception as exc:
            logger.error("[MemoryConsistencyValidator] FAIL-SECURE: %s", exc)
            return self._fail_secure(fact, str(exc))

    def persist_if_consistent(
        self,
        fact:    MemoryFact,
        payload: Dict[str, Any],
    ) -> ConsistencyReport:
        """
        Valida e, se consistente, persiste no DurableLedger.
        Memórias inconsistentes são marcadas com flag mas não bloqueiam o ledger.
        """
        report = self.validate(fact)
        persist_payload = {
            **payload,
            "memory_consistent":   report.consistent,
            "flagged_for_review":  report.flagged_for_review,
            "inconsistency_type":  report.inconsistency_type.value if report.inconsistency_type else None,
            "consistency_check_at": report.decided_at_iso,
            "explain_decision":    report.explain_decision,
        }
        self._ledger.append(persist_payload)
        return report

    # ── Internos ───────────────────────────────────────────────────────────────

    def _validate_internal(self, fact: MemoryFact) -> ConsistencyReport:
        existing_facts = self._load_facts()

        # 1. DIRECT_CONTRADICTION
        contradiction = self._check_direct_contradiction(fact, existing_facts)
        if contradiction:
            return contradiction

        # 2. TEMPORAL_VIOLATION
        temporal = self._check_temporal_violation(fact, existing_facts)
        if temporal:
            return temporal

        # 3. SOURCE_CONFLICT
        source_conflict = self._check_source_conflict(fact, existing_facts)
        if source_conflict:
            return source_conflict

        # 4. ENTITY_DUPLICATION
        entity_dup = self._check_entity_duplication(fact, existing_facts)
        if entity_dup:
            return entity_dup

        return self._ok_report(fact)

    def _load_facts(self) -> List[MemoryFact]:
        """Carrega fatos de memória do DurableLedger."""
        facts = []
        for entry in self._ledger.entries():
            payload = entry.payload
            if payload.get("type") == "memory_fact":
                try:
                    facts.append(MemoryFact(
                        entity_key       = payload.get("entity_key", ""),
                        attribute        = payload.get("attribute", ""),
                        value            = payload.get("value", ""),
                        source           = payload.get("source", ""),
                        timestamp_iso    = payload.get("timestamp_iso", ""),
                        event_references = payload.get("event_references", []),
                    ))
                except Exception:
                    continue
        return facts

    def _check_direct_contradiction(
        self,
        fact:           MemoryFact,
        existing_facts: List[MemoryFact],
    ) -> Optional[ConsistencyReport]:
        """A=X, novo: A=Y — mesma (entity_key, attribute, source), valor diferente.
        Fonte diferente com valores conflitantes → SOURCE_CONFLICT (verificado separado).
        """
        for existing in existing_facts:
            if (
                existing.entity_key == fact.entity_key
                and existing.attribute == fact.attribute
                and existing.source == fact.source   # mesma fonte contradiz a si mesma
                and existing.value != fact.value
            ):
                itype = InconsistencyType.DIRECT_CONTRADICTION
                return self._inconsistency_report(
                    fact        = fact,
                    itype       = itype,
                    key         = f"{fact.entity_key}.{fact.attribute}",
                    existing_v  = existing.value,
                    new_v       = fact.value,
                    explanation = (
                        f"DIRECT_CONTRADICTION: {fact.entity_key}.{fact.attribute} "
                        f"já tem valor='{existing.value}', novo valor='{fact.value}' conflita."
                    ),
                )
        return None

    def _check_temporal_violation(
        self,
        fact:           MemoryFact,
        existing_facts: List[MemoryFact],
    ) -> Optional[ConsistencyReport]:
        """B referencia A como pré-requisito mas B.timestamp < A.timestamp."""
        if not fact.event_references:
            return None
        for ref_key in fact.event_references:
            # Busca o evento referenciado
            ref_facts = [
                e for e in existing_facts
                if e.entity_key == ref_key
            ]
            if not ref_facts:
                continue
            # Verifica se o novo fato ocorre antes do referenciado
            try:
                new_ts      = datetime.fromisoformat(fact.timestamp_iso.replace("Z", "+00:00"))
                for ref_fact in ref_facts:
                    if not ref_fact.timestamp_iso:
                        continue
                    ref_ts = datetime.fromisoformat(ref_fact.timestamp_iso.replace("Z", "+00:00"))
                    if new_ts < ref_ts:
                        itype = InconsistencyType.TEMPORAL_VIOLATION
                        return self._inconsistency_report(
                            fact        = fact,
                            itype       = itype,
                            key         = f"{fact.entity_key} refs {ref_key}",
                            existing_v  = ref_fact.timestamp_iso,
                            new_v       = fact.timestamp_iso,
                            explanation = (
                                f"TEMPORAL_VIOLATION: {fact.entity_key} (ts={fact.timestamp_iso}) "
                                f"ocorre antes de {ref_key} (ts={ref_fact.timestamp_iso}), "
                                f"mas referencia {ref_key} como pré-requisito."
                            ),
                        )
            except (ValueError, TypeError):
                continue
        return None

    def _check_source_conflict(
        self,
        fact:           MemoryFact,
        existing_facts: List[MemoryFact],
    ) -> Optional[ConsistencyReport]:
        """Fonte A diz X, fonte B diz Y para mesma (entity_key, attribute)."""
        for existing in existing_facts:
            if (
                existing.entity_key == fact.entity_key
                and existing.attribute == fact.attribute
                and existing.source != fact.source
                and existing.value != fact.value
            ):
                itype = InconsistencyType.SOURCE_CONFLICT
                return self._inconsistency_report(
                    fact        = fact,
                    itype       = itype,
                    key         = f"{fact.entity_key}.{fact.attribute}",
                    existing_v  = f"{existing.source}:'{existing.value}'",
                    new_v       = f"{fact.source}:'{fact.value}'",
                    explanation = (
                        f"SOURCE_CONFLICT: {fact.entity_key}.{fact.attribute}: "
                        f"fonte '{existing.source}' diz '{existing.value}', "
                        f"fonte '{fact.source}' diz '{fact.value}'."
                    ),
                )
        return None

    def _check_entity_duplication(
        self,
        fact:           MemoryFact,
        existing_facts: List[MemoryFact],
    ) -> Optional[ConsistencyReport]:
        """Mesma entidade (mesmo atributo canônico) com entity_keys distintos."""
        # Heurística: mesmo (attribute, value, source) mas entity_key diferente
        for existing in existing_facts:
            if (
                existing.attribute == fact.attribute
                and existing.value == fact.value
                and existing.source == fact.source
                and existing.entity_key != fact.entity_key
            ):
                itype = InconsistencyType.ENTITY_DUPLICATION
                return self._inconsistency_report(
                    fact        = fact,
                    itype       = itype,
                    key         = f"{fact.attribute}={fact.value}",
                    existing_v  = existing.entity_key,
                    new_v       = fact.entity_key,
                    explanation = (
                        f"ENTITY_DUPLICATION: {fact.attribute}='{fact.value}' (source={fact.source}) "
                        f"já existe com entity_key='{existing.entity_key}', "
                        f"novo entity_key='{fact.entity_key}' é duplicata."
                    ),
                )
        return None

    def _inconsistency_report(
        self,
        fact:        MemoryFact,
        itype:       InconsistencyType,
        key:         str,
        existing_v:  str,
        new_v:       str,
        explanation: str,
    ) -> ConsistencyReport:
        severity = _TYPE_SEVERITY[itype]
        now_iso  = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        explain  = (
            f"[MemoryConsistencyValidator] INCONSISTÊNCIA DETECTADA.\n"
            f"  tipo={itype.value} severidade={severity.value}\n"
            f"  {explanation}\n"
            f"  Memória marcada para revisão humana (flagged_for_review=True).\n"
            f"  DurableLedger preservado append-only — sem remoção de entradas.\n"
            f"  Contestável via /api/v1/contestation (SLA 24h)."
        )
        sig = self._sign(fact.entity_key, itype, now_iso)
        return ConsistencyReport(
            consistent          = False,
            inconsistency_type  = itype,
            severity            = severity,
            conflicting_key     = key,
            existing_value      = existing_v,
            new_value           = new_v,
            flagged_for_review  = True,
            explain_decision    = explain,
            decided_at_iso      = now_iso,
            signature           = sig,
        )

    def _ok_report(self, fact: MemoryFact) -> ConsistencyReport:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        explain = (
            f"[MemoryConsistencyValidator] Consistência OK.\n"
            f"  entity_key={fact.entity_key} attribute={fact.attribute}\n"
            f"  Nenhuma inconsistência dos 4 tipos v1 detectada."
        )
        sig = self._sign(fact.entity_key, None, now_iso)
        return ConsistencyReport(
            consistent          = True,
            inconsistency_type  = None,
            severity            = InconsistencySeverity.LOW,
            conflicting_key     = None,
            existing_value      = None,
            new_value           = None,
            flagged_for_review  = False,
            explain_decision    = explain,
            decided_at_iso      = now_iso,
            signature           = sig,
        )

    def _fail_secure(self, fact: MemoryFact, error: str) -> ConsistencyReport:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        explain = (
            f"[MemoryConsistencyValidator] FAIL-SECURE ativado.\n"
            f"  entity_key={fact.entity_key} erro={error}\n"
            f"  Memória marcada para revisão humana (Jonas: precaução ante dúvida).\n"
            f"  Contestável via /api/v1/contestation (SLA 24h)."
        )
        sig = self._sign(fact.entity_key, None, now_iso)
        return ConsistencyReport(
            consistent          = False,
            inconsistency_type  = None,
            severity            = InconsistencySeverity.HIGH,
            conflicting_key     = None,
            existing_value      = None,
            new_value           = None,
            flagged_for_review  = True,
            explain_decision    = explain,
            decided_at_iso      = now_iso,
            signature           = sig,
        )

    def _sign(
        self,
        entity_key: str,
        itype:      Optional[InconsistencyType],
        now_iso:    str,
    ) -> str:
        payload = json.dumps(
            {
                "entity_key": entity_key,
                "itype":      itype.value if itype else None,
                "decided_at": now_iso,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
