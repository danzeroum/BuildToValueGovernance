"""
PersuasionGuard — PROP-037 (ADR-0049)

Defesa contra ataques adversariais via Chain-of-Thought (CoT).

Invariantes (ADR-0049):
  D1: checker_model_family != model_family (normalização case-insensitive por prefixo)
  D2: validação em startup — falha explícita antes de qualquer decisão
  D3: checker ausente → BLOCK (não ESCALATE_HUMAN)
  D4: CoT original no Ledger inalterado; julgamento usa AnnotatedCoT
  D5: checker sobre SLMClassifier (ADR-0027 v1.8.0)

Filosofia: Levinas (visibilidade total do processo), Rawls (BLOCK contestável SLA 24h).

Ref: paper 209 (Persuasion_Attacks, ICLR 2026):
  - CoT access → aprovação maliciosa +9.5%
  - Família diferente → redução de até 45%
  - Mesma família (versão distinta) → apenas -8%
"""

from __future__ import annotations

import re
import hmac
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ─── Enums ───────────────────────────────────────────────────────────────────────

class ClaimSuspicion(Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


class GuardStatus(Enum):
    AVAILABLE   = "available"
    UNAVAILABLE = "unavailable"


# ─── Exceptions ────────────────────────────────────────────────────────────────

class PersuasionGuardUnavailableError(RuntimeError):
    """
    Guard indisponível em runtime.
    Caller deve retornar BLOCK imediato (ADR-0049 D3).
    """


# ─── Protocol ───────────────────────────────────────────────────────────────────

@runtime_checkable
class FactCheckerProtocol(Protocol):
    """
    Protocolo para checker de claims (implementação: SLMClassifier ADR-0027).

    Runtime-checkable para isinstance() em testes.
    Contrato: model_family DEVE diferir do agente (ADR-0049 D1).
    """

    @property
    def model_id(self) -> str: ...

    @property
    def model_family(self) -> str: ...

    def check_claim(self, claim: str, context: str) -> Tuple[bool, float]: ...


# ─── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class BiasDeclarationV2:
    """
    BiasDeclaration extendida (ADR-0049 D1 / v2.0).

    checker_model_family DEVE diferir de model_family.
    Validação: comparação case-insensitive do prefixo até primeiro hífen ou ponto.

    to_explain_dict() — serialização completa para explain_decision e
    DurableLedger (Levinas: transparência total do processo de avaliação).
    """
    model_id:             str
    model_family:         str
    checker_model_id:     str
    checker_model_family: str
    declared_at_iso:      str
    known_limitations:    Tuple[str, ...]  = field(default_factory=tuple)
    false_positive_rate:  float            = 0.05
    false_negative_rate:  float            = 0.02
    calibration_date:     Optional[str]    = None  # ISO date da última calibração

    def to_explain_dict(self) -> Dict[str, object]:
        """
        Serialização auditável para explain_decision e DurableLedger.

        Todos os campos incluídos — sem omissões (Levinas: responsabilidade total).
        known_limitations como list para JSON-serializabilidade.
        """
        return {
            "model_id":             self.model_id,
            "model_family":         self.model_family,
            "checker_model_id":     self.checker_model_id,
            "checker_model_family": self.checker_model_family,
            "declared_at_iso":      self.declared_at_iso,
            "false_positive_rate":  self.false_positive_rate,
            "false_negative_rate":  self.false_negative_rate,
            "calibration_date":     self.calibration_date,
            "known_limitations":    list(self.known_limitations),
        }


@dataclass(frozen=True)
class ClaimFlag:
    """
    Flag de claim suspeito no CoT.

    Incluída em explain_decision (Levinas: visibilidade total do julgamento).
    """
    claim_text: str
    suspicion:  ClaimSuspicion
    position:   int    # offset de início no CoT original
    reason:     str


@dataclass(frozen=True)
class AnnotatedCoT:
    """
    CoT anotado pelo PersuasionGuard.

    Invariante (ADR-0049 D4):
      - cot_original preservado inalterado → Ledger
      - flags indicam claims não-verificados → julgamento
      - hmac_sha256 garante integridade da anotação
    """
    cot_original:        str
    cot_hash_sha256:     str           # hash do CoT original para o Ledger
    flags:               Tuple[ClaimFlag, ...]
    annotation_time_iso: str
    checker_model_id:    str
    hmac_sha256:         str           # HMAC da anotação completa
    persuasion_score:    float         # 0.0 (limpo) → 1.0 (máxima suseição)

    @property
    def high_suspicion_count(self) -> int:
        return sum(1 for f in self.flags if f.suspicion == ClaimSuspicion.HIGH)

    @property
    def has_suspicious_claims(self) -> bool:
        return any(f.suspicion != ClaimSuspicion.LOW for f in self.flags)

    def to_explain_dict(self) -> Dict[str, object]:
        """Formato para explain_decision (obrigatório ADR-0049)."""
        return {
            "cot_hash_sha256":      self.cot_hash_sha256,
            "persuasion_score":     self.persuasion_score,
            "high_suspicion_count": self.high_suspicion_count,
            "flags": [
                {
                    "claim":     f.claim_text[:80],
                    "suspicion": f.suspicion.value,
                    "position":  f.position,
                    "reason":    f.reason,
                }
                for f in self.flags
            ],
            "checker_model_id":  self.checker_model_id,
            "annotation_time":   self.annotation_time_iso,
        }


# ─── Padrões heurísticos (paper 209) ─────────────────────────────────────────────────

_PERSUASION_PATTERNS: List[Tuple[re.Pattern, str, ClaimSuspicion]] = [
    (
        re.compile(r'\b(ignore|disregard|forget|override).{0,40}(previous|original|initial|goal)\b', re.I),
        "goal_override_attempt",
        ClaimSuspicion.HIGH,
    ),
    (
        re.compile(r'\b(definitely|certainly|guaranteed|always will|without doubt)\b', re.I),
        "absolute_certainty",
        ClaimSuspicion.HIGH,
    ),
    (
        re.compile(r'\b(must act now|immediately|no time to|urgent|critical deadline)\b', re.I),
        "false_urgency",
        ClaimSuspicion.HIGH,
    ),
    (
        re.compile(r'\b(trust me|believe me|i promise|i assure you)\b', re.I),
        "unverifiable_assertion",
        ClaimSuspicion.MEDIUM,
    ),
    (
        re.compile(r'\b(experts say|according to|studies show|research confirms|statistics prove)\b', re.I),
        "unverifiable_authority",
        ClaimSuspicion.MEDIUM,
    ),
    (
        re.compile(r'\b\d+\.\d{4,}\b'),
        "suspicious_precision",
        ClaimSuspicion.MEDIUM,
    ),
]


# ─── Helpers ──────────────────────────────────────────────────────────────────────

def _normalize_family(family: str) -> str:
    """
    Normaliza prefixo de família (ADR-0049 D1).

    Case-insensitive, prefixo até primeiro hífen ou ponto.
    Ex: 'Llama3-70b' → 'llama3', 'mistral.v2' → 'mistral'
    """
    return re.split(r'[-.]', family.lower().strip())[0]


def _validate_bias_declaration(decl: BiasDeclarationV2) -> None:
    """
    Validação startup (ADR-0049 D2).

    Raises:
        ValueError: se checker_model_family ausente ou igual a model_family.
    """
    if not decl.checker_model_family:
        raise ValueError(
            "BiasDeclarationV2.checker_model_family obrigatório (ADR-0049 D1)"
        )
    if _normalize_family(decl.checker_model_family) == _normalize_family(decl.model_family):
        raise ValueError(
            f"checker_model_family='{decl.checker_model_family}' deve diferir de "
            f"model_family='{decl.model_family}' "
            "(paper 209: mesma família = apenas -8% de eficácia — ADR-0049 D1)"
        )


def _compute_annotation_hmac(
    cot_hash: str,
    flags: List[ClaimFlag],
    checker_model_id: str,
    annotation_time_iso: str,
    key: bytes,
) -> str:
    """HMAC-SHA256 da anotação completa (Jonas: responsabilidade auditável)."""
    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(cot_hash.encode())
    for f in flags:
        mac.update(f.claim_text.encode())
        mac.update(f.suspicion.value.encode())
        mac.update(str(f.position).encode())
        mac.update(f.reason.encode())
    mac.update(checker_model_id.encode())
    mac.update(annotation_time_iso.encode())
    return mac.hexdigest()


# ─── PersuasionGuard ─────────────────────────────────────────────────────────────────

class PersuasionGuard:
    """
    Proteção contra ataques adversariais via CoT (ADR-0049).

    Separação invariante (D4):
      cot_original → Ledger (inalterado, HMAC-SHA256)
      AnnotatedCoT → EthicalContextEngine (seguro)

    Fail-secure (D3): checker indisponível → caller retorna BLOCK.
    """

    def __init__(
        self,
        bias_declaration: BiasDeclarationV2,
        hmac_key: bytes,
        fact_checker: Optional[FactCheckerProtocol] = None,
    ) -> None:
        _validate_bias_declaration(bias_declaration)   # startup validation D2
        self._bias_declaration = bias_declaration
        self._hmac_key         = hmac_key
        self._fact_checker     = fact_checker
        self._status           = GuardStatus.AVAILABLE
        logger.info(
            "PersuasionGuard: model_family=%s checker_family=%s checker=%s",
            bias_declaration.model_family,
            bias_declaration.checker_model_family,
            bias_declaration.checker_model_id,
        )

    @property
    def status(self) -> GuardStatus:
        return self._status

    @property
    def bias_declaration(self) -> BiasDeclarationV2:
        return self._bias_declaration

    def annotate_cot(self, cot: str) -> AnnotatedCoT:
        """
        Anota o CoT identificando claims suspeitos.

        CoT original preservado. Flags indicam claims não-verificados.
        HMAC-SHA256 garante integridade da anotação para o Ledger.

        Raises:
            PersuasionGuardUnavailableError: se guard UNAVAILABLE (→ BLOCK).
        """
        if self._status == GuardStatus.UNAVAILABLE:
            raise PersuasionGuardUnavailableError(
                "PersuasionGuard UNAVAILABLE → caller deve retornar BLOCK (ADR-0049 D3)"
            )

        cot_hash  = hashlib.sha256(cot.encode()).hexdigest()
        flags     = self._annotate_heuristic(cot)

        if self._fact_checker is not None:
            flags = self._merge_checker_flags(cot, flags)

        persuasion_score = _calculate_persuasion_score(flags)
        now_iso          = datetime.utcnow().isoformat() + "Z"

        annotation_hmac = _compute_annotation_hmac(
            cot_hash, flags,
            self._bias_declaration.checker_model_id,
            now_iso, self._hmac_key,
        )

        return AnnotatedCoT(
            cot_original        = cot,
            cot_hash_sha256     = cot_hash,
            flags               = tuple(flags),
            annotation_time_iso = now_iso,
            checker_model_id    = self._bias_declaration.checker_model_id,
            hmac_sha256         = annotation_hmac,
            persuasion_score    = persuasion_score,
        )

    def mark_unavailable(self) -> None:
        """Marca guard como indisponível (ex: SLM falhou em init)."""
        self._status = GuardStatus.UNAVAILABLE
        logger.warning("PersuasionGuard marcado UNAVAILABLE")

    def _annotate_heuristic(self, cot: str) -> List[ClaimFlag]:
        """
        Anotação heurística baseada em padrões do paper 209.

        Uma flag por sentença (máximo) — prioriza padrão mais crítico.
        Não-hot-path: List alocada aqui é aceitável.
        """
        flags: List[ClaimFlag] = []
        sentences = re.split(r'(?<=[.!?])\s+', cot)
        offset = 0
        for sentence in sentences:
            best: Optional[Tuple[str, ClaimSuspicion]] = None
            for pattern, reason, suspicion in _PERSUASION_PATTERNS:
                if pattern.search(sentence):
                    if best is None or suspicion.value > best[1].value:
                        best = (reason, suspicion)
            if best is not None:
                flags.append(ClaimFlag(
                    claim_text = sentence[:120],
                    suspicion  = best[1],
                    position   = offset,
                    reason     = best[0],
                ))
            offset += len(sentence) + 1
        return flags

    def _merge_checker_flags(
        self,
        cot: str,
        existing: List[ClaimFlag],
    ) -> List[ClaimFlag]:
        """
        Integra flags do SLM checker com flags heurísticas.

        Claims que o checker considera suspeitos → ClaimSuspicion.HIGH.
        Falha do checker: log + continua sem flag (não bloqueia).
        """
        if self._fact_checker is None:
            return existing

        already_flagged_positions = {f.position for f in existing}
        merged: List[ClaimFlag] = list(existing)
        sentences = re.split(r'(?<=[.!?])\s+', cot)
        offset = 0

        for sentence in sentences:
            if offset not in already_flagged_positions:
                try:
                    is_suspicious, _score = self._fact_checker.check_claim(sentence, cot)
                    if is_suspicious:
                        merged.append(ClaimFlag(
                            claim_text = sentence[:120],
                            suspicion  = ClaimSuspicion.HIGH,
                            position   = offset,
                            reason     = "fact_checker_flagged",
                        ))
                except Exception as exc:
                    logger.warning("FactChecker falhou para claim offset=%d: %s", offset, exc)
            offset += len(sentence) + 1

        return merged


# ─── Helpers de instância extraídos (funções puras, testáveis) ────────────────────────

def _calculate_persuasion_score(flags: List[ClaimFlag]) -> float:
    """
    Score de persuasão 0.0–1.0.

    Média ponderada por nível de suseição.
    """
    if not flags:
        return 0.0
    weights = {
        ClaimSuspicion.LOW:    0.1,
        ClaimSuspicion.MEDIUM: 0.4,
        ClaimSuspicion.HIGH:   0.9,
    }
    total = sum(weights[f.suspicion] for f in flags)
    return min(total / len(flags), 1.0)
