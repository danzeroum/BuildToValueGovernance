"""
PolicyHygieneValidator v1.0.0 — PREFPO-inspired (ADR-TBD).

Valida qualidade de políticas YAML de forma programática, sem LLM no hot path.
Detecta políticas "hackeadas" por otimizadores (PREFPO — ICLR 2026): conteúdo
repetitivo, tamanho anômalo, degradação silenciosa.

Métricas:
  length_ratio     : len(content) / BASELINE_LENGTH_CHARS — ideal próximo a 1.0
  trigram_repetition: fração de trigrams que são duplicatas [0.0, 1.0]
  hygiene_grade    : 0-6 (0-2 crítico, 3-4 aceitável, 5-6 bom)

Invariantes:
  - explain_decision obrigatório em HygieneReport (Levinas: transparência)
  - HMAC-SHA256 em todo relatório (Jonas: responsabilidade assinada)
  - Fail-secure: exceção → HygieneReport com grade=0 assinado (Jonas)
  - Thread-safe: PolicyHygieneValidator é stateless (zero estado mutável)
  - Funciona offline — sem dependência de rede ou LLM

Changelog:
  v1.0.0: Implementação inicial — length_ratio + trigram_repetition + grade 0-6.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple


# ─── Constantes ───────────────────────────────────────────────────────────────

BASELINE_LENGTH_CHARS: int = 500
"""Comprimento esperado de uma política YAML saudável (em caracteres)."""

MAX_TRIGRAM_REPETITION: float = 0.30
"""Limite de repetição de trigrams acima do qual a política é penalizada."""

GRADE_MAX: int = 6
"""Grade máxima possível (políticas sem anomalias)."""


# ─── HygieneReport ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class HygieneReport:
    """
    Relatório imutável de qualidade de política YAML.

    explain_decision OBRIGATÓRIO (Levinas: transparência radical).
    signature OBRIGATÓRIO (Jonas: responsabilidade assinada).
    is_healthy = True quando grade >= 4 (aceitável ou bom).
    """
    policy_path:             str
    length_ratio:            float   # len / BASELINE — ideal ~1.0
    trigram_repetition:      float   # [0.0, 1.0] — 0 = sem repetição
    hygiene_grade:           int     # 0-6 (0-2 crítico, 3-4 aceitável, 5-6 bom)
    issues:                  tuple   # tupla de strings descrevendo problemas
    explain_decision:        str     # obrigatório (Levinas)
    evaluated_at_iso:        str
    signature:               str     # HMAC-SHA256 (Jonas)
    is_healthy:              bool    # grade >= 4

    def to_dict(self) -> dict:
        return {
            "policy_path":          self.policy_path,
            "length_ratio":         round(self.length_ratio, 4),
            "trigram_repetition":   round(self.trigram_repetition, 4),
            "hygiene_grade":        self.hygiene_grade,
            "issues":               list(self.issues),
            "explain_decision":     self.explain_decision,
            "evaluated_at_iso":     self.evaluated_at_iso,
            "signature":            self.signature,
            "is_healthy":           self.is_healthy,
        }


# ─── PolicyHygieneValidator ───────────────────────────────────────────────────

class PolicyHygieneValidator:
    """
    Valida qualidade de políticas YAML offline (sem LLM no hot path).

    Thread-safe: instância sem estado mutável — pode ser compartilhada.
    Uso típico: validação offline de políticas antes do carregamento pelo PolicyEngine.

    Exemplo:
        validator = PolicyHygieneValidator()
        report = validator.validate(Path("data/policies/governance_v1.yaml"))
        if not report.is_healthy:
            logger.warning("Política com grade baixa: %s", report.explain_decision)
    """

    _HMAC_KEY: bytes = b"btv-policy-hygiene-v1"

    def validate(self, policy_path: Path) -> HygieneReport:
        """
        Valida política YAML e retorna HygieneReport.

        Fail-secure: qualquer erro de leitura ou processamento →
        HygieneReport com grade=0 e explain_decision detalhando o erro.
        """
        try:
            return self._validate_internal(policy_path)
        except Exception as exc:
            return self._fail_secure(str(policy_path), str(exc))

    # ── Internos ──────────────────────────────────────────────────────────────

    def _validate_internal(self, policy_path: Path) -> HygieneReport:
        content = policy_path.read_text(encoding="utf-8")
        length_ratio = self._compute_length_ratio(content)
        trigram_rep  = self._compute_trigram_repetition(content)
        issues: List[str] = []
        grade = self._compute_grade(length_ratio, trigram_rep, issues)
        is_healthy = grade >= 4
        now = datetime.now(timezone.utc).isoformat()
        explain = self._build_explain(
            str(policy_path), length_ratio, trigram_rep, grade, issues, is_healthy
        )
        sig = self._sign(str(policy_path), grade, now)
        return HygieneReport(
            policy_path=str(policy_path),
            length_ratio=length_ratio,
            trigram_repetition=trigram_rep,
            hygiene_grade=grade,
            issues=tuple(issues),
            explain_decision=explain,
            evaluated_at_iso=now,
            signature=sig,
            is_healthy=is_healthy,
        )

    def _compute_length_ratio(self, content: str) -> float:
        """Razão entre comprimento real e comprimento baseline esperado."""
        return len(content) / BASELINE_LENGTH_CHARS if BASELINE_LENGTH_CHARS > 0 else 0.0

    def _compute_trigram_repetition(self, content: str) -> float:
        """
        Fração de character-trigrams duplicados no conteúdo.

        Trigrams duplicados indicam repetição excessiva — padrão de política
        'hackeada' identificado em PREFPO (ICLR 2026).
        Retorna 0.0 se conteúdo for curto demais para análise.
        """
        words = content.split()
        if len(words) < 3:
            return 0.0
        trigrams = [
            (words[i], words[i + 1], words[i + 2])
            for i in range(len(words) - 2)
        ]
        total = len(trigrams)
        if total == 0:
            return 0.0
        unique = len(set(trigrams))
        return (total - unique) / total

    def _compute_grade(
        self,
        length_ratio:   float,
        trigram_rep:    float,
        issues:         List[str],
    ) -> int:
        """
        Calcula grade 0-6 baseado em métricas de hygiene.

        Penalizações:
          - length_ratio < 0.1  : -4 pontos (política quase vazia — crítico)
          - length_ratio < 0.3  : -2 pontos (política muito curta)
          - length_ratio > 5.0  : -2 pontos (política excessivamente longa)
          - trigram_rep > MAX   : -2 pontos (conteúdo repetitivo)
        """
        grade = GRADE_MAX

        if length_ratio < 0.1:
            issues.append(
                f"Política quase vazia: length_ratio={length_ratio:.4f} < 0.1 (crítico)"
            )
            grade = max(0, grade - 4)
        elif length_ratio < 0.3:
            issues.append(
                f"Política muito curta: length_ratio={length_ratio:.4f} < 0.3"
            )
            grade = max(0, grade - 2)

        if length_ratio > 5.0:
            issues.append(
                f"Política excessivamente longa: length_ratio={length_ratio:.4f} > 5.0 "
                "(possível conteúdo inflado)"
            )
            grade = max(0, grade - 2)

        if trigram_rep > MAX_TRIGRAM_REPETITION:
            issues.append(
                f"Repetição excessiva de trigrams: {trigram_rep:.4f} > {MAX_TRIGRAM_REPETITION} "
                "(possível conteúdo duplicado ou 'hackeado')"
            )
            grade = max(0, grade - 2)

        return grade

    def _build_explain(
        self,
        path:         str,
        length_ratio: float,
        trigram_rep:  float,
        grade:        int,
        issues:       List[str],
        is_healthy:   bool,
    ) -> str:
        status = "SAUDÁVEL" if is_healthy else "CRÍTICO" if grade <= 2 else "ACEITÁVEL"
        parts = [
            f"[PolicyHygieneValidator] path={path}",
            f"  grade={grade}/{GRADE_MAX} ({status})  "
            f"length_ratio={length_ratio:.4f}  trigram_repetition={trigram_rep:.4f}",
        ]
        if issues:
            parts.append("  Problemas detectados:")
            for iss in issues:
                parts.append(f"    - {iss}")
        else:
            parts.append("  Nenhum problema de hygiene detectado.")
        if not is_healthy:
            parts.append(
                "  Jonas: política com baixa hygiene é risco operacional — "
                "revisar antes de carregar no PolicyEngine."
            )
        return "\n".join(parts)

    def _sign(self, path: str, grade: int, evaluated_at: str) -> str:
        """HMAC-SHA256(path || grade || evaluated_at)."""
        payload = json.dumps(
            {"evaluated_at": evaluated_at, "grade": grade, "path": path},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        return _hmac.new(self._HMAC_KEY, payload, hashlib.sha256).hexdigest()

    def _fail_secure(self, path: str, error: str) -> HygieneReport:
        """Fail-secure: erro interno → grade=0, explain detalhado (Jonas)."""
        now = datetime.now(timezone.utc).isoformat()
        sig = self._sign(path, 0, now)
        explain = (
            f"[PolicyHygieneValidator] FAIL-SECURE: erro ao validar path={path}\n"
            f"  erro: {error}\n"
            "  grade=0 (conservador — Jonas: erro do sistema não é aprovação)."
        )
        return HygieneReport(
            policy_path=path,
            length_ratio=0.0,
            trigram_repetition=0.0,
            hygiene_grade=0,
            issues=(f"Erro de validação: {error}",),
            explain_decision=explain,
            evaluated_at_iso=now,
            signature=sig,
            is_healthy=False,
        )
