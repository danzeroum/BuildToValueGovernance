"""manifest_hash_verifier.py — ManifestHashVerifier v1.0.0 (ADR-042 Fase 2)

Verifica integridade do manifesto JSON de um modelo antes de delegar
a verificação completa dos pesos ao Rust kernel.

Arquitetura em camadas (Jonas: responsabilidade em cadeia):
  Python:      hash do manifesto (arquivo leve, <1MB) — fast-path
  Rust kernel: hash dos pesos    (arquivo pesado, >1GB) — full-path

Filosofia:
  Jonas:   fail-secure — dúvida + block_on_failure=True → is_valid=False
  Levinas: explain_decision() obrigatório em todos os caminhos
  Rawls:   mesma verificação para todos os modelos (sem excecções silenciosas)

Algoritmo: SHA-256 do conteúdo do arquivo manifesto (hex lowercase).
Env var: BTV_<MODEL>_MANIFEST_HASH define o hash esperado (imutável em deploy).
"""
from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .policy_engine import PolicyEngine

logger = logging.getLogger("btv.governance.manifest_hash_verifier")


@dataclass(frozen=True)
class ManifestVerificationResult:
    """Resultado imutável da verificação de hash do manifesto (Rawls: contrato auditável)."""
    model_id: str
    manifest_path: str
    is_valid: bool
    explanation: str
    contestable: bool = True

    def explain_decision(self) -> str:
        """Obrigatório — ADR-016 Transparency Radical."""
        return self.explanation


class ManifestHashVerifier:
    """Verifica hash SHA-256 do manifesto JSON de um modelo (ADR-042 Fase 2).

    Invariantes:
    - explain_decision() obrigatório em todos os resultados (Levinas)
    - Fail-secure: block_on_failure=True + dúvida → is_valid=False (Jonas)
    - verification_enabled=False → skip auditado via log
    - Funções ≤50 linhas
    """

    def verify(
        self,
        model_id: str,
        policy_engine: "PolicyEngine",
    ) -> ManifestVerificationResult:
        """Verifica hash SHA-256 do manifesto para model_id.

        Fluxo (6 caminhos, todos auditados):
          1. verification_enabled=False → skip (log warn, is_valid=True)
          2. manifest_path não configurado → resolve_on_failure
          3. env var ausente → resolve_on_failure
          4. arquivo não encontrado → fail
          5. hash match → is_valid=True
          6. hash mismatch → is_valid=False (MODEL_INTEGRITY_HASH_MISMATCH)
        """
        mic = policy_engine.model_integrity

        if not mic.verification_enabled:
            logger.warning(
                "ManifestHashVerifier: verification_enabled=False para '%s' — skip",
                model_id,
            )
            return self._ok(model_id, "", "Verificação desabilitada (verification_enabled=False).")

        manifest_path = policy_engine.manifest_path_for(model_id)
        if manifest_path is None:
            return self._resolve_on_failure(
                model_id, "", mic.block_on_failure,
                f"manifest_path não configurado para '{model_id}'",
            )

        model_cfg = mic.models.get(model_id)
        if model_cfg is None:
            return self._resolve_on_failure(
                model_id, manifest_path, mic.block_on_failure,
                f"ModelConfig ausente para '{model_id}' em model_integrity.yaml",
            )

        expected_hash = os.environ.get(model_cfg.expected_hash_env, "").strip().lower()
        if not expected_hash:
            return self._resolve_on_failure(
                model_id, manifest_path, mic.block_on_failure,
                f"Env var '{model_cfg.expected_hash_env}' não definida — hash não verificável",
            )

        return self._check_file_hash(model_id, manifest_path, expected_hash)

    def _check_file_hash(
        self,
        model_id: str,
        manifest_path: str,
        expected_hash: str,
    ) -> ManifestVerificationResult:
        """Lê arquivo, computa SHA-256, compara com expected_hash (lowercase)."""
        path = Path(manifest_path)
        if not path.exists():
            return self._fail(
                model_id, manifest_path,
                f"Arquivo de manifesto não encontrado: '{manifest_path}'",
            )
        try:
            content = path.read_bytes()
        except OSError as exc:
            return self._fail(model_id, manifest_path, f"Erro ao ler manifesto: {exc}")

        computed = hashlib.sha256(content).hexdigest().lower()
        if computed == expected_hash:
            logger.info(
                "ManifestHashVerifier: hash OK para '%s' (sha256=%.16s...)",
                model_id, computed,
            )
            return self._ok(
                model_id, manifest_path,
                f"Hash SHA-256 verificado: {computed[:16]}... — manifesto íntegro (ADR-042).",
            )

        logger.error(
            "ManifestHashVerifier: HASH MISMATCH para '%s' — "
            "computed=%.16s... expected=%.16s...",
            model_id, computed, expected_hash,
        )
        return self._fail(
            model_id, manifest_path,
            f"Hash mismatch: computed={computed[:16]}... expected={expected_hash[:16]}... "
            f"— possível adulteração (MODEL_INTEGRITY_HASH_MISMATCH).",
        )

    def _resolve_on_failure(
        self,
        model_id: str,
        manifest_path: str,
        block_on_failure: bool,
        reason: str,
    ) -> ManifestVerificationResult:
        """Jonas: block_on_failure=True → fail; False → warn e continua."""
        if block_on_failure:
            return self._fail(model_id, manifest_path, reason)
        logger.warning(
            "ManifestHashVerifier: %s — continuando (block_on_failure=False)", reason
        )
        return self._ok(
            model_id, manifest_path,
            f"Aviso: {reason} — verificação pulada (block_on_failure=False).",
        )

    def _ok(
        self, model_id: str, path: str, explanation: str
    ) -> ManifestVerificationResult:
        return ManifestVerificationResult(
            model_id=model_id, manifest_path=path,
            is_valid=True, explanation=explanation,
        )

    def _fail(
        self, model_id: str, path: str, explanation: str
    ) -> ManifestVerificationResult:
        return ManifestVerificationResult(
            model_id=model_id, manifest_path=path,
            is_valid=False,
            explanation=(
                f"MANIFEST FAIL-SECURE: {explanation} "
                "Contestable SLA 24h (Rawls)."
            ),
        )
