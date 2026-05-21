"""Model integrity verifier v1.2.0 — ADR-049 + ADR-042.

Separado de model_integrity.py (\u2264200 linhas).

v1.1.0 (ADR-042): remove acesso direto a _governance_config; usa accessors tipados.
v1.2.0 (ADR-042 Fase 2): IntegrityVerifier integra ManifestHashVerifier —
  Python fast-path (manifest hash) antes do Rust kernel (weights hash).
  Cadeia de responsabilidade: Python SHA-256 → Rust BLAKE3 (Jonas).
"""
import logging
from typing import Optional, Callable
from .model_integrity import KnownModel, get_model_info, normalize_id, is_known_abliterated, ModelStatus
from .manifest_hash_verifier import ManifestHashVerifier
# H-06: canonical AbliterationDetector is abliteration_detector.py (v1.2.0 ADR-051 Fase 2).
# The v1.1.0 duplicate that lived here has been removed; IntegrityVerifier now uses the
# production implementation with timeout enforcement and extended probe catalog.
from .abliteration_detector import AbliterationDetector
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .policy_engine import PolicyEngine

logger = logging.getLogger("btv.governance.model_integrity")


# ==========================================
# VERIFICADOR DE INTEGRIDADE
# ==========================================

class IntegrityVerifier:
    """Ponto de entrada único para verificação de integridade de modelos.

    v1.2.0 (ADR-042 Fase 2): cadeia Python → Rust:
      1. ManifestHashVerifier — SHA-256 do manifesto JSON (fast-path)
      2. Blacklist / whitelist / behavioral test
      3. Rust kernel — hash dos pesos (full-path, delegado)
    """

    def __init__(self, policy_engine: "Optional[PolicyEngine]" = None) -> None:
        self._policy_engine = policy_engine
        self.detector = AbliterationDetector(policy_engine=policy_engine)
        self._manifest_verifier = ManifestHashVerifier()

    def verify(self, model_id: str, model_callable: Optional[Callable] = None) -> bool:
        """
        Verifica se um modelo é seguro para uso.

        Ordem:
          1. Manifest hash Python (ADR-042 Fase 2) — fast-path, BLOCK se inválido
          2. Blacklist check
          3. Whitelist fast-path
          4. Unknown model — behavioral test
          5. Fail-secure para desconhecidos

        Returns:
            True se SEGURO/ÍNTEGRO. False se COMPROMETIDO/ABLITERADO.
        """
        logger.debug("Verifying integrity for model: %s", model_id)

        # 1. Manifest hash — Python fast-path (ADR-042 Fase 2)
        if self._policy_engine is not None:
            mv_result = self._manifest_verifier.verify(model_id, self._policy_engine)
            if not mv_result.is_valid:
                logger.error(
                    "BLOCK: manifest hash failed for '%s'. %s",
                    model_id, mv_result.explain_decision(),
                )
                return False
            logger.debug(
                "verify: '%s' manifest OK — %s",
                model_id, mv_result.explain_decision(),
            )

        # 2. Blacklist Check
        if is_known_abliterated(model_id):
            logger.error("BLOCK: Model %s is in the ABLITERATED registry.", model_id)
            return False

        # 3. Whitelist Fast-path
        info = get_model_info(model_id)
        if info and info.status == ModelStatus.LEGITIMATE:
            return True

        # 4. Unknown Model — Run Behavioral Tests if callable provided
        if model_callable:
            is_compromised = self.detector.detect(model_id)
            if is_compromised:
                logger.error("BLOCK: Behavioral test failed for unknown model %s.", model_id)
                return False

        # 5. Fail-secure para desconhecidos (Jonas: precaução máxima)
        logger.warning(
            "BLOCK: Model '%s' not in registry. "
            "Fail-secure applied. Register in LEGITIMATE_MODELS to allow.",
            model_id,
        )
        return False


# ==========================================
# API PÚBLICA
# ==========================================

def verify_model_integrity(
    model_id: str,
    model_callable: Optional[Callable] = None,
    policy_engine: "Optional[PolicyEngine]" = None,
) -> bool:
    """
    Função de conveniência para verificar integridade.

    Cria IntegrityVerifier por chamada — sem singleton global.
    Em FastAPI, prefira injetar IntegrityVerifier via Depends().
    """
    return IntegrityVerifier(policy_engine=policy_engine).verify(model_id, model_callable)


def get_tri(model_id: str) -> float:
    """Retorna o Tamper Resistance Index (0.0 a 1.0)."""
    info = get_model_info(model_id)
    if info:
        return info.tamper_resistance_index
    return 0.0
