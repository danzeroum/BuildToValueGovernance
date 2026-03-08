# python/buildtovalue/governance/bias_guardian.py
"""
BiasGuardian - Módulo de Proteção de Justiça Algorítmica.

Garante que modelos utilizados para decisões sensíveis ou análise de viés
sejam íntegros e não-comprometidos (não-abliterados).

Referências:
    - ADR-036: BiasGuardian Implementation
    - ADR-052: Abliteration Detection Integration
    - Iteração 2: model_integrity.py
"""

import logging
from enum import Enum
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass

# Importações internas (Iteração 2 e 4)
from .model_integrity import (
    ModelStatus,
    get_model_info,
)
from .model_integrity_verifier import (
    verify_model_integrity,
    get_tri,
)
from .exceptions import SecurityViolation, IntegrityCheckFailed

logger = logging.getLogger("btv.governance.bias_guardian")

# ==========================================
# RESULTADO DA GUARDA
# ==========================================

@dataclass
class GuardianVerdict:
    """Resultado da avaliação do BiasGuardian."""
    allowed: bool
    model_id: str
    reason: str
    tri_score: float = 1.0  # Tamper Resistance Index
    warnings: list = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []

# ==========================================
# BIAS GUARDIAN
# ==========================================

class BiasGuardian:
    """
    Guardião que verifica a elegibilidade de modelos antes de operações críticas.
    
    Políticas:
    1. Modelos Abliterados -> BLOCK (SecurityViolation).
    2. Modelos Desconhecidos -> WARN/ESCALATE (Policy definível).
    3. Modelos Legítimos -> ALLOW.
    """
    
    def __init__(self, fail_on_unknown: bool = False):
        """
        Args:
            fail_on_unknown: Se True, modelos desconhecidos são tratados como 
                             inseguros (fail-secure). Se False, permite com aviso.
        """
        self.fail_on_unknown = fail_on_unknown

    def check_eligibility(self, model_id: str) -> GuardianVerdict:
        """
        Verifica se o modelo tem permissão para operar.
        
        Este é o ponto de entrada principal para qualquer pipeline de IA.
        """
        logger.info(f"BiasGuardian checking eligibility for: {model_id}")
        
        # 1. Consulta o registro de integridade (Iteração 2)
        info = get_model_info(model_id)
        tri = get_tri(model_id)

        # 2. Verificação Explícita de Abliteration
        if info and info.status == ModelStatus.ABLITERATED:
            logger.error(f"BLOCK: Model {model_id} is marked as ABLITERATED.")
            raise SecurityViolation(
                message="Model has been tampered with (abliteration detected).",
                model_id=model_id
            )
        
        # 3. Modelo Legítimo
        if info and info.status == ModelStatus.LEGITIMATE:
            logger.info(f"ALLOW: Model {model_id} is LEGITIMATE (TRI: {tri}).")
            return GuardianVerdict(
                allowed=True,
                model_id=model_id,
                reason="Verified legitimate model.",
                tri_score=tri
            )

        # 4. Modelo Desconhecido (Caso default)
        # Política depende da configuração `fail_on_unknown`
        if self.fail_on_unknown:
            logger.warning(f"BLOCK: Model {model_id} is UNKNOWN and policy is fail-secure.")
            raise IntegrityCheckFailed(
                message="Unknown model encountered in strict mode.",
                model_id=model_id
            )
        else:
            logger.warning(f"WARN: Model {model_id} is UNKNOWN. Proceeding with caution.")
            return GuardianVerdict(
                allowed=True,
                model_id=model_id,
                reason="Unknown model allowed per policy (warn mode).",
                tri_score=tri,
                warnings=["Model not in trusted registry."]
            )

    def safe_evaluate(self, model_id: str, eval_func: Callable, *args, **kwargs) -> Any:
        """
        Executa uma função de avaliação (ex: cálculo de métrica de justiça)
        somente se o modelo for elegível.
        
        Args:
            model_id: ID do modelo.
            eval_func: Função a ser executada (ex: `calculate_fairness`).
            
        Returns:
            Resultado da `eval_func`.
            
        Raises:
            SecurityViolation: Se o modelo for comprometido.
        """
        # O check_eligibilidade já lança exceção se bloqueado
        verdict = self.check_eligibility(model_id)
        
        if not verdict.allowed:
            # Este bloco é redundante (exceção já teria sido lançada), mas seguro
            raise SecurityViolation("Model not allowed.", model_id)

        logger.info(f"Executing safe evaluation for {model_id}...")
        
        # Executa a função passada
        try:
            result = eval_func(*args, **kwargs)
            return result
        except Exception as e:
            logger.error(f"Error during safe evaluation: {e}")
            raise

# ==========================================
# API GLOBAL
# ==========================================

# Instância global com política padrão (warn on unknown)
_default_guardian = BiasGuardian(fail_on_unknown=False)

def check_model(model_id: str) -> GuardianVerdict:
    """Atalho para verificação rápida."""
    return _default_guardian.check_eligibility(model_id)

def run_safe(model_id: str, func: Callable, *args, **kwargs) -> Any:
    """Atalho para execução segura."""
    return _default_guardian.safe_evaluate(model_id, func, *args, **kwargs)

# ─────────────────────────────────────────────────────────────────────────────
# ADR-036: DivergenceLevel enum (maiúsculas conforme spec)
# ─────────────────────────────────────────────────────────────────────────────

class DivergenceLevel(Enum):
    OK      = "OK"
    WARNING = "WARNING"
    BLOCK   = "BLOCK"
