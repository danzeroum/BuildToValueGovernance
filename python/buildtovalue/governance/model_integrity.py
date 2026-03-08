# python/buildtovalue/governance/model_integrity.py
"""
Model Integrity Module - BuildToValue Sovereign Trust OS.

Agência Reguladora: Verifica a integridade e proveniência de modelos LLM.
Detecta modelos "abliterated" (com mecanismos de recusa removidos).

Referências:
    - ADR-052: Abliteration Detection
    - ADR-049: CoT Opacity Controlled
    - ADR-036: BiasGuardian Integration
"""

import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Callable

# Configuração de logging
logger = logging.getLogger("btv.governance.integrity")


# ==========================================
# ENUMS E ESTRUTURAS DE DADOS
# ==========================================

class ModelStatus(Enum):
    """Status de conformidade de um modelo."""
    LEGITIMATE = "legitimate"  # Conhecido e seguro
    ABLITERATED = "abliterated"  # Conhecido como comprometido
    SUSPICIOUS = "suspicious"  # Comportamento anômalo
    UNKNOWN = "unknown"  # Não consta na base de dados


@dataclass
class KnownModel:
    """Registro de um modelo conhecido."""
    model_id: str
    family: str
    status: ModelStatus
    aliases: List[str] = field(default_factory=list)
    detection_date: str = ""
    notes: str = ""
    tamper_resistance_index: float = 1.0  # 1.0 = Intacto, 0.0 = Completamente Abliterado


# ==========================================
# DATABASE DE MODELOS CONHECIDOS
# ==========================================

# Modelos verificados e autorizados (Tier 1 - Confiáveis)
LEGITIMATE_MODELS: Dict[str, KnownModel] = {
    "llama-3.1-8b-instruct": KnownModel(
        model_id="llama-3.1-8b-instruct",
        family="llama",
        status=ModelStatus.LEGITIMATE,
        aliases=["llama3.1-8b", "llama-3.1-8b"],
        notes="Modelo base instruct"
    ),
    "llama-3.2-3b-instruct": KnownModel(
        model_id="llama-3.2-3b-instruct",
        family="llama",
        status=ModelStatus.LEGITIMATE,
        aliases=["llama3.2-3b"]
    ),
    "qwen2.5-7b-instruct": KnownModel(
        model_id="qwen2.5-7b-instruct",
        family="qwen",
        status=ModelStatus.LEGITIMATE,
        aliases=["qwen2.5-7b"]
    ),
}

# Modelos comprometidos (Blacklist - Tier 0)
ABLITERATED_MODELS: Dict[str, KnownModel] = {
    "heretic-llama-3.1-8b": KnownModel(
        model_id="heretic-llama-3.1-8b",
        family="llama",
        status=ModelStatus.ABLITERATED,
        aliases=["heretic-llama3.1"],
        notes="Direções de recusa removidas via técnica de abliteration.",
        detection_date="2025-12-15",
        tamper_resistance_index=0.1
    ),
    "abliterated-qwen2.5-7b": KnownModel(
        model_id="abliterated-qwen2.5-7b",
        family="qwen",
        status=ModelStatus.ABLITERATED,
        aliases=["qwen2.5-7b-abliterated"],
        notes="Mecanismo de recusa desabilitado.",
        detection_date="2025-11-20",
        tamper_resistance_index=0.15
    ),
}


# ==========================================
# FUNÇÕES DE CONSULTA
# ==========================================

def normalize_id(model_id: str) -> str:
    """Normaliza ID do modelo para busca case-insensitive."""
    return model_id.lower().strip()


def get_model_info(model_id: str) -> Optional[KnownModel]:
    """Recupera informações de um modelo conhecido."""
    norm_id = normalize_id(model_id)

    # Busca direta em legítimos
    if norm_id in LEGITIMATE_MODELS:
        return LEGITIMATE_MODELS[norm_id]
    # Busca em aliases legítimos
    for model in LEGITIMATE_MODELS.values():
        if norm_id in [normalize_id(a) for a in model.aliases]:
            return model

    # Busca direta em abliterados
    if norm_id in ABLITERATED_MODELS:
        return ABLITERATED_MODELS[norm_id]
    # Busca em aliases abliterados
    for model in ABLITERATED_MODELS.values():
        if norm_id in [normalize_id(a) for a in model.aliases]:
            return model

    return None


def is_known_abliterated(model_id: str) -> bool:
    """Verifica rapidamente se o modelo está na blacklist."""
    info = get_model_info(model_id)
    return info is not None and info.status == ModelStatus.ABLITERATED


# ==========================================
# DETECTOR DE ABLITERATION
# ==========================================

