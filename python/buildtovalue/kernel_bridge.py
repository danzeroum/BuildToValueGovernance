# python/buildtovalue/kernel_bridge.py
"""
Kernel Bridge - Ligação entre a Governança Python e o Kernel Rust.

Responsável por:
1. Carregar configurações de Policy (YAML).
2. Injetar configurações no Kernel Rust via FFI.
"""

import yaml
import logging
import json
from typing import Dict, Any
from pathlib import Path

logger = logging.getLogger("btv.kernel_bridge")


class KernelBridge:
    """
    Gerencia a comunicação com o Kernel Rust.
    """

    def __init__(self, rust_lib):
        """
        Args:
            rust_lib: O módulo Rust compilado (via PyO3).
        """
        self.lib = rust_lib
        self.config_cache: Dict[str, Any] = {}

    def load_sensitivity_config(self, yaml_path: str) -> bool:
        """
        Carrega a configuração de sensibilidade de um YAML e injeta no Rust.

        Args:
            yaml_path: Caminho para data/policies/security/sensitivity_weights.yaml

        Returns:
            True se a configuração foi aplicada com sucesso.
        """
        try:
            path = Path(yaml_path)
            if not path.exists():
                logger.warning(f"Config file not found: {yaml_path}. Using defaults.")
                return False

            with open(path, 'r') as f:
                config_data = yaml.safe_load(f)

            # Extrai campos relevantes para o Rust
            rust_config = {
                "intervention_threshold": float(config_data.get("intervention_threshold", 75.0)),
                "temporal_decay_factor": float(config_data.get("temporal_decay_factor", 0.95)),
                "max_history_size": int(config_data.get("max_history_size", 100)),
            }

            # Serializa para JSON (formato universal para FFI)
            config_json = json.dumps(rust_config)

            # Chama função FFI do Rust
            # Assume que o Rust expõe `update_accumulator_config(json)`
            self.lib.update_accumulator_config(config_json)

            self.config_cache['sensitivity'] = rust_config
            logger.info(f"Sensitivity config updated from {yaml_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to load sensitivity config: {e}")
            return False

    def reload_policies(self, policy_dir: str):
        """
        Recarrega todas as políticas do diretório e sincroniza com o Kernel.
        """
        # 1. Sensitivity Weights
        self.load_sensitivity_config(f"{policy_dir}/security/sensitivity_weights.yaml")

        # 2. Outras políticas (ex: patterns YAML)
        # O PatternRegistry Rust pode ter sua própria função reload_tier2()
        # self.lib.reload_patterns(f"{policy_dir}/security/patterns_jailbreak.yaml")