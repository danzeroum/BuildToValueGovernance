"""
Profile Manager - Gerenciador de perfis de governança.
Carrega e resolve herança hierárquica de perfis YAML.
"""
import yaml
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class DomainConfig:
    """Configuração específica de domínio."""
    risk_multiplier: Optional[float] = None
    allowed_findings: List[str] = None
    blocked_findings: List[str] = None
    education_message: Optional[str] = None


class ProfileManager:
    """
    Gerenciador de perfis de governança.

    Suporta:
    - Carregamento de perfis YAML
    - Herança hierárquica (parent_id)
    - Cache em memória
    - Merge de domain_config
    """

    def __init__(self, config_dir: Path):
        """
        Inicializa gerenciador.

        Args:
            config_dir: Diretório com arquivos YAML de perfis
        """
        self.config_dir = Path(config_dir)
        self._cache: Dict[str, Any] = {}

    def load_profile(self, profile_name: str) -> 'Profile':
        """
        Carrega perfil por nome.

        Args:
            profile_name: Nome do perfil (ex: "general", "healthcare")

        Returns:
            Profile com herança resolvida

        Raises:
            ValueError: Se perfil não encontrado ou herança circular
        """
        # Cache hit
        if profile_name in self._cache:
            return self._cache[profile_name]

        # Carrega do YAML
        yaml_path = self.config_dir / f"{profile_name}.yaml"
        if not yaml_path.exists():
            raise ValueError(f"Profile not found: {profile_name}")

        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)

        # Parse Profile
        profile = Profile(
            name=data['name'],
            parent_id=data.get('parent_id'),
            rules=[Rule(**r) for r in data.get('rules', [])],
            domain_config={
                k: DomainConfig(**v) for k, v in data.get('domain_config', {}).items()
            }
        )

        # Cache antes de resolver herança (para detectar circular)
        self._cache[profile_name] = profile

        # Resolve herança
        if profile.parent_id:
            self._resolve_inheritance(profile_name)

        return profile

    def _resolve_inheritance(self, profile_id: str, visited: set = None):
        """
        Resolve herança recursiva (DFS).

        Ordem de aplicação de regras:
        1. Regras do pai (recursivamente até base)
        2. Regras do filho
        3. Ordena por prioridade
        4. Remove duplicados (filho override pai se mesmo ID)
        """
        if visited is None:
            visited = set()

        if profile_id in visited:
            raise ValueError(f"Circular inheritance: {profile_id}")

        visited.add(profile_id)

        profile = self._cache[profile_id]

        if not profile.parent_id:
            return  # Base profile

        # Resolve pai primeiro
        parent_id = profile.parent_id
        if parent_id not in self._cache:
            # Carrega pai recursivamente
            self.load_profile(parent_id)

        self._resolve_inheritance(parent_id, visited)
        parent = self._cache[parent_id]

        # Herda regras do pai (exceto se filho override)
        child_rule_ids = {r.id for r in profile.rules}
        inherited_rules = [
            r for r in parent.rules
            if r.id not in child_rule_ids
        ]

        # Combina: herdadas + próprias
        profile.rules = inherited_rules + profile.rules

        # Ordena por prioridade (maior = mais importante)
        profile.rules.sort(key=lambda r: r.priority, reverse=True)

        # Herda domain_config (merge)
        for domain, parent_config in parent.domain_config.items():
            if domain not in profile.domain_config:
                profile.domain_config[domain] = parent_config
            else:
                # Merge (filho sobrescreve pai)
                child_config = profile.domain_config[domain]
                merged = DomainConfig(
                    risk_multiplier=child_config.risk_multiplier or parent_config.risk_multiplier,
                    allowed_findings=list(set(
                        (child_config.allowed_findings or []) + (parent_config.allowed_findings or [])
                    )),
                    blocked_findings=list(set(
                        (child_config.blocked_findings or []) + (parent_config.blocked_findings or [])
                    )),
                    education_message=child_config.education_message or parent_config.education_message,
                )
                profile.domain_config[domain] = merged

    def clear_cache(self):
        """Limpa cache de perfis."""
        self._cache.clear()
