"""
Profile Manager v2.0 - Hierarchical Profile System

Responsabilidades:
- Carrega perfis de YAML
- Resolve herança hierárquica (parent → child)
- Cache de perfis
- Validação de integridade

Hierarquia exemplo:
  base (root)
    ├─ medical-agent
    │   └─ specialized-medical
    ├─ research-agent
    └─ legal-agent

Gate: Week 4 - Day 17
"""

import yaml
from pathlib import Path
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field
import logging
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# AGENT MODULE CONFIG — maps agent_policies YAML names to guard module paths
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AgentModuleConfig:
    """
    Maps agent policy YAML names to the Path each guard module should load.

    None = module disabled (fail-secure: unknown name → module stays off).
    No YAML schema merge is performed — each module reads its own config file
    directly (correct by design: agents/*.yaml are module configs, not PolicyEngine rules).
    """
    visual_firewall:   Optional[Path] = None   # VisualInputFirewall
    channel_authority: Optional[Path] = None   # ChannelAuthorityVerifier
    oracle_trust_gate: Optional[Path] = None   # OracleTrustGate
    rag_verifier:      Optional[Path] = None   # RagIntegrityVerifier
    skill_monitor:     Optional[Path] = None   # SkillBehaviorMonitor
    liveness_monitor:  Optional[Path] = None   # LivenessMonitor


# ═══════════════════════════════════════════════════════════════════════════
# PROFILE TYPES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PolicyRule:
    """Regra de policy individual."""
    id: str
    name: str
    description: str
    action: str  # ALLOW, LOG, EDUCATE, REDACT, BLOCK
    priority: int

    # Condições
    validators: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    min_severity: float = 0.0
    min_confidence: float = 0.0

@dataclass
class DomainConfig:
    """Configuração específica de domínio."""
    risk_multiplier: float = 1.0
    allowed_findings: List[str] = field(default_factory=list)
    blocked_findings: List[str] = field(default_factory=list)
    education_message: str = ""

@dataclass
class Profile:
    """Perfil de governance com herança."""
    id: str
    name: str
    description: str

    # Herança
    parent_id: Optional[str] = None

    # Regras (ordenadas por prioridade)
    rules: List[PolicyRule] = field(default_factory=list)

    # Config por domínio
    domain_config: Dict[str, DomainConfig] = field(default_factory=dict)

    # Metadata
    version: str = "1.0.0"
    created_at: str = ""
    updated_at: str = ""
    output_schema: Optional[Dict[str, Any]] = None


# ═══════════════════════════════════════════════════════════════════════════
# PROFILE MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class ProfileManager:
    """
    Profile Manager v2.0 - Hierarchical System.

    Features:
    - Load profiles from YAML
    - Resolve inheritance (parent → child)
    - Cache profiles (memory)
    - Override rules (child overrides parent with same ID)
    - Merge domain configs

    Performance: <5ms per profile load (cached)
    """

    def __init__(self, profiles_dir: Path):
        """
        Inicializa manager.

        Args:
            profiles_dir: Diretório com arquivos YAML de perfis
        """
        self.profiles_dir = Path(profiles_dir)
        self.cache: Dict[str, Profile] = {}

        # Metrics
        self.metrics = {
            'profiles_loaded': 0,
            'cache_hits': 0,
            'cache_misses': 0,
        }

    def load_profile(self, profile_id: str) -> Profile:
        """
        Carrega perfil por ID.

        Args:
            profile_id: ID do perfil (e.g., "base", "medical-agent")

        Returns:
            Profile com herança resolvida

        Raises:
            ValueError: Se perfil não encontrado ou herança circular
        """
        # Cache hit
        if profile_id in self.cache:
            self.metrics['cache_hits'] += 1
            return self.cache[profile_id]

        self.metrics['cache_misses'] += 1

        # Load from YAML
        yaml_path = self.profiles_dir / f"{profile_id}.yaml"
        if not yaml_path.exists():
            raise ValueError(f"Profile not found: {profile_id}")

        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)

        # Parse profile
        profile = self._parse_profile(data)

        # Cache (antes de resolver herança para detectar circular)
        self.cache[profile_id] = profile

        # Resolve herança se tem parent
        if profile.parent_id:
            self._resolve_inheritance(profile_id)

        self.metrics['profiles_loaded'] += 1
        logger.info(f"Profile loaded: {profile_id} (parent: {profile.parent_id or 'none'})")

        return profile

    def _parse_profile(self, data: Dict[str, Any]) -> Profile:
        """Parse YAML data para Profile."""
        # Parse rules
        rules = []
        for rule_data in data.get('rules', []):
            if not isinstance(rule_data, dict):
                continue
            rule = PolicyRule(
                id=rule_data.get('id', ''),
                name=rule_data.get('name', ''),
                description=rule_data.get('description', ''),
                action=rule_data.get('action', 'ALLOW'),
                priority=rule_data.get('priority', 100),
                validators=rule_data.get('validators', []),
                categories=rule_data.get('categories', []),
                min_severity=rule_data.get('min_severity', 0.0),
                min_confidence=rule_data.get('min_confidence', 0.0),
            )
            rules.append(rule)

        # Parse domain configs
        domain_config = {}
        for domain, config_data in data.get('domain_config', {}).items():
            if not isinstance(config_data, dict):
                continue
            config = DomainConfig(
                risk_multiplier=config_data.get('risk_multiplier', 1.0),
                allowed_findings=config_data.get('allowed_findings', []),
                blocked_findings=config_data.get('blocked_findings', []),
                education_message=config_data.get('education_message', ''),
            )
            domain_config[domain] = config

        # Create profile — use .get() so non-profile YAMLs don't crash
        return Profile(
            id=data.get('id', ''),
            name=data.get('name', ''),
            description=data.get('description', ''),
            parent_id=data.get('parent_id'),
            rules=rules,
            domain_config=domain_config,
            version=data.get('version', '1.0.0'),
            created_at=data.get('created_at', ''),
            updated_at=data.get('updated_at', ''),
            output_schema=data.get('output_schema'),
        )

    def _resolve_inheritance(self, profile_id: str, visited: Optional[set] = None):
        """
        Resolve herança recursiva (DFS).

        Ordem de aplicação:
        1. Regras do pai (recursivamente até base)
        2. Regras do filho
        3. Ordena por prioridade
        4. Remove duplicados (filho override pai se mesmo ID)

        Args:
            profile_id: ID do perfil
            visited: Set de IDs visitados (detecta circular)

        Raises:
            ValueError: Se herança circular detectada
        """
        if visited is None:
            visited = set()

        # Detecta circular
        if profile_id in visited:
            raise ValueError(f"Circular inheritance detected: {profile_id}")

        visited.add(profile_id)

        profile = self.cache[profile_id]

        # Base case: sem parent
        if not profile.parent_id:
            return

        # Resolve parent primeiro (recursivo)
        parent_id = profile.parent_id
        if parent_id not in self.cache:
            self.load_profile(parent_id)

        self._resolve_inheritance(parent_id, visited)

        parent = self.cache[parent_id]

        # Herda regras do pai (exceto se filho override)
        child_rule_ids = {r.id for r in profile.rules}
        inherited_rules = [r for r in parent.rules if r.id not in child_rule_ids]

        # Combina: herdadas + próprias
        profile.rules = inherited_rules + profile.rules

        # Ordena por prioridade (maior = mais importante)
        profile.rules.sort(key=lambda r: r.priority, reverse=True)

        # Herda domain configs (merge)
        for domain, parent_config in parent.domain_config.items():
            if domain not in profile.domain_config:
                # Herda completamente
                profile.domain_config[domain] = parent_config
            else:
                # Merge (filho sobrescreve pai)
                child_config = profile.domain_config[domain]
                merged = DomainConfig(
                    risk_multiplier=child_config.risk_multiplier or parent_config.risk_multiplier,
                    allowed_findings=list(set(child_config.allowed_findings + parent_config.allowed_findings)),
                    blocked_findings=list(set(child_config.blocked_findings + parent_config.blocked_findings)),
                    education_message=child_config.education_message or parent_config.education_message,
                )
                profile.domain_config[domain] = merged

        logger.debug(f"Inheritance resolved: {profile_id} ← {parent_id} ({len(inherited_rules)} rules inherited)")

    def get_metrics(self) -> Dict[str, Any]:
        """Retorna métricas."""
        return {
            **self.metrics,
            'cache_size': len(self.cache),
            'cache_hit_rate': self.metrics['cache_hits'] / max(self.metrics['cache_hits'] + self.metrics['cache_misses'], 1),
        }

    def clear_cache(self):
        """Limpa cache (útil para reloads)."""
        self.cache.clear()
        logger.info("Profile cache cleared")

    def resolve_module_config(self, agent_policies: List[str]) -> "AgentModuleConfig":
        """
        Maps a list of agent policy YAML names to an AgentModuleConfig.

        Each name corresponds to a file in data/policies/agents/ that a specific
        Python guard module should load for its configuration.  Unknown names are
        silently ignored (fail-secure: module stays disabled).

        This method does NOT merge schemas — the PolicyEngine (Legislativo) handles
        condition→action rules; this method only resolves *which module gets which
        YAML path* for runtime activation.

        Args:
            agent_policies: list of YAML base-names, e.g. ["pa_channel_hierarchy",
                            "pa_p2p_oracle"].

        Returns:
            AgentModuleConfig with Path fields set for recognised policy names.
        """
        agents_dir = self.profiles_dir  # already points to data/policies/agents/

        # Static mapping: YAML name → (AgentModuleConfig field, yaml filename)
        _MAPPING: Dict[str, tuple] = {
            "pa_channel_hierarchy":  ("channel_authority",  "pa_channel_hierarchy.yaml"),
            "pa_p2p_oracle":         ("oracle_trust_gate",  "pa_p2p_oracle.yaml"),
            "pa_identity_firewall":  ("visual_firewall",    "pa_identity_firewall.yaml"),
            "pa_resource_hierarchy": ("skill_monitor",      "pa_resource_hierarchy.yaml"),
            "pa_dead_mans_switch":   ("liveness_monitor",   "pa_dead_mans_switch.yaml"),
            # pa_p2p_oracle also serves as RAG verifier config when RAG context is active
            "pa_p2p_oracle_rag":     ("rag_verifier",       "pa_p2p_oracle.yaml"),
        }

        config = AgentModuleConfig()
        for name in agent_policies:
            entry = _MAPPING.get(name)
            if entry is None:
                logger.debug("resolve_module_config: unknown policy name '%s' — skipped", name)
                continue
            field_name, yaml_file = entry
            yaml_path = agents_dir / yaml_file
            if yaml_path.exists():
                setattr(config, field_name, yaml_path)
                logger.debug(
                    "resolve_module_config: %s → %s", field_name, yaml_path
                )
            else:
                logger.warning(
                    "resolve_module_config: YAML not found for '%s' at %s — module disabled",
                    name, yaml_path,
                )
        return config
