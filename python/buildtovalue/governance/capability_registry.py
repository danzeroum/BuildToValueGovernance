"""CapabilityRegistry — Gap C: Capability-Based Access Control (Registry).

Loads per-agent capability grants from YAML. Provides lookup for
whether an agent has specific capabilities.

Invariants:
- Fail-secure: unknown agent -> default capabilities only
- Revoked capabilities override grants
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set

import yaml

logger = logging.getLogger("btv.governance.capability_registry")


@dataclass(frozen=True)
class CapabilityResult:
    allowed: bool
    missing: FrozenSet[str]
    explain: str


class CapabilityRegistry:
    """Registry of per-agent capability grants."""

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        raw = self._load(policy_path) if policy_path else {}
        self._defaults: Set[str] = set(
            raw.get("default_capabilities", [])
        )
        self._agents: Dict[str, Set[str]] = {}
        self._revoked: Dict[str, Set[str]] = {}
        for aid, cfg in raw.get("agents", {}).items():
            grants = set(cfg.get("capabilities", []))
            revoked = set(cfg.get("revoked", []))
            self._agents[aid] = grants - revoked
            self._revoked[aid] = revoked
        self._hierarchy: Dict[str, List[str]] = {}
        for cap, meta in raw.get("hierarchy", {}).items():
            self._hierarchy[cap] = meta.get("requires", [])

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def capabilities_for(self, agent_id: str) -> FrozenSet[str]:
        """Return effective capabilities for an agent."""
        if agent_id in self._agents:
            return frozenset(self._agents[agent_id])
        return frozenset(self._defaults)

    def has_capability(self, agent_id: str, capability: str) -> bool:
        return capability in self.capabilities_for(agent_id)

    def check_capabilities(
        self,
        agent_id: str,
        required: List[str],
    ) -> CapabilityResult:
        """Check if agent has all required capabilities."""
        effective = self.capabilities_for(agent_id)
        missing = frozenset(set(required) - effective)
        if missing:
            return CapabilityResult(
                allowed=False,
                missing=missing,
                explain=f"Agent '{agent_id}' missing: {sorted(missing)}",
            )
        return CapabilityResult(
            allowed=True,
            missing=frozenset(),
            explain=f"Agent '{agent_id}' has all required capabilities",
        )

    def check_hierarchy(
        self, agent_id: str, capability: str
    ) -> CapabilityResult:
        """Check capability and its prerequisites."""
        required = [capability]
        prereqs = self._hierarchy.get(capability, [])
        required.extend(prereqs)
        return self.check_capabilities(agent_id, required)
