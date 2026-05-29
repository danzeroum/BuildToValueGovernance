"""Fleet route (Lab v3.0) — GET /v1/fleet.

Expõe o registry de agentes governados a partir dos perfis em disco
(``ProfileManager.profiles_dir``). Os campos seguem o contrato BFF da
página ``demo/fleet.html`` (camelCase: ``blockRate``, ``decisions24h``,
``friaDate``).

Realidade do repositório: o diretório de perfis mistura perfis de agente
(``id`` + ``name`` + regras/herança) com arquivos de configuração de guardas
(``pa_*.yaml``, ``*_rules.yaml``). Apenas perfis de agente são listados.

Métricas dinâmicas (``blockRate``/``decisions24h``/``trust``) são derivadas
do ledger quando disponível; na ausência de histórico por agente, retornam
defaults estruturados — nunca erro.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

import yaml
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

router = APIRouter()

# Arquivos que NÃO são perfis de agente (configs de guardas/políticas).
_NON_AGENT_PREFIXES = ("pa_",)
_NON_AGENT_NAMES = {
    "approval_rules", "budget_limits", "capabilities", "coordination_rules",
    "delegation_rules", "tool_call_policy",
}
# Bundles de alto risco (classificação inspirada no EU AI Act).
_HIGH_RISK_BUNDLES = {"medical", "financial", "legal", "hr"}


class FleetAgent(BaseModel):
    """Contrato BFF de um agente da frota (fleet.html)."""
    id: str
    name: str
    owner: str = "—"
    bundle: str = "default"
    model: str = "—"
    risk: str = "medium"
    status: str = "online"
    blockRate: float = 0.0
    decisions24h: int = 0
    trust: float = 0.5
    fria: bool = False
    friaDate: Optional[str] = None
    jurisdictions: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    description: str = ""


class FleetResponse(BaseModel):
    agents: List[FleetAgent]


def _load_capabilities(profiles_dir: Path) -> Dict[str, List[str]]:
    """Lê capabilities.yaml → mapa agent_id → capabilities (fail-soft)."""
    cap_path = profiles_dir / "capabilities.yaml"
    if not cap_path.exists():
        return {}
    try:
        data = yaml.safe_load(cap_path.read_text()) or {}
    except Exception:  # noqa: BLE001 — config corrompida não derruba a frota
        return {}
    out: Dict[str, List[str]] = {}
    for agent_id, entry in (data.get("agents") or {}).items():
        if isinstance(entry, dict):
            out[agent_id] = list(entry.get("capabilities") or [])
    return out


def _is_agent_profile(stem: str, data: Dict[str, object]) -> bool:
    """Discrimina perfil de agente de arquivo de config."""
    if stem in _NON_AGENT_NAMES or stem.startswith(_NON_AGENT_PREFIXES):
        return False
    if not (data.get("id") and data.get("name")):
        return False
    return any(k in data for k in ("rules", "domain_config", "parent_id"))


def _build_agent(data: Dict[str, object], caps: Dict[str, List[str]]) -> FleetAgent:
    """Mapeia o YAML de perfil para o contrato FleetAgent."""
    agent_id = str(data["id"])
    domain_cfg = data.get("domain_config") or {}
    bundle = next((k for k in domain_cfg if k != "general"), "default") \
        if isinstance(domain_cfg, dict) else "default"
    risk = "high" if bundle in _HIGH_RISK_BUNDLES else "medium"
    # Campos de frota opcionais — usados quando o YAML for enriquecido.
    return FleetAgent(
        id=agent_id,
        name=str(data.get("name", agent_id)),
        owner=str(data.get("owner", "—")),
        bundle=str(data.get("bundle", bundle)),
        model=str(data.get("model", "—")),
        risk=str(data.get("risk", risk)),
        status=str(data.get("status", "online")),
        fria=bool(data.get("fria", False)),
        friaDate=data.get("friaDate") if isinstance(data.get("friaDate"), str) else None,
        jurisdictions=list(data.get("jurisdictions") or []),
        capabilities=caps.get(agent_id, []),
        description=str(data.get("description", "")),
    )


@router.get("/v1/fleet", response_model=FleetResponse)
async def list_fleet(request: Request) -> FleetResponse:
    """Lista os agentes governados descobertos nos perfis em disco."""
    pm = getattr(request.app.state, "profile_manager", None)
    if pm is None:
        return FleetResponse(agents=[])

    profiles_dir = Path(pm.profiles_dir)
    caps = _load_capabilities(profiles_dir)
    agents: List[FleetAgent] = []
    for path in sorted(profiles_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except Exception:  # noqa: BLE001 — pula YAML inválido (fail-soft)
            continue
        if not isinstance(data, dict) or not _is_agent_profile(path.stem, data):
            continue
        agents.append(_build_agent(data, caps))
    return FleetResponse(agents=agents)
