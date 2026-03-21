"""AgentBudget — Gap I: Agent Budget/Token Tracking.

Tracks per-agent, per-session token usage, cost, and API call counts.
EDUCATE at 80% budget, BLOCK at 100%.
Tool call circuit breaker per request.

Extensão (Cenário 30 — Sobrevivência a Qualquer Custo):
  - AccountTier: hierarquia de contas (Operational, Reserve, Untouchable)
  - ResourceHierarchy: verifica se o agente pode acessar uma conta financeira
  - check_budget() estendido: chama can_access() quando account_id presente
  - Retrocompatível: sem account_id no metadata → comportamento original preservado

Invariants:
- Fail-secure: budget error -> BLOCK
- Monotonic counters (never decrease)
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import yaml

from .agent_pdp import AgentVerdict
from .chatbot_gates import GateResult

logger = logging.getLogger("btv.governance.agent_budget")

_DEFAULT_TOKENS = 1_000_000
_DEFAULT_COST = 10.0
_DEFAULT_CALLS = 500
_DEFAULT_TOOLS_PER_REQ = 20
_EDUCATE_PCT = 0.80


@dataclass
class BudgetLimits:
    max_tokens: int = _DEFAULT_TOKENS
    max_cost_usd: float = _DEFAULT_COST
    max_api_calls: int = _DEFAULT_CALLS
    max_tools_per_request: int = _DEFAULT_TOOLS_PER_REQ


@dataclass
class BudgetStatus:
    agent_id: str
    session_id: str
    tokens_used: int
    tokens_remaining: int
    cost_used_usd: float
    cost_remaining_usd: float
    api_calls_used: int
    api_calls_remaining: int


# ---------------------------------------------------------------------------
# Cenário 30 — Hierarquia de Contas Financeiras
# ---------------------------------------------------------------------------

class AccountTier(Enum):
    """Tier de conta financeira — proteção crescente."""
    OPERATIONAL = "operational"   # despesas correntes do agente
    RESERVE     = "reserve"       # reserva: exige assinatura humana
    UNTOUCHABLE = "untouchable"   # intocável: BLOCK absoluto


@dataclass(frozen=True)
class ResourceHierarchy:
    """Hierarquia de contas financeiras com limites e proteções.

    Exemplo de uso:
        hierarchy = ResourceHierarchy(
            accounts={"wallet_op": AccountTier.OPERATIONAL,
                      "savings": AccountTier.RESERVE},
            daily_operational_limit_brl=Decimal("500.00"),
            human_sig_required_above_brl=Decimal("1000.00"),
        )
        ok, reason = hierarchy.can_access("savings", Decimal("100"), has_human_sig=False)
        # → (False, "Conta reserva exige assinatura humana")
    """
    accounts: Dict[str, AccountTier]
    daily_operational_limit_brl: Decimal
    human_sig_required_above_brl: Decimal

    def can_access(
        self,
        account_id: str,
        amount: Decimal,
        has_human_sig: bool,
    ) -> Tuple[bool, str]:
        """Verifica se o agente pode acessar `account_id` com `amount`.

        Fail-secure: account_id ausente no mapa → Reserve (não Operational).
        """
        tier = self.accounts.get(account_id, AccountTier.RESERVE)  # fail-secure

        if tier == AccountTier.UNTOUCHABLE:
            return False, f"Conta '{account_id}' intocável — BLOCK absoluto"

        if tier == AccountTier.RESERVE and not has_human_sig:
            return False, f"Conta reserva '{account_id}' exige assinatura humana"

        if amount > self.daily_operational_limit_brl and not has_human_sig:
            return (
                False,
                f"Valor R${amount} excede limite diário R${self.daily_operational_limit_brl}"
                " — assinatura humana obrigatória",
            )

        return True, "Dentro dos limites autorizados"


@dataclass
class _Usage:
    tokens: int = 0
    cost_usd: float = 0.0
    api_calls: int = 0
    tool_calls_in_request: Dict[str, int] = field(default_factory=dict)


class AgentBudget:
    """Tracks and enforces per-agent, per-session resource budgets."""

    def __init__(
        self,
        policy_path: Optional[Path] = None,
        resource_hierarchy: Optional[ResourceHierarchy] = None,
    ) -> None:
        self._resource_hierarchy = resource_hierarchy
        raw = self._load(policy_path) if policy_path else {}
        defaults = raw.get("defaults", {})
        self._default = BudgetLimits(
            max_tokens=defaults.get("max_tokens", _DEFAULT_TOKENS),
            max_cost_usd=defaults.get("max_cost_usd", _DEFAULT_COST),
            max_api_calls=defaults.get("max_api_calls", _DEFAULT_CALLS),
            max_tools_per_request=defaults.get(
                "max_tools_per_request", _DEFAULT_TOOLS_PER_REQ
            ),
        )
        self._agents: Dict[str, BudgetLimits] = {}
        for aid, cfg in raw.get("agents", {}).items():
            self._agents[aid] = BudgetLimits(
                max_tokens=cfg.get("max_tokens", self._default.max_tokens),
                max_cost_usd=cfg.get("max_cost_usd", self._default.max_cost_usd),
                max_api_calls=cfg.get("max_api_calls", self._default.max_api_calls),
                max_tools_per_request=cfg.get(
                    "max_tools_per_request", self._default.max_tools_per_request
                ),
            )
        self._usage: Dict[Tuple[str, str], _Usage] = {}

    @staticmethod
    def _load(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def _limits(self, agent_id: str) -> BudgetLimits:
        return self._agents.get(agent_id, self._default)

    def _key(self, agent_id: str, session_id: str) -> Tuple[str, str]:
        return (agent_id, session_id)

    def _get_usage(self, agent_id: str, session_id: str = "") -> _Usage:
        k = self._key(agent_id, session_id)
        if k not in self._usage:
            self._usage[k] = _Usage()
        return self._usage[k]

    def check_budget(
        self,
        agent_id: str,
        estimated_tokens: int = 0,
        session_id: str = "",
        account_id: Optional[str] = None,
        amount_brl: Optional[Decimal] = None,
        has_human_sig: bool = False,
    ) -> GateResult:
        """Check budget. EDUCATE at 80%, BLOCK at 100%.

        Extensão Cenário 30: se account_id fornecido, verifica ResourceHierarchy.
        Retrocompatível: sem account_id → comportamento original preservado.
        """
        # Cenário 30: verificação de hierarquia de contas (se configurada)
        if account_id is not None and self._resource_hierarchy is not None:
            ok, reason = self._resource_hierarchy.can_access(
                account_id,
                amount_brl or Decimal("0"),
                has_human_sig,
            )
            if not ok:
                return _block(f"ResourceHierarchy: {reason}")

        limits = self._limits(agent_id)
        usage = self._get_usage(agent_id, session_id)
        projected = usage.tokens + estimated_tokens

        if projected > limits.max_tokens:
            return _block(f"Token limit: {usage.tokens}/{limits.max_tokens}")
        if usage.cost_usd >= limits.max_cost_usd:
            return _block(f"Cost limit: ${usage.cost_usd:.2f}/${limits.max_cost_usd:.2f}")
        if usage.api_calls >= limits.max_api_calls:
            return _block(f"API call limit: {usage.api_calls}/{limits.max_api_calls}")

        if projected > limits.max_tokens * _EDUCATE_PCT:
            return _educate(f"Token budget at {projected/limits.max_tokens:.0%}")
        if usage.cost_usd >= limits.max_cost_usd * _EDUCATE_PCT:
            return _educate(f"Cost budget at {usage.cost_usd/limits.max_cost_usd:.0%}")
        if usage.api_calls >= limits.max_api_calls * _EDUCATE_PCT:
            return _educate(f"API calls at {usage.api_calls/limits.max_api_calls:.0%}")

        return _allow("Within budget")

    def record_usage(
        self, agent_id: str, tokens_used: int = 0,
        cost_usd: float = 0.0, session_id: str = "",
    ) -> None:
        """Record resource consumption (monotonic)."""
        usage = self._get_usage(agent_id, session_id)
        usage.tokens += tokens_used
        usage.cost_usd += cost_usd
        usage.api_calls += 1

    def check_tool_calls(
        self, agent_id: str, request_id: str, session_id: str = "",
    ) -> GateResult:
        """Circuit breaker: BLOCK if too many tool calls per request."""
        limits = self._limits(agent_id)
        usage = self._get_usage(agent_id, session_id)
        count = usage.tool_calls_in_request.get(request_id, 0) + 1
        usage.tool_calls_in_request[request_id] = count
        if count > limits.max_tools_per_request:
            return _block(f"Tool calls {count} > {limits.max_tools_per_request}/req")
        return _allow(f"Tool call {count}/{limits.max_tools_per_request}")

    def get_remaining(
        self, agent_id: str, session_id: str = "",
    ) -> BudgetStatus:
        limits = self._limits(agent_id)
        usage = self._get_usage(agent_id, session_id)
        return BudgetStatus(
            agent_id=agent_id, session_id=session_id,
            tokens_used=usage.tokens,
            tokens_remaining=max(0, limits.max_tokens - usage.tokens),
            cost_used_usd=usage.cost_usd,
            cost_remaining_usd=max(0.0, limits.max_cost_usd - usage.cost_usd),
            api_calls_used=usage.api_calls,
            api_calls_remaining=max(0, limits.max_api_calls - usage.api_calls),
        )

    def reset(self, agent_id: str, session_id: str = "") -> None:
        self._usage.pop(self._key(agent_id, session_id), None)


def _block(reason: str) -> GateResult:
    logger.warning("BLOCK: agent_budget %s", reason)
    return GateResult(
        verdict=AgentVerdict.BLOCK, evidence_id=None,
        explain=f"[agent_budget] {reason}", gate="agent_budget",
    )

def _educate(reason: str) -> GateResult:
    return GateResult(
        verdict=AgentVerdict.EDUCATE, evidence_id=None,
        explain=f"[agent_budget] {reason}", gate="agent_budget",
    )

def _allow(reason: str) -> GateResult:
    return GateResult(
        verdict=AgentVerdict.ALLOW, evidence_id=None,
        explain=f"[agent_budget] {reason}", gate="agent_budget",
    )
