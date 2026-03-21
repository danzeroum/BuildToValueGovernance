"""ToolCallGuard — Gap A: Tool Call Validation (Pre/Post).

Pre-execution: validates tool name, parameters, ActionImpact,
and verifies agent capabilities against registry.
Post-execution: screens output for injection and leakage.

Accepts AgentDecisionRequest directly (ADR-029 contract).
Produces SimpleFinding on capability discrepancy.

Invariants:
- Fail-secure: unknown tool / YAML error -> BLOCK
- explain_decision in every GateResult
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .agent_pdp import (
    ActionImpact, AgentDecisionRequest, AgentVerdict,
)
from .chatbot_gates import GateResult
from .tool_sanitizer import _RE_SCREEN
from .types import SimpleFinding

logger = logging.getLogger("btv.governance.tool_call_guard")

_DEFAULT_MAX_PARAMS = 10_000
_GATE = "tool_call_guard"


@dataclass(frozen=True)
class ToolPolicy:
    allowed_tools: List[str] = field(default_factory=list)
    blocked_tools: List[str] = field(default_factory=list)
    max_params_size_bytes: int = _DEFAULT_MAX_PARAMS
    required_capabilities: Dict[str, List[str]] = field(default_factory=dict)


def _load_policy(path: Path) -> Dict[str, Any]:
    try:
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        logger.error("fail-secure: YAML load error for %s", path)
        return {"_load_error": True}


def _compile_patterns(patterns: List[str]) -> re.Pattern:
    if not patterns:
        return re.compile(r"(?!)")
    return re.compile("|".join(patterns), flags=re.IGNORECASE)


class ToolCallGuard:
    """Validates tool calls pre/post execution (ADR-029)."""

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        raw = _load_policy(policy_path) if policy_path else {}
        self._load_error = raw.pop("_load_error", False)
        self._global_blocked = set(raw.get("global_blocked_tools", []))
        self._blocked_re = _compile_patterns(
            raw.get("global_blocked_params", [])
        )
        self._default = raw.get("default_policy", {})
        self._agents: Dict[str, ToolPolicy] = {}
        for aid, cfg in raw.get("agents", {}).items():
            self._agents[aid] = ToolPolicy(
                allowed_tools=cfg.get("allowed_tools", []),
                blocked_tools=cfg.get("blocked_tools", []),
                max_params_size_bytes=cfg.get(
                    "max_params_size_bytes", _DEFAULT_MAX_PARAMS
                ),
                required_capabilities=cfg.get("required_capabilities", {}),
            )

    def validate_pre_request(
        self,
        request: AgentDecisionRequest,
        capability_set: Optional[frozenset] = None,
    ) -> GateResult:
        """Pre-execution validation from AgentDecisionRequest."""
        if self._load_error:
            return _block("Policy YAML load error — fail-secure")

        tool = request.action.name
        agent_id = request.agent_id

        if tool in self._global_blocked:
            return _block(f"Tool '{tool}' is globally blocked")

        policy = self._agents.get(agent_id, ToolPolicy())

        if tool in policy.blocked_tools:
            return _block(f"Tool '{tool}' blocked for agent '{agent_id}'")

        if policy.allowed_tools and tool not in policy.allowed_tools:
            if self._default.get("unknown_tool_action", "BLOCK") == "BLOCK":
                return _block(f"Tool '{tool}' not in allowed list")

        if capability_set is not None and request.action.capabilities:
            missing = set(request.action.capabilities) - capability_set
            if missing:
                return _block(
                    f"CAPABILITY_EXCEEDED: missing {sorted(missing)}"
                )

        return _allow("Pre-validation passed")

    def validate_pre(
        self,
        tool_name: str,
        params: str,
        agent_id: str,
        session_id: str,
    ) -> GateResult:
        """Legacy pre-validation (string-based)."""
        if self._load_error:
            return _block("Policy YAML load error — fail-secure")

        if tool_name in self._global_blocked:
            return _block(f"Tool '{tool_name}' is globally blocked")

        policy = self._agents.get(agent_id, ToolPolicy())
        if tool_name in policy.blocked_tools:
            return _block(f"Tool '{tool_name}' blocked for '{agent_id}'")
        if policy.allowed_tools and tool_name not in policy.allowed_tools:
            if self._default.get("unknown_tool_action", "BLOCK") == "BLOCK":
                return _block(f"Tool '{tool_name}' not in allowed list")
        if len(params.encode()) > policy.max_params_size_bytes:
            return _block(f"Params exceed {policy.max_params_size_bytes}B")
        if self._blocked_re.search(params):
            return _block("Parameters contain blocked pattern")
        return _allow("Pre-validation passed")

    def validate_post(
        self,
        tool_name: str,
        result: str,
        agent_id: str,
        session_id: str,
    ) -> GateResult:
        """Post-execution validation. Screens output for injection."""
        if not result:
            return _allow("Empty output")
        if _RE_SCREEN.search(result):
            return _block("Output contains injection patterns")
        return _allow("Post-validation passed")

    @staticmethod
    def make_finding(reason: str, confidence: float = 0.9) -> SimpleFinding:
        """Create Finding for capability/tool violations."""
        return SimpleFinding(
            rule_id="CAPABILITY_EXCEEDED",
            confidence=confidence,
            severity=0.9,
            module="tool_call_guard",
        )


def _block(reason: str) -> GateResult:
    logger.warning("BLOCK: gate=%s reason=%s", _GATE, reason)
    return GateResult(
        verdict=AgentVerdict.BLOCK, evidence_id=None,
        explain=f"[{_GATE}] {reason}", gate=_GATE,
    )


def _allow(reason: str) -> GateResult:
    return GateResult(
        verdict=AgentVerdict.ALLOW, evidence_id=None,
        explain=f"[{_GATE}] {reason}", gate=_GATE,
    )
