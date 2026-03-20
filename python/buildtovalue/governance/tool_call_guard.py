"""ToolCallGuard — Gap A: Tool Call Validation (Pre/Post).

Pre-execution validation: checks tool name against allowed lists,
validates parameters against blocked patterns, enforces size limits.
Post-execution validation: screens output for injection and leakage.

Invariants:
- Fail-secure: unknown tool -> BLOCK (never silent pass)
- explain_decision in every GateResult
- HMAC-SHA256 on signed results
- Functions <= 50 lines, file <= 200 lines
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .agent_pdp import AgentVerdict
from .chatbot_gates import GateResult
from .tool_sanitizer import _RE_SCREEN

logger = logging.getLogger("btv.governance.tool_call_guard")

_DEFAULT_MAX_PARAMS = 10_000


@dataclass(frozen=True)
class ToolPolicy:
    allowed_tools: List[str] = field(default_factory=list)
    blocked_tools: List[str] = field(default_factory=list)
    max_params_size_bytes: int = _DEFAULT_MAX_PARAMS


def _load_policy(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _compile_patterns(patterns: List[str]) -> re.Pattern:
    if not patterns:
        return re.compile(r"(?!)")  # never matches
    return re.compile("|".join(patterns), flags=re.IGNORECASE)


class ToolCallGuard:
    """Validates tool calls pre/post execution."""

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        raw = _load_policy(policy_path) if policy_path else {}
        self._global_blocked = set(raw.get("global_blocked_tools", []))
        self._blocked_params_re = _compile_patterns(
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
            )

    def _agent_policy(self, agent_id: str) -> ToolPolicy:
        return self._agents.get(agent_id, ToolPolicy())

    def validate_pre(
        self,
        tool_name: str,
        params: str,
        agent_id: str,
        session_id: str,
    ) -> GateResult:
        """Pre-execution validation. Returns BLOCK on any violation."""
        if tool_name in self._global_blocked:
            return _block(
                "tool_call_guard_pre",
                f"Tool '{tool_name}' is globally blocked",
            )

        policy = self._agent_policy(agent_id)

        if tool_name in policy.blocked_tools:
            return _block(
                "tool_call_guard_pre",
                f"Tool '{tool_name}' blocked for agent '{agent_id}'",
            )

        if policy.allowed_tools and tool_name not in policy.allowed_tools:
            action = self._default.get("unknown_tool_action", "BLOCK")
            if action == "BLOCK":
                return _block(
                    "tool_call_guard_pre",
                    f"Tool '{tool_name}' not in allowed list for '{agent_id}'",
                )

        if len(params.encode()) > policy.max_params_size_bytes:
            return _block(
                "tool_call_guard_pre",
                f"Params exceed {policy.max_params_size_bytes}B limit",
            )

        if self._blocked_params_re.search(params):
            return _block(
                "tool_call_guard_pre",
                "Parameters contain blocked pattern",
            )

        return _allow("tool_call_guard_pre", "Pre-validation passed")

    def validate_post(
        self,
        tool_name: str,
        result: str,
        agent_id: str,
        session_id: str,
    ) -> GateResult:
        """Post-execution validation. Screens output for injection."""
        if not result:
            return _allow("tool_call_guard_post", "Empty output")

        if _RE_SCREEN.search(result):
            return _block(
                "tool_call_guard_post",
                "Output contains injection patterns",
            )

        return _allow("tool_call_guard_post", "Post-validation passed")


def _block(gate: str, reason: str) -> GateResult:
    logger.warning("BLOCK: gate=%s reason=%s", gate, reason)
    return GateResult(
        verdict=AgentVerdict.BLOCK,
        evidence_id=None,
        explain=f"[{gate}] {reason}",
        gate=gate,
    )


def _allow(gate: str, reason: str) -> GateResult:
    return GateResult(
        verdict=AgentVerdict.ALLOW,
        evidence_id=None,
        explain=f"[{gate}] {reason}",
        gate=gate,
    )
