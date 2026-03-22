"""
ProtocolDesigner — ARIA sub-component 3a (Protocol Designer).

Given a security policy, selects appropriate security protocols from the
PROTOCOL_REGISTRY whitelist. Rule-based (Level 2) — no generative AI in the
selection loop.

Scope Declaration (ADR-057):
  This module implements ARIA sub-component 3a (Protocol Designer) only.
  Sub-components 3b (Cryptography Solver) and 3c (Protocol Implementer)
  are Phase 2 roadmap items, developed in collaboration with Track 3 teams.
  Level: 2 (Security Orchestrator) — selects from whitelist of known protocols.
  Advancement to Level 3 (Security Engineer) is a Phase 2 objective.

BiasDeclaration (ADR-057 / Jonas principle):
  Selection accuracy vs. expert choice: TBD (measured during M7-M8 Arena calibration).
  FPR (selecting unavailable protocol): 0 — registry.available flag is deterministic.
  Calibration expiry: 90 days.

Invariants:
  - Registry is a whitelist — only explicitly listed protocols can be selected
  - Unavailable protocols are flagged, never silently excluded
  - All selections logged to DurableLedger (Jonas: responsibility chain)
  - explain_decision mandatory on every ProtocolPlan (Levinas: transparency)
  - Fail-secure: any exception → _fail_secure() with empty selected list
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from buildtovalue.governance.durable_ledger import DurableLedger

from .protocol_registry import PROTOCOL_REGISTRY, ProtocolSpec

logger = logging.getLogger("btv.agentic.protocol_designer")

_DEFAULT_HMAC_KEY: bytes = b"btv-protocol-designer-v1"


# ─── Result Types ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProtocolPlan:
    """
    Output of ProtocolDesigner.select().

    selected:    Protocols that match requirements AND are available today.
    unavailable: Protocols that match requirements but are roadmap items.
    rationale:   Maps each matched requirement to the protocol name.
    explain_decision: Mandatory (Levinas — full transparency).
    signature:   HMAC-SHA256 of plan content (Jonas — responsibility).
    """
    selected: tuple[ProtocolSpec, ...]
    unavailable: tuple[ProtocolSpec, ...]
    rationale: dict[str, str]
    explain_decision: str
    timestamp: float
    signature: str


# ─── ProtocolDesigner ─────────────────────────────────────────────────────────

class ProtocolDesigner:
    """
    ARIA sub-component 3a: rule-based security protocol selection.

    Uses PROTOCOL_REGISTRY whitelist. Extracts requirements from policy dict,
    matches against registry, returns ProtocolPlan with selected protocols.

    No LLM in the selection loop — pure structural matching.
    """

    # Fields that may contain security requirements
    _REQUIREMENT_FIELDS = frozenset({
        "integrity", "confidentiality", "availability", "privacy",
        "verifiability", "non_repudiation", "authenticity",
        "agreement", "fault_tolerance", "forensics", "remote_verification",
        "joint_computation",
    })

    def __init__(
        self,
        ledger: DurableLedger,
        registry: list[ProtocolSpec] = PROTOCOL_REGISTRY,
        hmac_key: bytes = _DEFAULT_HMAC_KEY,
    ) -> None:
        self._ledger = ledger
        self._registry = registry
        self._hmac_key = hmac_key

    def select(self, policy: dict) -> ProtocolPlan:
        """
        Select protocols matching the policy's security requirements.

        Args:
            policy: Security policy dict (from PolicyEngine or PolicyElicitor).

        Returns:
            ProtocolPlan with selected (available) and unavailable protocols.
            On exception: returns fail-secure ProtocolPlan with empty lists.
        """
        try:
            return self._select(policy)
        except Exception as exc:
            logger.error("ProtocolDesigner.select failed: %s", exc)
            return self._fail_secure(str(exc))

    def _select(self, policy: dict) -> ProtocolPlan:
        requirements = self._extract_requirements(policy)
        logger.debug("ProtocolDesigner extracted requirements: %s", requirements)

        selected, unavailable = self._match_protocols(requirements)

        rationale = self._build_rationale(requirements, selected + unavailable)
        explain = self._build_explain(requirements, selected, unavailable)
        timestamp = time.time()
        sig = self._sign_plan(selected, unavailable, rationale, timestamp)

        plan = ProtocolPlan(
            selected=tuple(selected),
            unavailable=tuple(unavailable),
            rationale=rationale,
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )

        self._log_to_ledger(plan, policy)
        return plan

    def _extract_requirements(self, policy: dict) -> frozenset[str]:
        """
        Extract security requirements from policy dict.

        Scans top-level keys and nested 'requirements', 'security', 'goals' dicts.
        Normalizes to lowercase. Only returns known requirement names.
        """
        found: set[str] = set()

        def scan(obj: object) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    k_lower = k.lower()
                    if k_lower in self._REQUIREMENT_FIELDS:
                        # Key itself is a requirement (e.g., {"integrity": true})
                        if v is True or v == "required" or v == "true":
                            found.add(k_lower)
                    # Recurse into nested structures
                    if isinstance(v, dict):
                        scan(v)
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, str) and item.lower() in self._REQUIREMENT_FIELDS:
                                found.add(item.lower())
                            elif isinstance(item, dict):
                                scan(item)
            elif isinstance(obj, list):
                for item in obj:
                    scan(item)

        scan(policy)

        # Also check for a top-level "requirements" key with list value
        if "requirements" in policy and isinstance(policy["requirements"], list):
            for req in policy["requirements"]:
                if isinstance(req, str) and req.lower() in self._REQUIREMENT_FIELDS:
                    found.add(req.lower())

        return frozenset(found)

    def _match_protocols(
        self, requirements: frozenset[str]
    ) -> tuple[list[ProtocolSpec], list[ProtocolSpec]]:
        """
        Match requirements against registry.
        Returns (available_matches, unavailable_matches).
        A protocol matches if requirements_met ∩ requirements ≠ ∅.
        """
        selected: list[ProtocolSpec] = []
        unavailable: list[ProtocolSpec] = []

        seen_names: set[str] = set()  # Dedup
        for spec in self._registry:
            if spec.name in seen_names:
                continue
            if spec.requirements_met & requirements:
                seen_names.add(spec.name)
                if spec.available:
                    selected.append(spec)
                else:
                    unavailable.append(spec)

        return selected, unavailable

    def _build_rationale(
        self,
        requirements: frozenset[str],
        all_matches: list[ProtocolSpec],
    ) -> dict[str, str]:
        """Map each satisfied requirement to the first matching protocol name."""
        rationale: dict[str, str] = {}
        for req in requirements:
            for spec in all_matches:
                if req in spec.requirements_met and req not in rationale:
                    rationale[req] = spec.name
        return rationale

    def _build_explain(
        self,
        requirements: frozenset[str],
        selected: list[ProtocolSpec],
        unavailable: list[ProtocolSpec],
    ) -> str:
        req_str = ", ".join(sorted(requirements)) if requirements else "none"
        sel_str = ", ".join(s.name for s in selected) if selected else "none"
        unav_str = ", ".join(u.name for u in unavailable) if unavailable else "none"
        return (
            f"ProtocolDesigner (ARIA 3a, Level 2): requirements=[{req_str}] "
            f"→ selected=[{sel_str}], unavailable_roadmap=[{unav_str}]. "
            f"Selection is rule-based from whitelist registry (no LLM)."
        )

    def _sign_plan(
        self,
        selected: list[ProtocolSpec],
        unavailable: list[ProtocolSpec],
        rationale: dict[str, str],
        timestamp: float,
    ) -> str:
        content = json.dumps(
            {
                "selected": [s.name for s in selected],
                "unavailable": [u.name for u in unavailable],
                "rationale": rationale,
                "timestamp": timestamp,
            },
            sort_keys=True,
        )
        return _hmac.new(self._hmac_key, content.encode(), hashlib.sha256).hexdigest()

    def _log_to_ledger(self, plan: ProtocolPlan, policy: dict) -> None:
        try:
            self._ledger.append({
                "event": "protocol_designer.select",
                "selected": [s.name for s in plan.selected],
                "unavailable": [u.name for u in plan.unavailable],
                "rationale": plan.rationale,
                "timestamp": plan.timestamp,
                "explain_decision": plan.explain_decision,
            })
        except Exception as exc:
            logger.warning("ProtocolDesigner: failed to log to ledger: %s", exc)

    def _fail_secure(self, reason: str) -> ProtocolPlan:
        """Fail-secure: return empty selection with ABORT rationale."""
        timestamp = time.time()
        explain = (
            f"ProtocolDesigner FAIL-SECURE: {reason}. "
            f"No protocols selected — manual review required (Jonas principle)."
        )
        sig = _hmac.new(
            self._hmac_key,
            f"fail_secure:{reason}:{timestamp}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return ProtocolPlan(
            selected=(),
            unavailable=(),
            rationale={},
            explain_decision=explain,
            timestamp=timestamp,
            signature=sig,
        )
