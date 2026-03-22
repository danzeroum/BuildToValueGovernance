"""
ProtocolRegistry — Whitelist of known security protocols.

Provides the authoritative list of security protocols available to
ProtocolDesigner (ARIA sub-component 3a). Designed as a whitelist:
only explicitly listed protocols can be selected — secure by construction.

Registry entries reference existing BTV implementations where available.
Unavailable entries document the planned implementation path.

ADR-057: Protocol Designer — Level 2 (rule-based), sub-component 3a only.

Invariants:
  - PROTOCOL_REGISTRY is a module-level constant (immutable in practice)
  - ProtocolSpec is frozen — no mutation after construction
  - all(isinstance(r.requirements_met, frozenset) for r in PROTOCOL_REGISTRY)
  - available=False entries are Phase 1 / Phase 2 roadmap items only
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ─── ProtocolSpec ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProtocolSpec:
    """
    Specification for a single security protocol.

    name:              Unique identifier (e.g., "commit_reveal")
    category:          "commitment" | "verification" | "privacy" | "consensus"
    requirements_met:  Set of security requirements this protocol satisfies
    trust_assumptions: Set of trust assumptions required (e.g., "honest_majority")
    overhead:          "low" | "medium" | "high"
    implementation:    Module path (buildtovalue.governance.*) or "external:{lib}"
    available:         True = implemented in BTV today; False = roadmap
    adr:               Reference to ADR that governs this protocol, or None
    """
    name: str
    category: str
    requirements_met: frozenset[str]
    trust_assumptions: frozenset[str]
    overhead: str
    implementation: str
    available: bool
    adr: Optional[str]


# ─── PROTOCOL_REGISTRY ────────────────────────────────────────────────────────
# ADR references use NNNN-slug format matching docs/adr/ filenames.

PROTOCOL_REGISTRY: list[ProtocolSpec] = [

    # ── Available today (implemented in BTV) ──────────────────────────────────

    ProtocolSpec(
        name="commit_reveal",
        category="commitment",
        requirements_met=frozenset({"integrity", "non_repudiation"}),
        trust_assumptions=frozenset(),
        overhead="low",
        implementation="buildtovalue.governance.commit_reveal",
        available=True,
        adr="0004-immutable-ledger",
    ),

    ProtocolSpec(
        name="hmac_evidence",
        category="verification",
        requirements_met=frozenset({"integrity", "authenticity"}),
        trust_assumptions=frozenset(),
        overhead="low",
        implementation="buildtovalue.governance.ffi_client",
        available=True,
        adr="0052-forensic-audit-storage",
    ),

    ProtocolSpec(
        name="bft_consensus",
        category="consensus",
        requirements_met=frozenset({"agreement", "fault_tolerance"}),
        trust_assumptions=frozenset({"honest_majority"}),
        overhead="medium",
        implementation="buildtovalue.governance.consensus_validator",
        available=True,
        adr="0050-multi-run-consensus-validator",
    ),

    ProtocolSpec(
        name="blake2b_audit",
        category="verification",
        requirements_met=frozenset({"integrity", "forensics"}),
        trust_assumptions=frozenset(),
        overhead="low",
        implementation="buildtovalue.governance.durable_ledger",
        available=True,
        adr="0051-model-integrity-abliteration-detection",
    ),

    # ── Planned (Phase 1 — ARIA-funded M1-M6) ────────────────────────────────

    ProtocolSpec(
        name="tee_attestation",
        category="verification",
        requirements_met=frozenset({"confidentiality", "integrity", "remote_verification"}),
        trust_assumptions=frozenset({"tee_available"}),
        overhead="medium",
        implementation="external:tee_sdk",
        available=False,
        adr=None,
    ),

    # ── Future (Phase 2 — Track 3 collaboration) ─────────────────────────────

    ProtocolSpec(
        name="zk_proof",
        category="privacy",
        requirements_met=frozenset({"privacy", "verifiability"}),
        trust_assumptions=frozenset(),
        overhead="high",
        implementation="external:arkworks",
        available=False,
        adr=None,
    ),

    ProtocolSpec(
        name="mpc_computation",
        category="privacy",
        requirements_met=frozenset({"privacy", "joint_computation"}),
        trust_assumptions=frozenset({"honest_majority"}),
        overhead="high",
        implementation="external:mp_spdz",
        available=False,
        adr=None,
    ),
]

# Index for O(1) lookup by name
_REGISTRY_BY_NAME: dict[str, ProtocolSpec] = {p.name: p for p in PROTOCOL_REGISTRY}


def get_protocol(name: str) -> Optional[ProtocolSpec]:
    """Return ProtocolSpec by name, or None if not in registry."""
    return _REGISTRY_BY_NAME.get(name)


def get_available_protocols() -> list[ProtocolSpec]:
    """Return only protocols available for use today."""
    return [p for p in PROTOCOL_REGISTRY if p.available]
