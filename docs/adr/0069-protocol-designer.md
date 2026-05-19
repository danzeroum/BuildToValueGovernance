# ADR-069: Protocol Designer (ARIA Sub-Component 3a)

**Status**: ✅ ACCEPTED
**Date**: 2026-03-22
**Authors**: Daniel Camargo, Staff Engineer
**Impact**: `python/buildtovalue/agentic/protocol_designer.py`, `python/buildtovalue/agentic/protocol_registry.py`
**Related ADRs**: ADR-0054, ADR-0004, ADR-0050, ADR-0051, ADR-0052

---

## Scope Declaration

This module implements **ARIA sub-component 3a (Protocol Designer)** only.

| Sub-component | Description | Status |
|---------------|-------------|--------|
| 3a: Protocol Designer | Generates idealised protocol selection from policy | **This ADR — implemented** |
| 3b: Cryptography Solver | Proposes cryptographic implementation | Phase 2 roadmap |
| 3c: Protocol Implementer | Implements protocol securely | Phase 2 roadmap |

**Level**: 2 (Security Orchestrator) — selects from whitelist of known protocols.
Advancement to Level 3 (Security Engineer) is a Phase 2 objective, ideally developed in collaboration with Track 3 research teams.

---

## Context

Given a security policy (YAML dict from PolicyEngine or PolicyElicitor), the system must recommend appropriate cryptographic/verification protocols. The selection must be:
- **Deterministic** — same policy always produces same result
- **Auditable** — logged to DurableLedger with full rationale
- **Fail-secure** — exceptions return empty plan, never invalid protocol
- **Whitelist-based** — only approved protocols can be selected

---

## Decision

**Rule-based matching (Level 2)** against `PROTOCOL_REGISTRY` whitelist.

### Algorithm

1. Extract requirements from policy dict (recursive key scan)
2. For each registry entry: if `requirements_met ∩ extracted_requirements ≠ ∅` → match
3. Partition matches into `selected` (available=True) and `unavailable` (available=False)
4. Build `rationale` dict mapping each requirement to matched protocol name
5. Log to DurableLedger with `explain_decision`
6. Return `ProtocolPlan`

### Registry Design

- Whitelist, not search space — secure by construction
- `frozenset` for requirements (immutable, hashable)
- `available` flag explicitly marks today vs. roadmap
- `adr` field provides traceability to governing decision records
- External protocols reference real libraries (arkworks, MP-SPDZ, tee_sdk)

---

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| LLM-based selection (Level 3-4) | Non-deterministic; requires formal verification before Arena use; Phase 2 |
| Free-text protocol description | Ambiguous; cannot be audited against known implementations |
| Dynamic registry loading | Security risk — whitelist must be static and reviewed |
| Per-policy custom rules | Combinatorial explosion; whitelist is simpler and safer |

---

## Philosophical Foundation

- **Jonas (Responsibility)**: All selections logged to DurableLedger with HMAC signature. Unavailable protocols are explicitly flagged — no silent capability gaps.
- **Levinas (Transparency)**: `explain_decision` field mandatory on every `ProtocolPlan`. Human reviewer can understand exactly why each protocol was selected.
- **Rawls (Fairness)**: Whitelist is publicly reviewable; no hidden selection criteria.

---

## Consequences

**Positive**:
- Deterministic and fully auditable — every selection reproducible
- Unavailable protocols are surfaced (not hidden) — honest about capabilities
- Registry can be extended without code changes to ProtocolDesigner
- Level 2 is sufficient for TRL 5 demo; Level 3 is Phase 2

**Negative**:
- Cannot discover novel protocol combinations — constrained to registry
- Requirement extraction is heuristic (key scan) — complex policy schemas may need explicit `requirements` field

**Technical Debt**:
- Level 3 (generative protocol composition) is Phase 2 roadmap
- TEE, ZKP, MPC protocols are registry stubs — not implemented
- Requirement extraction does not parse PolicyEngine domain schemas directly (Phase 1 improvement)

---

## Compliance

- **NIST SP 800-53** (SA-11: Developer Security Testing — whitelist approach satisfies least-privilege)
- **ISO 42001** (8.4: AI System Design — deterministic, auditable selection)

---

## BiasDeclaration

| Metric | Value | Calibration |
|--------|-------|-------------|
| Selection accuracy vs. expert | TBD | Measured during M7–M8 Arena calibration |
| FPR (selecting unavailable) | 0 | `available` flag is deterministic — no false positives possible |
| FNR (missing valid protocol) | TBD | Red-team suite Phase 2 |
| Calibration expiry | 90 days (Jonas principle) | Baseline from E2E tests |
