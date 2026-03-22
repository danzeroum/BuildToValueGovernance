# ADR-0054: Agentic Layer Architecture

**Status**: ✅ ACCEPTED
**Date**: 2026-03-22
**Authors**: Daniel Camargo, Staff Engineer
**Impact**: `python/buildtovalue/agentic/` (new package, zero modifications to existing files)
**Related ADRs**: ADR-0004, ADR-0011, ADR-0017, ADR-0039, ADR-0049, ADR-0050, ADR-0051, ADR-0052

---

## Context

BuildToValue v2.3.1 provides a robust governance infrastructure: PolicyEngine, GoalDriftSentinel, DurableLedger, CommitRevealProtocol, ConsensusValidator, TechnicalEvidence, and PersuasionGuard. The ARIA Scaling Trust Track 2.2 (CFP) requires demonstrating four additional sub-components:

1. **Policy Elicitor** — converts natural-language security requirements to validated YAML policies
2. **Negotiation Engine** — enables two agents to negotiate a shared security policy with safety guarantees
3. **Security Reasoner / Protocol Designer** — selects appropriate cryptographic protocols for a given policy
4. **Arena Reporter** — generates structured (Utility; Security) audit reports

These components require building on top of — not modifying — the existing governance infrastructure.

---

## Decision

Add `python/buildtovalue/agentic/` as an **independent, additive package** that imports from `buildtovalue.governance.*` but never modifies it.

### Package Structure

```
python/buildtovalue/agentic/
├── __init__.py           # Package root, v0.1.0
├── types.py              # Shared types (NegotiationMessage, NegotiationResult)
├── a2a_channel.py        # A2AChannel Protocol + InProcessChannel + MCPChannel stub
├── protocol_registry.py  # ProtocolSpec + PROTOCOL_REGISTRY whitelist
├── protocol_designer.py  # ARIA sub-component 3a: rule-based protocol selection
├── negotiation_guard.py  # A2A safety wrapper (deobfuscation + PersuasionGuard)
├── negotiation_engine.py # A2A negotiate state machine (async)
├── policy_elicitor.py    # NL → YAML policy with LLM backend
└── arena_reporter.py     # Structured (Utility; Security) audit reports
```

### Import Map (verified at SHA c685301)

All imports use the `buildtovalue.governance.*` prefix:

| Used Module | Verified Path |
|-------------|---------------|
| GoalDriftSentinel | `buildtovalue.governance.goal_drift_sentinel` |
| PolicyEngine | `buildtovalue.governance.policy_engine` |
| DurableLedger | `buildtovalue.governance.durable_ledger` |
| TechnicalEvidence | `buildtovalue.governance.ffi_client` |
| FFIClient | `buildtovalue.governance.ffi_client` |
| CommitRevealProtocol | `buildtovalue.governance.commit_reveal` |
| ConsensusValidator | `buildtovalue.governance.consensus_validator` |
| ContestabilityLoop | `buildtovalue.governance.contestability_loop` |
| explain_decision | `buildtovalue.governance.context_engine_explain` |
| PersuasionGuard | `buildtovalue.governance.persuasion_guard` |

---

## Performance Architecture — Two SLA Tiers

The BTV MCP server exposes two performance tiers with explicitly different SLA contracts:

### Tier 1 — Governance (synchronous hot path)
- **Tools**: `validate_input`, `decide`, `trust_score`, `compliance`
- **SLA**: < 50ms p99
- **Characteristics**: deterministic, zero LLM, Rust kernel + Python judiciary
- **Status**: unchanged by v3.0 agentic layer

### Tier 2 — Agentic (asynchronous coordination path)
- **Tools**: `elicit_policy`, `negotiate`, `select_protocol`
- **SLA**: < 5s p99 (`elicit_policy` with LLM), < 500ms p99 (`negotiate`, `select_protocol`)
- **Characteristics**: async by design, may involve LLM (elicitor only), multi-round (negotiation)
- **Isolation**: Tier 2 tools are async; Tier 1 hot path is never blocked by Tier 2 latency

---

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| Modify existing governance/ modules | Breaks stability invariants; governance layer is ADR-validated and battle-tested |
| Single flat module | No separation of concerns; makes Phase 1 extensions harder to scope |
| Separate Python package (different repo) | Unnecessary complexity for TRL 5 demo; shared DurableLedger requires same process |
| LLM for negotiation decisions | Non-deterministic, not auditable; paper 213 shows 100% violation under pressure — structural comparison is safer |

---

## Philosophical Foundation

- **Jonas (Responsibility)**: Every new module includes BiasDeclarationV2 with calibration expiry date. Additive-only approach preserves v2.3.1 governance integrity.
- **Levinas (Transparency)**: `explain_decision` field mandatory in every result dataclass. Full transcript preserved in DurableLedger.
- **Rawls (Fairness)**: All BLOCK/ABORT decisions are contestable via existing ContestabilityLoop (SLA 24h).

---

## Consequences

**Positive**:
- v2.3.1 governance infrastructure untouched — all existing tests continue to pass
- New modules reuse DurableLedger, GoalDriftSentinel, PersuasionGuard — no reimplementation
- Clear scope boundary enables parallel development of Tier 1 and Tier 2

**Negative**:
- PolicyElicitor introduces LLM latency (500ms–5s) — mitigated by Tier 2 async isolation
- NegotiationEngine has no formal verification — empirical testing only (Phase 2 roadmap)

**Technical Debt**:
- MCPChannel is a stub; full implementation is Phase 1 roadmap (M3 Arena Demo)
- ProtocolDesigner Level 3 is Phase 2 roadmap (Track 3 collaboration)

---

## TRL Declaration

BuildToValue v3.0 enters at **TRL 5 — validated in controlled environment**. The agentic layer (v0.1.0) extends 3+ months of governance infrastructure development (v1.0–v2.3.1). ARIA grant funds advancement from TRL 5 to TRL 7.

---

## Compliance

- **NIST SP 800-53** (CM-3: Configuration Change Control — additive only, no regression)
- **ISO 42001** (6.1.2: Risk Assessment — incremental change reduces risk vs. rewrite)
- **EU AI Act Art. 14** (Human Oversight — all BLOCK/ABORT contestable, 24h SLA)

---

## BiasDeclaration

| Metric | Value | Notes |
|--------|-------|-------|
| FPR (agentic layer) | TBD | Measured during M7–M8 Arena calibration |
| FNR (agentic layer) | TBD | Measured via red-team suite (Phase 2) |
| Calibration expiry | 90 days (Jonas principle) | Baseline from E2E tests |
| Scope | Agentic layer only | Tier 1 governance BiasDeclarations unchanged |
