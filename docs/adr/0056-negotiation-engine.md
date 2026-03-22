# ADR-0056: NegotiationEngine Protocol

**Status**: ✅ ACCEPTED
**Date**: 2026-03-22
**Authors**: Daniel Camargo, Staff Engineer
**Impact**: `python/buildtovalue/agentic/negotiation_engine.py`, `python/buildtovalue/agentic/a2a_channel.py`
**Related ADRs**: ADR-0054, ADR-0004, ADR-0039, ADR-0049, ADR-0051

---

## Context

ARIA Track 2.2 requires demonstrating agent-to-agent (A2A) policy negotiation with safety guarantees. Two agents must be able to negotiate a shared security policy from their individual policies, with protection against goal drift, adversarial messages, and protocol abuse.

---

## Decision

**Propose/counter/accept/abort state machine** with:
- `GoalDriftSentinel` integration for cumulative concession monitoring
- `NegotiationGuard` on all incoming messages (deobfuscation + persuasion detection)
- `DurableLedger` logging of all state transitions
- **Async from Phase 0** — `async/await` throughout, no sync-then-async migration

### State Machine

```
IDLE → PROPOSED → COUNTERED → ACCEPTED → CONFIRMED
                            ↘ ABORTED
Any state → ABORTED (timeout | max_rounds | goal_drift | jailbreak_blocked | error)
```

### Negotiation Protocol

1. Proposer sends `propose(own_policy)`
2. Responder evaluates: `accept` / `counter(merged_policy)` / `reject`
3. Proposer evaluates counter: accept / further counter / abort
4. Continue until `CONFIRMED` or `ABORTED`

### Policy Evaluation (structural, no LLM)

```
satisfaction_ratio = |own_keys ∩ incoming_keys with matching values| / |own_keys|
  ≥ 80% → accept
  > 0%  → counter (merge own + non-conflicting incoming fields)
  = 0%  → reject
```

### Goal Drift Mapping

Concession ratio (requirements not present or changed in incoming):

| Concession | Drift Level | Action |
|-----------|-------------|--------|
| < 10%  | None     | ALLOW  |
| < 30%  | Low      | ALLOW  |
| < 60%  | Medium   | ALLOW  |
| < 80%  | High     | BLOCK  |
| ≥ 80%  | Critical | BLOCK  |

GoalDriftSentinel (ADR-0039) monitors the sequence across rounds — burst detection and asymmetric pressure apply.

### Message Signing

Every `NegotiationMessage` carries HMAC-SHA256 of `(type + policy + reason + round_number)`. Every `NegotiationResult` carries HMAC-SHA256 of `(status + policy + rounds + timestamp)`.

---

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| LLM-based negotiation | Non-deterministic; paper 213: 100% violation under pressure in final timesteps |
| Synchronous first, async later | Migration debt; async from day one is cleaner and Arena-ready |
| Free-form JSON exchange | Not auditable; requires schema validation at each step |
| Bidding / auction model | Overkill for two-party security policy negotiation |

---

## Philosophical Foundation

- **Jonas (Responsibility)**: All state transitions logged to DurableLedger with HMAC. Hard abort on drift — agent cannot be socially engineered into accepting weaker policy.
- **Levinas (Transparency)**: `explain_decision` mandatory on `NegotiationResult`. Full `transcript` preserved for audit.
- **Rawls (Fairness)**: Both parties use same state machine — no asymmetric advantage.

---

## Consequences

**Positive**:
- Deterministic, auditable negotiation — every outcome reproducible from transcript
- GoalDriftSentinel prevents Efficiency vs. Security drift (paper 213)
- NegotiationGuard blocks adversarial messages before they affect state

**Negative**:
- Structural comparison is heuristic — complex policy schemas may need richer matching logic
- No formal verification of the protocol (empirical testing only — Phase 2 roadmap)

**Technical Debt**:
- MCPChannel for cross-agent communication is Phase 1 roadmap
- Policy merging (counter) is simple union — domain-specific merge rules are Phase 1
- No formal protocol proof — empirical test suite covers main paths

---

## Known Limitations

- Negotiation is limited to 2 parties; multi-party (> 2) requires ConsensusValidator integration (future)
- `NegotiationResult.drift_score` is currently set to 0.0 — integrating per-session cumulative drift score is a Phase 1 improvement

---

## Compliance

- **NIST SP 800-53** (AC-2: Account Management, SI-10: Information Input Validation)
- **ISO 42001** (8.6: AI System Operations — auditable agent coordination)

---

## BiasDeclaration

| Metric | Value | Notes |
|--------|-------|-------|
| Abort rate on compatible policies | ~0 | Deterministic — identical policies always confirm |
| Convergence rate | TBD | Measured during M7–M8 Arena calibration |
| False abort rate (goal drift) | TBD | Calibrated against Arena negotiation traces |
| Calibration expiry | 90 days (Jonas principle) | |
