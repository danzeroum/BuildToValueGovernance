# ADR-0058: ArenaReporter

**Status**: ✅ ACCEPTED
**Date**: 2026-03-22
**Authors**: Daniel Camargo, Staff Engineer
**Impact**: `python/buildtovalue/agentic/arena_reporter.py`
**Related ADRs**: ADR-0054, ADR-0051 (DurableLedger), ADR-0052 (Forensic Audit)

---

## Context

ARIA Track 2.2 sub-component 4 (Report) requires generating structured `(Utility; Security)` audit reports compatible with Arena scoring. Reports must be:
- **Auditable**: backed by cryptographically-chained DurableLedger evidence
- **Honest about scope**: utility_score is computed by Arena, not BTV
- **Fail-secure**: exceptions produce a report, never silence
- **Signed**: HMAC-SHA256 for Jonas responsibility chain

---

## Decision

**ArenaReporter reads from DurableLedger as the single source of truth.**

### Scope Declaration (Correction C4)

`utility_score` is **NEVER computed by BTV**. It is:
- Passed by caller from Arena API (Arena knows whether the task was completed)
- `None` in standalone mode (when not connected to Arena API)

`security_score` is computed by BTV from DurableLedger event analysis:
```
security_score = 1 - (violation_count / max(total_events, 1))
```

`cost_efficiency` is computed by BTV:
```
cost_efficiency = events / duration_seconds
```

### Violation Detection

A DurableLedger entry is a violation if:
- `event` field is in `_VIOLATION_EVENT_TYPES` (explicit list), OR
- `explain_decision` field contains a violation keyword (BLOCK, ABORT, FAIL-SECURE, etc.)

### Evidence Chain

```python
evidence_chain = tuple(entry.entry_hash for entry in ledger.entries())
```

Uses BLAKE2b hashes from DurableLedger (pending BLAKE3 migration per ADR-0051 §4).
The chain is ordered — `entry_hash[n]` includes `hash(entry_hash[n-1] || payload_n)`.

### ARIA Arena Alignment

| ARIA Metric | BTV Source | Notes |
|-------------|-----------|-------|
| Utility score | FROM Arena API | BTV does not compute — external only |
| Security score | DurableLedger | Computed: 1 - violation_rate |
| Cost efficiency | DurableLedger | Computed: events/duration |
| Generalisation | N/A | Phase 2 roadmap |

---

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| Compute utility_score internally | BTV has no task completion signal — only Arena knows |
| Flat event log (not DurableLedger) | Loses cryptographic integrity chain |
| Per-event report (not per-session) | Incompatible with Arena scoring granularity |

---

## Philosophical Foundation

- **Jonas (Responsibility)**: Every report signed with HMAC-SHA256. Evidence chain provides forensic traceability.
- **Levinas (Transparency)**: `explanation` field documents all scoring components and their sources. `utility_score is None` in standalone mode is explicit, not hidden.
- **Rawls (Fairness)**: Evidence chain is verifiable independently — auditors can replay DurableLedger.

---

## Consequences

**Positive**:
- Honest about BTV scope — never claims to know task completion
- Evidence chain provides forensic-grade audit trail
- Fail-secure on ledger exception — report with security_score=0.0, never silence

**Negative**:
- `security_score` is a ratio, not a probabilistic score — may not align with all Arena rubrics
- Violation detection uses keyword matching — domain-specific violation patterns are Phase 1

**Technical Debt**:
- BLAKE2b hashes (stdlib) used instead of BLAKE3 — migration pending (ADR-0051 §4)
- `cost_efficiency` units (events/second) may need normalization for Arena comparison
- `generalisation` metric not implemented (Phase 2)

---

## Compliance

- **NIST SP 800-53** (AU-9: Protection of Audit Information — HMAC-SHA256 on all reports)
- **ISO 42001** (9.1: Performance Evaluation — security_score provides measurable metric)
- **EU AI Act Art. 14** (Transparency — evidence chain enables independent audit)

---

## BiasDeclaration

| Metric | Value | Notes |
|--------|-------|-------|
| Evidence chain integrity rate | Target: 100% | DurableLedger HMAC chain guarantees integrity |
| Security score accuracy | TBD | Calibrated against Arena human annotations |
| Violation detection FPR | TBD | Measured during red-team suite |
| Violation detection FNR | TBD | Measured during M7–M8 calibration |
| Calibration expiry | 90 days (Jonas principle) | |
