# ADR-0055: PolicyElicitor Design

**Status**: ✅ ACCEPTED
**Date**: 2026-03-22
**Authors**: Daniel Camargo, Staff Engineer
**Impact**: `python/buildtovalue/agentic/policy_elicitor.py`
**Related ADRs**: ADR-0054, ADR-0011 (PolicyEngine), ADR-0042 (Policy-as-Code v2)

---

## Context

ARIA Track 2.2 sub-component 1 (Requirement Gathering) requires converting natural-language security requirements into machine-readable policies. The output must be compatible with the existing `PolicyEngine` schema (ADR-0042) so downstream components (NegotiationEngine, ProtocolDesigner) can process them without format conversion.

---

## Decision

**LLM for NL extraction only; schema validation against existing PolicyEngine YAML format.**

### Architecture

```
NL Input → PolicyElicitor.elicit(nl_input, domain)
         → LLMBackend.complete(system_prompt, user_prompt)
         → yaml.safe_load() on raw LLM output
         → gap detection (expected fields vs. present fields)
         → ElicitedPolicy(policy, gaps, confidence, error)
```

### LLM Abstraction (Pluggable Backend)

```python
class LLMBackend(Protocol):
    async def complete(self, system: str, user: str) -> str: ...

MockBackend:      Deterministic canned YAML (unit tests, no external calls)
AnthropicBackend: Production — claude-sonnet-4-6 (Anthropic API, 2026-03)
```

### Fail-Secure Invariants

1. LLM output that is not valid YAML → `ElicitedPolicy(policy={}, error=...)`
2. YAML that is not a dict (e.g., list) → fail-secure error
3. LLM exception → fail-secure error (never raises to caller)
4. Unknown domain → fail-secure error
5. **Never generates or uses an invalid policy** — empty policy is safer than wrong policy

### Gap Detection

Policy fields expected per domain (from analysis of existing `data/policies/` schemas).
`confidence = 1 - (|gaps| / |expected_fields|)`

### Schema Template

Domain-specific templates loaded from `data/policies/{domain}/` at elicitation time.
No new schema format — uses existing YAML structure.

---

## Alternatives Considered

| Alternative | Rejected because |
|-------------|-----------------|
| Fine-tuned model | Too expensive for MVP; requires labeled training data; Phase 1 improvement |
| Regex extraction | Too brittle for free-form NL; high FNR on varied phrasing |
| JSON Schema validation | Overkill for TRL 5; existing YAML structure is the de facto schema |
| LLM for policy decisions | Never acceptable — LLM is extraction only, never decision-maker |

---

## Philosophical Foundation

- **Jonas (Responsibility)**: LLM used only for extraction, never for policy decisions. Fail-secure on any validation failure — empty policy is safer than potentially wrong policy.
- **Levinas (Transparency)**: `explain_decision` documents confidence, gaps, and LLM role. `source_nl` preserved in result for full traceability.
- **Rawls (Fairness)**: All domains use same validation pipeline — no privileged paths.

---

## Performance (Tier 2, ADR-0054)

- SLA: < 5s p99 with Anthropic API (network + model inference)
- Not on Tier 1 hot path — async, called only on explicit user request
- MockBackend for testing: < 1ms (deterministic)

---

## Consequences

**Positive**:
- No new schema format — output is immediately consumable by existing PolicyEngine
- Pluggable backend prevents vendor lock-in
- MockBackend enables comprehensive unit testing without external API

**Negative**:
- LLM latency (500ms–5s) unsuitable for hot path — mitigated by Tier 2 isolation
- LLM extraction accuracy depends on prompt quality — requires calibration
- No formal schema validation (jsonschema) in v0.1 — field-presence check only

**Technical Debt**:
- AnthropicBackend requires `pip install anthropic` (not in base requirements)
- No `jsonschema.validate()` in v0.1 — Phase 1 improvement
- Schema templates are loaded from YAML files — caching would improve performance

---

## Compliance

- **NIST SP 800-53** (SA-11: Security Testing — all outputs validated before use)
- **ISO 42001** (9.1: Monitoring and Measurement — confidence score tracks extraction quality)
- **EU AI Act Art. 13** (Transparency — LLM role is explicitly limited and documented)

---

## BiasDeclaration

| Metric | Value | Notes |
|--------|-------|-------|
| Schema validation failure rate | 0 | Validator is deterministic |
| Gap detection accuracy | TBD | Measured during M7–M8 Arena calibration |
| LLM extraction accuracy | TBD | Measured vs. expert-authored policies |
| Calibration expiry | 90 days (Jonas principle) | |
