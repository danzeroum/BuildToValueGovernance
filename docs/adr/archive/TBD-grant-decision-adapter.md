# ADR: Grant Decision Adapter

**Status:** Accepted  
**Date:** 2026-04-13  
**Authors:** AI Squad (Arquiteta, Dev Python)  
**Context:** `btv_grants/` module integration with BTV governance kernel  
**Supersedes:** None  
**Superseded by:** None  

---

## Context

The BuildToValue platform needs to route third-party grant proposals (e.g., from
Gitcoin rounds, community grant portals) through the BTV ethical governance kernel.
The grant domain has specific requirements not covered by the base `use_decide()`
interface: OFAC sanctions checking, scam/Ponzi pattern detection, multilingual
proposal support, and Levinas SLA contestability for policy blocks.

This ADR documents the six architectural decisions made when designing
`GrantDecisionAdapter`.

---

## Decisions

### (a) `use_decide=True` — Full Ethical Pipeline Mandatory for Grants

**Decision:** The adapter always calls `client.use_decide()` (not `client.gate()` or
`client.score()`). The `use_decide` path activates the full Rawls-Levinas-Jonas-Gilligan
pipeline, producing a `Verdict` with `explain_decision` fields.

**Rationale:** Grant proposals involve irreversible financial decisions affecting real
communities. The abbreviated `gate()` path (which returns only ALLOW/BLOCK without
ethical explanation) is insufficient. `explain_decision` is mandatory for Transparency
Radical and for Levinas SLA contestability — applicants must receive a human-readable
rationale when blocked.

**Consequences:** Higher latency per decision (~50ms vs ~10ms for `gate()`). Acceptable
for the grant use case, which is not latency-sensitive.

---

### (b) `hard_blocked` as Primary Gate (Before `action`)

**Decision:** In `_process_verdict()`, `hard_blocked` is evaluated **before** `action`.
A verdict with `hard_blocked=True` raises `GrantBlockedError` unconditionally, even if
`action` is `EDUCATE` or `mercy_applied` is `True`.

**Rationale:** The BTV kernel's `hard_blocked` field represents decisions by the Rust
gatekeeper that bypass the Python governance layer (OFAC sanctions, deny-list matches).
These decisions are not subject to Python-layer override. Checking `action` first would
create a bypass vulnerability: an attacker who manipulates `action` to `EDUCATE` would
circumvent sanctions enforcement if `hard_blocked` were not checked first.

**Consequences:** Fail-secure by design. `hard_blocked=True` proposals always get
`contestable=False` and `appeal_deadline_hours=0`, regardless of other fields.

---

### (c) HMAC-SHA256 for `session_id` (Not BLAKE3)

**Decision:** `GrantProposal.to_session_id()` uses `hmac.new(..., hashlib.sha256)`.
BLAKE3 is explicitly avoided.

**Rationale:** BLAKE3 is the Rust kernel's hashing domain (used for `TechnicalEvidence`
integrity). The Python layer uses HMAC-SHA256, consistent with `agent_pdp.py`'s existing
HMAC implementation. Duplicating BLAKE3 in Python would require an additional dependency
(`hashlib.blake3` is not in the stdlib) and creates confusion about which hash belongs
to which layer.

**Consequences:** `session_id` values are deterministic per `applicant_id` and compatible
with existing BTV session management infrastructure.

---

### (d) JSON Serialization in `to_btv_input()` (Not Free Text)

**Decision:** `GrantProposal.to_btv_input()` serializes to compact JSON with
`json.dumps(..., ensure_ascii=False, separators=(',', ':'))`. English-language
prefixes (`"Title: "`, `"Description: "`, `"Budget: "`) are explicitly avoided.

**Rationale:** The BTV `LanguageDetector` (in `gatekeeper.rs`) runs on the full
`content` string. English prefixes like `"Title:"` contaminate the language signal,
causing misclassification of Portuguese, Spanish, and Swahili proposals. JSON structure
is language-neutral and preserves the original text for accurate detection.

**Consequences:** All downstream consumers of `to_btv_input()` must parse JSON.
Free-text fallback is not supported.

---

### (e) Policy Files in `data/policies/sectors/` (Not `data/policies/`)

**Decision:** The grant eligibility policy YAML is placed at
`data/policies/sectors/grant-eligibility-v1.yaml`, not at `data/policies/grants.yaml`
or a new top-level location.

**Rationale:** The BTV repository already contains 12 sector YAMLs under
`data/policies/sectors/` (e.g., `education.yaml`, `healthcare.yaml`). The grant
domain maps to this sector taxonomy. Consistency with the existing structure reduces
cognitive load for maintainers and ensures the MkDocs policy index picks up the new
file automatically.

**Consequences:** Policy consumers that hard-code `data/policies/` paths will not find
the grant policy. Reference the full path `data/policies/sectors/grant-eligibility-v1.yaml`.

---

### (f) `BiasDeclaration` Null for `sw` Group (Jonas Responsibility)

**Decision:** The `BiasDeclaration` for Swahili (`sw`) has `fpr: null` and `fnr: null`
in the policy YAML, and the `BiasDeclaration` Python model raises `ValueError` if
non-null values are set for `sw`.

**Rationale:** Jonas Responsibility Principle: it is more harmful to fabricate
calibration metrics than to admit uncertainty. As of v1.0, insufficient labeled
Swahili grant proposals exist for reliable FPR/FNR measurement. Declaring `null`
triggers `INSPECT` for all `sw` proposals (human review required), ensuring fairness
without false precision.

**Target:** Calibrate `sw` by Q2 2026 using East African grant partner data. Once
calibrated, update `bias_declarations[sw].fpr` and `fnr` and remove the null guard.

**Consequences:** All Swahili proposals receive `INSPECT` action until calibration
is complete. This is conservative but correct per the Jonas principle.

---

## Rejected Alternatives

| Alternative | Rejected because |
|---|---|
| Use `client.gate()` instead of `use_decide()` | No `explain_decision` → violates Levinas SLA and Transparency Radical |
| Check `action` before `hard_blocked` | Creates OFAC bypass vulnerability |
| BLAKE3 for `session_id` in Python | External dependency; confuses kernel/adapter hash responsibilities |
| Free-text input with English prefixes | Corrupts LanguageDetector signal for non-English proposals |
| Policy at `data/policies/grants.yaml` | Breaks sector taxonomy and MkDocs auto-index |
| Fabricate `sw` FPR/FNR from `en-US` data | Violates Jonas principle; false precision harms sw applicants |

---

## Checklist

- [x] Fail-secure: BLOCK on error, not ALLOW
- [x] `explain_decision` present in all non-hard-block verdicts
- [x] `BiasDeclaration` declared for all 4 linguistic groups
- [x] HMAC-SHA256 signed session_id
- [x] Contestability SLA: 168h for policy blocks, 0h for hard blocks
- [x] Adversarial test suite: 800 cases (8 categories × 100)
- [x] No `.unwrap()` equivalents (all errors explicit)
- [x] No `any` type annotations
- [x] Functions ≤ 50 lines
