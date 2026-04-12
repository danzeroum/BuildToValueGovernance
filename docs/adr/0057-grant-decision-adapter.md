# ADR-0057: Grant Decision Adapter

**Status:** Accepted  
**Date:** 2026-04-11  
**Deciders:** Arquiteta (Opus), Dev Python (Sonnet), Reviewer (Opus)  
**Context:** BuildToValue v3.0 — República Algorítmica  

---

## Context

Grant evaluation platforms (Gitcoin Rounds, DAO treasury, quadratic funding)
need to integrate BTV ethical governance to screen proposals before financial
disbursement. This adapter must handle multilingual proposals (en-US, pt-BR,
es, sw) and enforce fail-secure behavior for financial risk.

This ADR documents 6 architectural decisions that diverge from the existing
LangChain/CrewAI/AutoGen adapter patterns.

---

## Decisions

### (a) `use_decide=True` as default — full ethical pipeline for grants

**Decision:** GrantGuard defaults to `use_decide=True`, calling `/v1/decide`
(full Rawls → Levinas → Jonas → Gilligan pipeline, ~30ms p99).

**Rationale:** Grants carry real financial risk. Other adapters (LangChain,
CrewAI) default to `use_decide=False` because their actions are reversible.
Grant disbursements are IRREVERSIBLE — the full ethical pipeline is warranted.

**Consequence:** Higher latency per evaluation (~30ms vs ~3ms). Acceptable
given that grant evaluations are low-frequency, high-stakes operations.

---

### (b) `hard_blocked` checked BEFORE `action` — fail-secure gate priority

**Decision:** In `GrantGuard.evaluate()`, `verdict.hard_blocked` is evaluated
BEFORE checking `verdict.action` against the `block_on` set.

**Rationale:** The BTV Rust gatekeeper sets `hard_blocked=True` when the
proposal matches hard deny-lists (OFAC-sanctioned entities, known scam
addresses). This is a fail-secure signal that MUST override the ethical
pipeline — even if Gilligan's mercy would change BLOCK→EDUCATE, a hard block
is final per the Jonas responsibility principle.

**Consequence:** Hard-blocked proposals always raise `GrantBlockedError` with
`contestable=False` and `appeal_deadline_hours=0`, regardless of policy config.

---

### (c) HMAC-SHA256 for `session_id` — no double-hashing with BLAKE3

**Decision:** `GrantProposal.to_session_id()` uses `hmac.new(..., hashlib.sha256)`.

**Rationale:** The Rust kernel already applies BLAKE3 internally for integrity
verification (9596-byte TechnicalEvidence, ring buffer, BLAKE3 hash chain).
Adapters must NOT double-hash using BLAKE3 — this would create a hash collision
domain with the kernel's internal chain.

HMAC-SHA256 provides: deterministic session IDs per applicant, resistance to
length-extension attacks, and a distinct salt domain from the kernel's BLAKE3.

**Consequence:** Session IDs are 64 hex characters. Salt MUST be rotated per
environment (dev/staging/prod) via `GrantGuardConfig.session_salt`.

---

### (d) JSON minified serialization in `to_btv_input()` — language detector safety

**Decision:** `GrantProposal.to_btv_input()` serializes to compact JSON
(`json.dumps(..., ensure_ascii=False, separators=(',', ':'))`), NOT free text.

**Rationale:** Earlier drafts used text serialization:
```
Title: Projeto de Monitoramento\nDescription: Sensoriamento para a Amazônia
```
This is FRAGILE: English prefixes ("Title:", "Description:") pollute the BTV
language detector, causing pt-BR/es/sw proposals to be misidentified as en-US
and applying wrong governance profiles.

JSON minified avoids this — the Rust gatekeeper parses JSON natively and
extracts text fields for language detection independently of structural keys.

**Consequence:** `to_btv_input()` output is not human-readable. Debugging
requires JSON parsing. `to_dict()` is provided for human-readable logging.

---

### (e) Policy path `data/policies/sectors/grant-eligibility-v1.yaml`

**Decision:** The default policy path follows the existing sector taxonomy
in `data/policies/sectors/` (alongside `education.yaml`, `healthcare.yaml`,
etc.).

**Rationale:** The repository already has 12 sector-specific YAML files.
Creating a new directory (`data/policies/grants/`) would fragment the taxonomy.
The `sectors/` directory is the correct home per the existing IA.

**Consequence:** Policy file must be deployed alongside the adapter.
The `GrantGuardConfig.policy_path` parameter allows override per deployment.

---

### (f) `BiasDeclaration` null for Swahili — Jonas integrity principle

**Decision:** `DEFAULT_BIAS_DECLARATIONS[LinguisticGroup.SW]` has `fpr=None,
fnr=None, sample_size=0`. The `BiasDeclaration.__post_init__()` enforces this
via ValueError if non-null values are provided for the `sw` group.

**Rationale:** No real Swahili grant proposal dataset exists yet (0 samples).
Fabricating FPR/FNR values would violate the Jonas responsibility principle —
the system would claim calibration it doesn't have, leading to opaque unfairness
for East African applicants.

The honest position: declare uncalibrated, apply INSPECT as default action
(policy YAML `default_action_override: INSPECT`), and commit to calibration
when 500+ real proposals are collected.

**Consequence:** Swahili proposals receive elevated scrutiny (INSPECT) until
calibrated. This is disclosed in the `BiasDeclaration.notes` field and in the
policy YAML. Target calibration: 500+ proposals from East African Web3
community (Kenya, Tanzania, Uganda, Rwanda).

---

## Files Created

| File | Description |
|---|---|
| `sdk/integrations/grants/btv_grants/__init__.py` | Public API exports |
| `sdk/integrations/grants/btv_grants/adapter.py` | GrantGuard + GrantGuardConfig |
| `sdk/integrations/grants/btv_grants/exceptions.py` | GrantBlockedError + 3 others |
| `sdk/integrations/grants/btv_grants/models.py` | GrantProposal + BiasDeclaration |
| `data/policies/sectors/grant-eligibility-v1.yaml` | Sector policy YAML |
| `tests/integrations/grants/test_adversarial_grant_adapter.py` | 800 adversarial cases |

---

## Invariants

- `hard_blocked=True` → `contestable=False` + `appeal_deadline_hours=0` always
- Swahili BiasDeclaration `fpr=None` and `fnr=None` always (enforced by `__post_init__`)
- `to_btv_input()` output must be valid JSON (no English-prefix text format)
- `to_session_id()` output must be 64 hex characters (HMAC-SHA256)
- All functions ≤ 50 lines (BTV kernel invariant)
