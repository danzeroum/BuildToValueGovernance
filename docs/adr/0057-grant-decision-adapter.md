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

---

## Cross-References

This ADR depends on and extends the following architectural decisions:

### ADR-001 — Hybrid Architecture (Rust + Python)

The grant adapter is a Python-layer component that communicates with the Rust
kernel (ADR-001). The separation of concerns is deliberate: the Rust gatekeeper
(`buildtovalue_kernel`) handles compute-intensive work (entropy analysis, regex
matching, BLAKE3 hashing, PII detection), while the Python adapter layer handles
business logic (policy YAML evaluation, sector-specific thresholds, multilingual
proposal parsing).

`GrantGuard.evaluate()` calls `/v1/decide` (the Rust gateway endpoint) and
interprets the `Verdict` response. The adapter does NOT re-implement any of the
Rust kernel's detection logic — it delegates entirely to the gatekeeper pipeline.

This is consistent with ADR-001's principle: Python handles orchestration and
policy; Rust handles high-throughput safety checks at microsecond latency.

**Contract with ADR-001:** The adapter MUST use the `/v1/decide` endpoint with
`use_decide=True` (full ethical pipeline) rather than the raw `/v1/scan` endpoint.
Grant proposals carry financial risk that warrants the complete Rawls → Levinas →
Jonas → Gilligan governance chain.

### ADR-015 — Interceptor Hooks Architecture

The BTV InterceptorChain (ADR-015) provides pre-flight and post-flight hooks in
the gatekeeper pipeline. The grant adapter is NOT a gatekeeper interceptor — it
is a higher-level client. However, the adapter respects the gatekeeper's
`InterceptAction.Block` signals returned via the Verdict.

When the gatekeeper's `ToolScreen` interceptor blocks a request (before it even
reaches the kernel modules), the Verdict carries `hard_blocked=True` with a
specific block reason. The grant adapter treats this identically to a hard block
from the full pipeline: `GrantBlockedError` is raised with `contestable=False`.

**Implication:** GrantGuard does not need to re-implement ToolScreen logic. The
Rust gatekeeper already applies the interceptor chain on every `/v1/decide` call.
This avoids the dual-validation anti-pattern that could introduce timing windows
between the adapter's validation and the gatekeeper's validation.

### ADR-022 — Streamlit Dashboard (btv-sigma)

The Streamlit dashboard (ADR-022) provides observability for the BTV governance
pipeline. Grant evaluations are logged as TechnicalEvidence records with a
9596-byte fixed layout (ADR-017). Each `GrantGuard.evaluate()` call that reaches
the BTV kernel generates a TechnicalEvidence entry that appears in the sigma
dashboard.

Operators monitoring grant evaluation throughput should filter the sigma dashboard
by `module_id=ValidatorModule.SensitiveDataValidator` to see financial PII
findings (CNPJ, CPF, IBAN, wallet addresses) that may accompany grant proposals.

The adapter populates `parameters_hash` (BLAKE3 of the full parameters JSON) in
the `/v1/decide` request, which the sigma dashboard uses to correlate verdicts
with proposals without exposing raw proposal content.

### ADR-031 — External Chatbot Vendor LLM Integration

ADR-031 documents the chatbot vendor integration pattern. The grant adapter
follows the same security posture:

- No API key embedded in source (uses environment variables or secrets manager)
- HMAC-SHA256 signatures on all outbound requests (via `GrantGuardConfig.session_salt`)
- Fail-secure default: if the BTV gateway is unreachable, `evaluate()` raises
  `GrantBlockedError` with rationale "gateway_unreachable" rather than allowing
  the proposal through

The grant adapter diverges from ADR-031 in one respect: it uses `use_decide=True`
by default (ADR-031 chatbot adapter uses `use_decide=False` because chat is
reversible). This difference is intentional and documented in decision (a) above.

---

## Consequences Summary

### Positive Consequences

1. **Fail-secure financial governance:** Every grant evaluation goes through the
   full BTV ethical pipeline. No proposal is allowed through on a technicality.
   Hard blocks (OFAC sanctions, scam wallets, Ponzi patterns) are final.

2. **Multilingual fairness:** JSON minified serialization (decision d) prevents
   English-prefix contamination of the language detector. Proposals in pt-BR, es,
   and sw are correctly identified and evaluated under their linguistic profiles.

3. **Honest bias disclosure:** The Jonas principle for Swahili (null FPR/FNR)
   prevents the system from claiming calibration it doesn't have. Applicants in
   the sw group know they receive elevated scrutiny (INSPECT) and why.

4. **Contestable by default:** Every BLOCK verdict (except hard blocks) is
   contestable with a 168-hour appeal window. The Levinas SLA guarantees an
   initial response within 24 hours and final decision within 168 hours.

5. **Adapter pattern reusability:** The 4-element pattern (exception, guard,
   validate, sanitize) established by the LangChain/CrewAI adapters is preserved.
   Operators familiar with `btv_langchain.LangChainBTVCallbackHandler` will
   recognize the `btv_grants.GrantGuard` interface.

### Negative Consequences

1. **Higher per-evaluation latency:** `use_decide=True` adds ~27ms vs
   `use_decide=False` (full pipeline vs scan-only). For batch processing of
   large grant rounds, this may require async evaluation or queue-based
   architecture.

2. **Swahili applicants face INSPECT until calibrated:** East African applicants
   using Swahili proposals will receive elevated scrutiny until a calibration
   dataset of 500+ real proposals is collected. This is disclosed but still
   introduces procedural friction for a potentially underserved group.

3. **OFAC hard blocks are final:** Applicants from sanctioned jurisdictions cannot
   appeal. This is legally required but may create false positives for
   applicants with dual nationality or VPN usage that incorrectly sets their
   `country_code`.

4. **JSON minified format breaks human readability:** Operators debugging
   proposals in the gateway logs must parse JSON. The `to_dict()` method is
   provided for structured logging, but raw logs show compact JSON.

5. **Policy YAML coupling:** The adapter depends on
   `data/policies/sectors/grant-eligibility-v1.yaml` being present and valid.
   Deployments that omit this file will fail at initialization. Policy updates
   require redeployment.

### Mitigations

- High latency: evaluate proposals asynchronously or in dedicated batch jobs
- Swahili scrutiny: publish calibration timeline in documentation; collect
  East African proposal data through partner programs
- OFAC false positives: implement manual override flow for dual-nationality cases
  with documentation requirements
- JSON readability: configure structured logging with `GrantProposal.to_dict()`

---

## Validation Criteria

The following criteria must be true at all times. CI enforces them via the
`Grant Adapter CI — Weeks 1-4` workflow (`.github/workflows/ci.yml`).

### Structural Invariants (Week 1)

| Criterion | Check | Status |
|---|---|---|
| 4 files in `btv_grants/` | W1.1 file existence | CI |
| 13 public symbols from `__init__.py` | W1.2 imports | CI |
| `session_id` is 64 hex chars, HMAC-SHA256 | W1.3 session_id | CI |
| `to_btv_input()` output is JSON, no English prefixes | W1.4 JSON | CI |
| `GrantBlockedError` has `contestable` + `appeal_deadline_hours` | W1.5 exception | CI |
| `hard_blocked` checked before `action` (source order) | W1.6 fail-secure | CI |
| `use_decide=True` is default | W1.7 config | CI |
| Swahili `BiasDeclaration` raises `ValueError` if `fpr` non-null | W1.8 Jonas | CI |

### Policy + ADR Invariants (Week 2)

| Criterion | Check | Status |
|---|---|---|
| Policy at `data/policies/sectors/grant-eligibility-v1.yaml` | W2.1 | CI |
| Policy has 10 required sections | W2.2 | CI |
| Metadata: semver, 90-day expiry, `sector=grants` | W2.3 | CI |
| Jurisdiction: 6+ bitmasks, OFAC sanctions, elevated risk | W2.4 | CI |
| Thresholds: monotonically ordered allow ≤ educate ≤ inspect ≤ block | W2.5 | CI |
| Gilligan: `enabled=True`, `max_intervention=EDUCATE` | W2.6 | CI |
| Levinas: SLA ≤ 24h/72h, 4 language groups | W2.7 | CI |
| Jonas: 90-day expiry, `sw=FLAG`, `Jonas` referenced | W2.8 | CI |
| This ADR: 2000+ words, cross-refs, Consequences + Validation sections | W2.9 | CI |

### Test Suite Invariants (Week 3)

| Criterion | Check | Status |
|---|---|---|
| 800+ test cases in `tests/test_grants_adapter.py` | W3.2 | CI |
| 8 categories × 100+ cases each | W3.3 | CI |
| All 4 linguistic groups represented | W3.4 | CI |
| ALLOW, BLOCK, HARD_BLOCK in ground truth | W3.5 | CI |
| All cases have required fields, valid structure | W3.6 | CI |
| All IDs unique, format `[A-Z]{2,4}-\d{3,4}` | W3.7 | CI |
| HARD_BLOCK cases: `should_raise=True`, `expected_exception='GrantBlockedError'` | W3.8 | CI |

### Runner + Schema Invariants (Week 4)

| Criterion | Check | Status |
|---|---|---|
| `tests/run_tests.py` and `tests/adversarial_data/dataset_schema.json` exist | W4.1 | CI |
| Runner responds to `--help` | W4.2 | CI |
| Runner supports `--dry-run` | W4.3 | CI |
| Runner supports `--cat <category>` for all 8 categories | W4.4 | CI |
| Runner supports `--lang <group>` for all 4 groups | W4.5 | CI |
| Runner supports `--json --output FILE` | W4.6 | CI |
| Dataset schema: Draft-07, 8 required fields, minItems≥800, `sw` bias null | W4.7 | CI |
| `python3 -m unittest test_grants_adapter` passes | W4.8 | CI |

---

## Open Questions

1. **Batch evaluation API:** Should the adapter expose `evaluate_batch()` as a
   fully async method (using `asyncio`) rather than a synchronous iteration? This
   would reduce wall-clock time for large grant rounds (Gitcoin Rounds typically
   evaluate 200–2000 proposals per round). Deferred to v1.1.

2. **Swahili calibration timeline:** The Jonas principle commits to null FPR/FNR
   until 500+ East African proposals are collected. The current target is Q2 2026.
   If the data collection timeline slips, should the policy expiry be extended or
   should INSPECT be retained indefinitely? Requires governance committee decision.

3. **Delegation depth for sub-grants:** If a grant recipient subsequently
   sub-grants to another applicant (common in ecosystem grants), what delegation
   depth applies? The current `delegation_depth` parameter in `AgentDecisionRequest`
   handles this for agent chains but not for grant chains. Requires ADR-058.

4. **Oracle verification for high-value grants:** Grants above $500K might require
   on-chain oracle verification (wallet ownership proof, multi-sig quorum).
   The `pa_p2p_oracle` policy is available in the agent governance pipeline
   (ADR-029) but not yet integrated into the grant adapter. Deferred to v1.2.

---

*This ADR was accepted on 2026-04-11 and supersedes the informal grant
screening notes in `docs/HANDOFF_TEMPLATES.md`. It is subject to review
at policy expiry (2026-07-01) or on significant changes to the BTV kernel
API, whichever comes first.*
