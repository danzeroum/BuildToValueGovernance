# ADR-043: Grant Decision Adapter

**Status:** Accepted  
**Date:** 2025-11-01  
**Authors:** BTV AI Squad (Arquiteta + Dev Python + Reviewer)  
**Relates to:** ADR-028 (Adapter Pattern), ADR-031 (Fail-Secure), ADR-037 (BiasDeclaration)

---

## Context

The BuildToValue ecosystem needs a governance adapter for grant funding pipelines
(Gitcoin Rounds, DAO treasury disbursements, quadratic funding platforms).
Grant proposals carry real financial risk — fraudulent applications, sanctioned
entities, Ponzi schemes, and jurisdiction violations can cause direct financial
harm to both the platform and applicants.

Existing adapters (LangChain, CrewAI, AutoGen) are designed for AI output
screening. Grant evaluation requires domain-specific models, multilingual
support for 4 linguistic groups (en-US, pt-BR, es, sw), and stricter governance
than LLM output filtering.

---

## Decisions

### §1 — use_decide=True (Full Ethical Pipeline by Default)

**Decision:** `GrantGuardConfig.use_decide` defaults to `True`, calling `/v1/decide`
(full Rawls → Levinas → Jonas → Gilligan pipeline, ~30ms) instead of
`/v1/validate` (Rust-only gatekeeper, ~3ms).

**Rationale:** Other adapters (LangChain, CrewAI, AutoGen) default to `use_decide=False`
because LLM output screening prioritizes throughput. Grant evaluation involves
real financial disbursement — the full ethical pipeline is warranted even at
higher latency cost. The 30ms overhead is negligible for human-facing grant
approval flows.

**Consequences:** Adapters that reuse GrantGuard for high-throughput contexts
can set `use_decide=False` explicitly, but must document this as a deliberate
deviation in their own ADR.

---

### §2 — HMAC-SHA256 for Session ID (Not BLAKE3)

**Decision:** `GrantProposal.to_session_id()` uses `hmac.new(..., hashlib.sha256)`,
not `hashlib.blake3`.

**Rationale:** The BTV Rust kernel already applies BLAKE3 internally via the
BTL (BLAKE3 Throughput Layer) in the Executive branch. Adapters that also use
BLAKE3 create a double-hashing dependency on the Rust kernel's internal
implementation, which is not part of the public SDK contract.

HMAC-SHA256 provides:
- Deterministic session IDs per applicant (same applicant → same session)
- Resistance to length-extension attacks vs plain SHA-256
- A distinct salt domain from the kernel's BLAKE3 operations
- Alignment with how `agent_pdp.py` derives its `hmac_sha256` signatures

**Consequences:** The `session_salt` MUST be rotated per environment
(dev/staging/prod). Default salt `b"btv-grant-salt"` is for development only.

---

### §3 — JSON Minified Serialization for to_btv_input()

**Decision:** `GrantProposal.to_btv_input()` serializes to compact JSON
(`json.dumps(..., separators=(",", ":"))`), not to a text string with English
prefixes like `"Title: ...\nDescription: ..."`.

**Rationale:** The BTV Rust gatekeeper's `LanguageDetector` analyzes the raw
text input to determine the proposal's linguistic group and apply the correct
governance profile. Text serialization with English structural keys ("Title:",
"Description:", "Budget:") pollutes the language signal for non-English proposals:
- A Portuguese proposal serialized as `"Title: Monitoramento de Água"` gets
  detected as mixed en-US/pt-BR and routed to the wrong governance profile.
- JSON keys are language-neutral and parsed structurally, not as language content.

**Consequences:** The BTV kernel must support JSON input parsing. This is
confirmed by the Rust gatekeeper specification (spec/kernel-api-v2.md).

---

### §4 — hard_blocked Gate Checked Before action Gate

**Decision:** In `GrantGuard.evaluate()`, the `verdict.hard_blocked` field is
checked BEFORE `verdict.action` is compared against `config.block_on`.

**Rationale:** The Rust gatekeeper sets `hard_blocked=True` for proposals that
match hard deny-list patterns (sanctioned entities, known scam wallets, Ponzi
scheme language). This is a fail-secure gate that operates independently of the
ethical pipeline. The `action` field reflects the ethical pipeline's recommendation
— it could be `EDUCATE` for a high-trust applicant from a sanctioned country,
but the hard block must take precedence regardless.

Current SDK model (sdk/python/buildtovalue/models.py) confirms `hard_blocked`
is a separate field from `action`, both present on the `Verdict` object.

**Consequences:** `GrantBlockedError` raised from a hard block always has
`contestable=False` and `appeal_deadline_hours=0`. The `action` value is
included for audit purposes but has no governance significance for hard blocks.

---

### §5 — Policy YAML Path in data/policies/sectors/

**Decision:** The grant eligibility policy is placed at
`data/policies/sectors/grant-eligibility-v1.yaml`, following the existing
taxonomy of sector-specific policies.

**Rationale:** The `data/policies/sectors/` directory already contains 12+
sector-specific YAML policies (education.yaml, healthcare.yaml, climate.yaml,
etc.). Placing the grant policy in a parallel `data/policies/grants/` directory
would create an inconsistency in the policy taxonomy and require changes to
the BTV kernel's policy loader.

**Consequences:** Policy filename MUST include the version suffix (`-v1`) to
support side-by-side versioning during policy migrations.

---

### §6 — BiasDeclaration fpr/fnr=None for Swahili (sw)

**Decision:** `DEFAULT_BIAS_DECLARATIONS[LinguisticGroup.SW]` has `fpr=None`
and `fnr=None`. The `BiasDeclaration.__post_init__()` validator raises
`ValueError` if a non-None FPR/FNR is provided for the `sw` group.

**Rationale:** The Jonas responsibility principle in BTV governance forbids
fabricating empirical data. No real-world Swahili grant proposal calibration
dataset exists at the time of this ADR. Assigning synthetic FPR/FNR values
would create a false appearance of calibration, potentially misleading
governance decisions for East African applicants.

The policy YAML routes uncalibrated `sw` proposals to INSPECT (human review)
rather than automated ALLOW/BLOCK decisions.

**Consequences:** FPR/FNR for `sw` group will remain None until 500+ real
Swahili grant proposals are collected from the East African Web3 community.
Calibration target communities: Kenya, Tanzania, Uganda, Rwanda.

---

### §7 — GrantBlockedError Carries Contestability Context (Levinas SLA)

**Decision:** `GrantBlockedError` includes `contestable: bool` and
`appeal_deadline_hours: int` as mandatory fields, not optional attributes.

**Rationale:** The Levinas principle in BTV governance requires that every
blocked entity knows whether they can appeal and within what timeframe. Upstream
callers (e.g. Gitcoin Round Manager API) must surface this information to
applicants without requiring an additional query to the BTV kernel.

Making these fields mandatory (not Optional) prevents callers from accidentally
omitting them, which would silently deny applicants their contestability rights.

**Consequences:** Hard blocks set `contestable=False, appeal_deadline_hours=0`.
Policy blocks set `contestable=True, appeal_deadline_hours=168` (7 days, per
policy YAML `contestability.policy_block_sla_hours`).

---

## Alternatives Considered

### Alt-1: Reuse existing `ContentGuard` from LangChain adapter
Rejected: `ContentGuard` (sdk/integrations/langchain/btv_langchain/callback.py)
is designed for LLM output text, not structured domain objects. It lacks
`GrantProposal` validation, multilingual bias declarations, and budget-aware
risk weighting.

### Alt-2: use_decide=False for performance
Rejected: Grant evaluation involves real financial disbursement. The 30ms
latency overhead of the full ethical pipeline is acceptable for human-facing
flows. Performance-critical paths can override via `GrantGuardConfig(use_decide=False)`.

### Alt-3: Plain SHA-256 for session_id
Rejected: SHA-256 without HMAC is vulnerable to length-extension attacks.
HMAC-SHA256 with a rotating salt is the correct construction.

---

## Implementation Notes

- Adapter: `sdk/integrations/grants/btv_grants/adapter.py`
- Models: `sdk/integrations/grants/btv_grants/models.py`
- Exceptions: `sdk/integrations/grants/btv_grants/exceptions.py`
- Policy: `data/policies/sectors/grant-eligibility-v1.yaml`
- Tests: `tests/test_grants_adapter.py` (800 adversarial cases)

## Review Checklist

- [x] hard_blocked checked before action in evaluate()
- [x] GrantBlockedError has contestable + appeal_deadline_hours
- [x] to_session_id() uses HMAC-SHA256 (not BLAKE3)
- [x] to_btv_input() uses JSON minified (not text prefixes)
- [x] BiasDeclaration sw fpr/fnr enforced as None
- [x] Policy YAML in data/policies/sectors/
- [x] use_decide=True documented as intentional deviation
- [x] All decisions reference a philosophical principle (Rawls/Levinas/Jonas/Gilligan)
