# ADR-043: Grant Decision Adapter

| Field | Value |
|-------|-------|
| **ADR ID** | ADR-043 |
| **Status** | Accepted |
| **Created** | 2025-11-01 |
| **Author** | BTV Governance Team |
| **Deciders** | Grant Adapter Working Group |
| **Supersedes** | None |
| **Related** | ADR-001 (Adapter Pattern), ADR-007 (Policy-as-Code), ADR-015 (Fail-Secure Defaults), ADR-022 (Mercy Algorithm), ADR-031 (Bias Declaration Integrity) |

---

## Context

The BuildToValueGovernance (BTV) project needs a dedicated adapter for grant proposal governance. Grant proposals represent a high-stakes use case — they involve real financial disbursements ($1K–$10M+), multiple linguistic communities (en-US, pt-BR, es, sw), and regulatory compliance requirements across jurisdictions (OFAC, EU AML, BCB, etc.).

Existing adapters (LangChain, CrewAI, AutoGen, LlamaIndex) default to `use_decide=False` (~3ms Rust-only). Grants require the opposite trade-off: the full ethical pipeline (~30ms) is warranted because financial risk demands deeper governance.

### Problem Statement

1. No existing adapter handles the grant domain's unique requirements.
2. The 4-element adapter pattern needs extension for grant-specific fields.
3. Session ID derivation must avoid collision with the Rust kernel's BLAKE3 operations.
4. Input serialization must preserve the original language of proposal text.

---

## Decision 1: `use_decide=True` as Default

**Status:** Accepted

**Decision:** GrantGuard defaults to `use_decide=True` — full `/v1/decide` endpoint (~30ms: Rawls → Levinas → Jonas → Gilligan).

**Rationale:**
- Grant proposals involve real financial risk. A false negative has direct monetary consequences.
- The full pipeline provides explainability needed for appeal workflows.
- 30ms latency is negligible compared to human review (hours to days).
- Gilligan's mercy stage (BLOCK → EDUCATE) is critical for first-time applicants.

**Consequences:** +27ms latency, higher API cost, deeper audit trail.

**Mitigation:** `GrantGuardConfig` allows `use_decide=False` for bulk pre-screening.

---

## Decision 2: HMAC-SHA256 for Session ID Derivation

**Status:** Accepted

**Decision:**
```python
def to_session_id(self, secret: bytes = b"btv-grant-salt") -> str:
    return hmac.new(secret, self.applicant_id.encode("utf-8"), hashlib.sha256).hexdigest()
```

**Rationale:**
- Avoids BLAKE3 collision with the Rust kernel's BTL layer.
- HMAC-SHA256 resists length-extension attacks that plain SHA-256 lacks.
- Deterministic: same applicant → same session, enabling trust history tracking.
- Salt rotation per environment (dev/staging/prod) is required.

**Rejected:** `hashlib.blake3` (Rust kernel owns BLAKE3), plain `uuid.uuid4()` (non-deterministic).

---

## Decision 3: JSON Minified Serialization for `to_btv_input()`

**Status:** Accepted

**Decision:** Compact JSON: `{"title":"...","description":"...","budget_usd":50000}`

**Rationale:** English prefixes ("Title:", "Description:") pollute the BTV language detector. A proposal titled "Monitoramento de Qualidade da Água" with an English "Title:" prefix could be misidentified as mixed/English, applying wrong governance profiles.

**Rejected:** Text with localized prefixes, Protocol Buffers (complexity), XML (verbosity).

---

## Decision 4: `hard_blocked` Checked Before `action`

**Status:** Accepted

**Decision:** Evaluation order in `evaluate()`:
```
1. _validate(proposal)        → structural pre-flight
2. _sanitize(proposal)        → input normalization
3. client.decide(...)         → BTV kernel call
4. if verdict.hard_blocked:   → FAIL-SECURE GATE (priority 1)
5. if action in block_on:     → POLICY GATE (priority 2)
6. return verdict             → ALLOW/EDUCATE/INSPECT/LOG
```

**Rationale:** `hard_blocked=True` is set by the Rust gatekeeper for hard deny-list matches (OFAC sanctions, known scams). This is an absolute gate — Gilligan's mercy cannot override it.

---

## Decision 5: Rich `GrantBlockedError`

**Status:** Accepted

**Decision:** `GrantBlockedError` includes: `contestable`, `appeal_deadline_hours`, `composite_risk`, `trust_score`, `mercy_applied`, `raw_verdict`.

**Rationale (Levinas SLA principle):** Every blocked entity must know their rights. Contestability information must be surfaceable without re-querying the kernel.

---

## Decision 6: Null Bias for Uncalibrated Groups (Swahili)

**Status:** Accepted

**Decision:** `BiasDeclaration` for Swahili MUST have `fpr=None` and `fnr=None`. `ValueError` raised otherwise.

**Rationale (Jonas integrity principle, ADR-031):** Fabricating bias calibration data violates the responsibility to truth. `sample_size=0` communicates honest uncalibrated status.

**Calibration target:** 500+ real proposals from East African Web3 communities before non-null values can be set.

---

## Decision 7: YAML Policy Placement in `data/policies/sectors/`

**Status:** Accepted

**Decision:** Policy at `data/policies/sectors/grant-eligibility-v1.yaml` following existing repository convention.

**Rationale:** Repository already uses `sectors/` for sector-specific policies (12 existing YAMLs). Root placement would break the organizational pattern.

---

## Consequences Summary

| Decision | Impact | Risk |
|----------|--------|------|
| `use_decide=True` default | +27ms latency, deeper audit | Low — acceptable for financial context |
| HMAC-SHA256 session ID | Deterministic, privacy-preserving | Low — salt rotation required |
| JSON minified serialization | Language-detector-safe, compact | None — net improvement |
| `hard_blocked` priority | Fail-secure sanctions enforcement | None — security improvement |
| Rich `GrantBlockedError` | Better UX, operational efficiency | Low — upstream API change |
| Null bias for uncalibrated | Integrity-preserving | Medium — elevated scrutiny for sw group |
| `sectors/` policy path | Convention-aligned | None |

---

## Validation Criteria

1. All 4 adapter elements implemented (exception, guard, validate, sanitize).
2. `hard_blocked=True` raises `GrantBlockedError(contestable=False)`.
3. `action=BLOCK` raises `GrantBlockedError(contestable=True)`.
4. `mercy_applied=True` with `action=EDUCATE` does NOT raise.
5. pt-BR proposals serialized as JSON correctly identified as Portuguese.
6. `BiasDeclaration(group=SW, fpr=0.05)` raises `ValueError`.
7. Same `applicant_id` produces same `session_id` across calls.
8. 800 adversarial tests passing across all 4 linguistic groups.

---

## Open Issues

- [ ] Appeal endpoint integration (`/v1/appeals`) — pending BTV Python SDK update
- [ ] Trust history endpoint (`/v1/trust/{session_id}`) — pending SDK update
- [ ] Swahili calibration — need 500+ real proposals from East African Web3 community
- [ ] Async batch evaluation — currently sequential, needs `asyncio` + `aiohttp`
- [ ] Webhook callbacks — for async verdict delivery on long-running INSPECT reviews
