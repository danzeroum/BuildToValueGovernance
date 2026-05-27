[BuildToValue](../README.md) › [Documentation](./README.md) › [Engineer Track](./for-engineers.md) › **API Reference**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

# API Reference

The full spec lives at [`spec/openapi.yaml`](https://github.com/buildtovalue/buildtovalue/blob/main/spec/openapi.yaml) (OpenAPI 3.0.3).

**Base URL:** `http://localhost:8080` (dev) · `https://gateway.buildtovalue.io` (prod)

**Authentication:** `X-API-Key: <your-key>` header on every endpoint except `/health`.

---

## POST /v1/decide

Full ethical pipeline (Rust + Python judiciary). Use it for decisions that
matter.

**Request:**
```json
{
  "input": "My CPF is 123.456.789-09",
  "session_id": "sess-user-001",
  "profile": "healthcare",
  "agent_id": "agent-xyz"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `input` | string | ✅ | Text to evaluate |
| `session_id` | string | — | Opaque session ID (for trust score) |
| `profile` | string | — | Sector profile |
| `agent_id` | string | — | Calling agent ID (audit) |

**Optional header:** `X-BTV-Jurisdiction: BR,EU` — jurisdiction bitmask

**Response 200:**
```json
{
  "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "action": "EDUCATE",
  "original_action": "BLOCK",
  "mercy_applied": true,
  "finding_count": 2,
  "critical_count": 1,
  "composite_risk": 0.71,
  "hard_blocked": false,
  "contestable": true,
  "appeal_deadline_hours": 24,
  "signature": "hmac-sha256:abc123...",
  "rationale": "CPF detected. First offense — educational response.",
  "jurisdiction_bitmask": 1,
  "latency_ms": 34.2,
  "explain": {
    "summary": "Sensitive PII detected. Mercy applied.",
    "rawls_rationale": "Violation of LGPD Art. 6 policy.",
    "levinas_rationale": "User deserves an explanation, not just a block.",
    "jonas_rationale": "Contained risk; no irreversible harm.",
    "gilligan_rationale": "First offense + trust > 0.6 → EDUCATE.",
    "trust_score": 0.72,
    "mercy_score": 0.83,
    "pipeline_stages": ["rawls", "levinas", "jonas", "gilligan"]
  }
}
```

---

## POST /v1/validate

Rust-only scan (no ethical pipeline). Faster, less reasoning. Use it for quick
validation.

**Request:** same shape as `/v1/decide` (without `agent_id`).

**Response 200:** same shape as `/v1/decide` without the `explain` field, plus
these extra fields:
```json
{
  "message": "SQL injection detected.",
  "matched_policies": ["sql_injection_hard_block"],
  "hard_block_term": "DROP TABLE",
  "max_finding_confidence": 0.99,
  "entropy": 3.2,
  "blake3_hash": "deadbeef..."
}
```

---

## POST /v1/sanitize

Masks PII and neutralizes injection patterns in the text.

**Request:**
```json
{ "text": "Contact John at john@example.com or 011-99999-9999" }
```

**Response 200:**
```json
{
  "sanitized": "Contact John at [EMAIL] or [PHONE]",
  "redactions": 2,
  "latency_ms": 3.1
}
```

---

## POST /v1/appeals

Appeals a verdict (LGPD Art. 20 / EU AI Act Art. 14).

**Request:**
```json
{
  "verdict_id": "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "user_id": "user-anon-001",
  "reason": "This CPF is from an ABNT test dataset, not real data.",
  "grounds": ["technical_error", "false_positive"],
  "evidence": "Reference: ABNT NBR ISO/IEC 27001 Annex A"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `verdict_id` | string | ✅ | ID of the verdict being appealed |
| `user_id` | string | ✅ | Opaque appellant identifier |
| `reason` | string (≥20 chars) | ✅ | Articulated reason (Levinas principle) |
| `grounds` | string[] | — | Philosophical/legal grounds |
| `evidence` | string | — | Additional evidence |

**Response 201:**
```json
{
  "appeal_id": "APL-01ARZ3NDEK...",
  "status": "pending",
  "sla_deadline": "2026-03-21T12:00:00Z",
  "mediator_recommendation": null
}
```

---

## GET /v1/appeals/{appeal_id}

Fetches an appeal's status.

**Response 200:** an `Appeal` object with `status`, `resolution`,
`mediator_recommendation`.

**Possible statuses:** `pending` → `under_review` → `accepted` | `rejected` | `expired`

---

## GET /v1/trust/{session_id}

Current trust score of the session.

**Response 200:**
```json
{
  "session_id": "sess-user-001",
  "trust_score": 0.82,
  "total_requests": 47,
  "offenses": 1,
  "calculated_at": "2026-03-20T12:00:00Z"
}
```

---

## GET /health

Public health check (no authentication).

```json
{ "status": "ok", "uptime_seconds": 3600.5, "version": "2.0.0" }
```

---

## Error codes

| Code | Meaning |
|---|---|
| `401` | Missing or invalid API key |
| `400` / `422` | Malformed request (e.g. `reason` < 20 chars) |
| `404` | Resource not found (unknown appeal_id) |
| `429` | Rate limit hit — the `Retry-After` header tells you when to retry |
| `503` | Python governance unavailable — Rust kernel runs in fail-secure mode |

---

## SDKs

The SDKs handle errors automatically with retry and backoff:

```python
from buildtovalue.exceptions import (
    BTVAuthError,      # 401
    BTVBlockedError,   # verdict.action == BLOCK (with raise_on_block=True)
    BTVRateLimitError, # 429, with .retry_after in seconds
    BTVGatewayError,   # 5xx
    BTVValidationError # 4xx
)
```

---

### Next steps / Related

- [Quickstart](./quickstart.md)
- [Concepts](./concepts.md)
- [Integrations](./integrations/index.md)
- [Changelog](./changelog.md)

---

<sub>[↑ Hub](./README.md) · [Engineer Track](./for-engineers.md) · [DPO/CISO Track](./for-dpo-ciso.md) · [Reference Links](./reference-links.md)</sub>
