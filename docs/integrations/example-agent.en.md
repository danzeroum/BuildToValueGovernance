[BuildToValue](../../README.md) › [Documentation](../README.md) › [Engineer Track](../for-engineers.md) › [Integrations](./index.md) › **Example Agent**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

# Example BTV-Compatible Agent — Integration Profile (ADR-029)

## Identification

| Field | Value |
|---|---|
| `agent_id` | `BLAKE3(agent_config_canonical)` — stable across restarts |
| `profile_id` | `default` |
| `sector_id` | `general` |
| Reference ADR | ADR-029 (canonical contract) |

## Actions → ActionImpact mapping

| Agent action | `impact` | Requires BTV gate |
|---|---|---|
| Read file | `Safe` | No (log locally) |
| Write file | `Destructive` | Yes |
| Send email | `Irreversible` | Yes |
| Call external API | `Irreversible` | Yes |
| Query database | `Safe` | No |
| Delete record | `Irreversible` | Yes |

## Integration flow
```
1. GET /v1/trust/{session_id}          → session_trust_score (TTL 60s)
2. POST /v1/validate                   → AgentDecisionRequest
3. Verify response HMAC                → constant-time (ADR-008)
4. Execute action if ALLOW/EDUCATE     → log evidence_id locally
5. If BLOCK → surface explain_decision to the operator + POST /v1/appeals
```

## Request example
```json
{
  "schema_version": "1.0",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_id": "a3b4c5d6e7f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a1b2c3d4e5f6a7b8",
  "session_id": "sess-abc123",
  "action": {
    "name": "send_email",
    "impact": "Irreversible",
    "capabilities": ["external_data_transfer", "email"]
  },
  "parameters_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "parameters_preview": {},
  "context": {
    "profile_id": "default",
    "sector_id": "general",
    "session_trust_score": 0.75,
    "agent_metadata": { "agent_version": "1.0.0" }
  },
  "timestamp_utc": "2026-03-07T12:00:00Z"
}
```

## Resilience protocol

| Scenario | Required behavior |
|---|---|
| Timeout (> 5s) | Local BLOCK + log `btv.timeout` |
| HTTP 5xx | 1 retry (100ms) → BLOCK |
| Invalid HMAC | BLOCK + alert `btv.hmac_mismatch` |
| Open circuit (≥3 failures/30s) | BLOCK every Destructive/Irreversible |

## Invariants (ADR-029 §9)

- No verified verdict → no execution
- Fail-secure: any error → BLOCK
- Cache forbidden for `Irreversible`
- `evidence_id` recorded on every ALLOW/EDUCATE
- API key unique per agent

---

### Next steps / Related

- [Integrations — overview](./index.md)
- [API Reference](../api-reference.md)
- [Concepts](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
