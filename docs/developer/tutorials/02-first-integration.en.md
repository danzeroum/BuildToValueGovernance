---
title: "Tutorial 02 — First Integration"
---

# Tutorial 02 — First Integration

You already know how to [handle the block](01-handle-failure.md). Now let's
call the gateway in the happy path.

## Step 1 — Decide

```bash
curl -X POST http://localhost:8080/v1/decide \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "demo-agent",
    "action": "summarize",
    "context": {"user_consent": true}
  }'
```

Response:

```json
{
  "decision": "ALLOW",
  "evidence_url": "/v1/evidence/<hash>",
  "verdict_id": "<ulid>"
}
```

## Step 2 — Consume the evidence

The evidence is returned in the **constitutional** (wire) format. To inspect
the structure, see the [generated technical reference](../reference/index.md).

## Step 3 — SDKs

- [Python SDK](../../integrations/python-sdk.md)
- [TypeScript SDK](../../integrations/typescript-sdk.md)

## Next

[Tutorial 03 — Out-of-browser cryptographic verification](03-verify-evidence-cli.md).
