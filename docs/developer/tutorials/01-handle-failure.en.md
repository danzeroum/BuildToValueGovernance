---
title: "Tutorial 01 — Handling the Block (Fail-Secure)"
---

# Tutorial 01 — Handling the Block

> This is the **first** tutorial by design. In BTV, the block is where trust is
> tested — not the happy path.

## Goal

You will:

1. Trigger a scenario that yields `HTTP 451`.
2. Read the evidence attached to the block.
3. Present the `ContestabilityLoop` to the end user.

## Prerequisites

- Local emulator running: `make emulator-up`.
- `curl` or your favorite HTTP client.

## Step 1 — Trigger the block

```bash
curl -i -X POST http://localhost:8080/v1/decide \
  -H 'Content-Type: application/json' \
  -d @demo/playground/scenarios/block-451.json
```

Expected response:

```http
HTTP/1.1 451 Unavailable For Legal Reasons
Content-Type: application/json
X-BTV-Evidence-Hash: <hex hash>

{
  "decision": "BLOCK",
  "reason": "policy_violation:HIPAA_base",
  "evidence_url": "/v1/evidence/<hash>",
  "contestability": {
    "endpoint": "/v1/contest",
    "sla_hours": 24,
    "protocol": "ADR-0047"
  }
}
```

## Step 2 — Read the evidence

```bash
curl http://localhost:8080/v1/evidence/<hash> | jq .
```

The payload size must match the **constitutional size**
(see the [generated technical reference](../reference/index.md)).

## Step 3 — Surface the contestation

Do not silently swallow the `451`. Present to the end user:

- The structured reason (`reason`).
- The contestation endpoint (`contestability.endpoint`).
- The SLA (`contestability.sla_hours`).

The playground does this for you — see
[`demo/playground/index.html`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/demo/playground/index.html).

## What you learned

- BTV fails closed by design ([fail-secure](../concepts/fail-secure.md)).
- Every decision produces auditable evidence ([anatomy](../concepts/evidence-anatomy.md)).
- Every block admits contestation ([loop](../concepts/contestability-loop.md)).

## Next

- **Integrator track:** [Tutorial 02 — First Integration](02-first-integration.md).
- **Want to audit the proof out of browser?** [Tutorial 03 — `btv-cli verify`](03-verify-evidence-cli.md).
