[BuildToValue](../../README.md) › [Documentation](../README.md) › [Engineer Track](../for-engineers.md) › [Integrations](./index.md) › **Python SDK**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

# Python SDK

```bash
pip install buildtovalue
```

Supports Python 3.10+. Synchronous and asynchronous clients. Automatic retry
with backoff.

---

## Available clients

| Client | When to use |
|---|---|
| `BTVClient` | Synchronous apps, scripts, Flask, Django |
| `AsyncBTVClient` | FastAPI, asyncio, async frameworks |
| `BTVSession` | Multiple calls sharing the same `session_id` |

---

## BTVClient (synchronous)

```python
from buildtovalue import BTVClient

with BTVClient(
    api_key="...",
    gateway_url="http://localhost:8080",
    timeout=30.0,        # seconds
    max_retries=3,       # retry on 503/429/502
    raise_on_block=False # True → raises BTVBlockedError
) as btv:

    # Full ethical pipeline
    verdict = btv.decide("text", session_id="sess-001", profile="healthcare")

    # Quick scan (Rust only)
    v = btv.validate("text", session_id="sess-001")

    # Mask PII
    result = btv.sanitize("My CPF is 123.456.789-09")
    print(result.sanitized)  # "My CPF is [CPF]"

    # Appeal
    appeal = btv.appeal(
        verdict.verdict_id,
        reason="ABNT test data — not real PII.",
        grounds=["technical_error"],
    )

    # Trust score
    ts = btv.trust_score("sess-001")
    print(ts.level)  # "high" | "medium" | "low"

    # Health (no auth)
    print(btv.health())
```

---

## AsyncBTVClient

```python
import asyncio
from buildtovalue import AsyncBTVClient

async def main():
    async with AsyncBTVClient(api_key="...", gateway_url="http://localhost:8080") as btv:
        verdict = await btv.decide("text", session_id="sess-001")
        print(verdict.action)

asyncio.run(main())
```

---

## BTVSession — session context manager

Avoids repeating `session_id` on every call:

```python
with btv.session("sess-user-001") as s:
    v1 = s.decide("Hello")
    v2 = s.validate("SELECT * FROM users")
    ts = s.trust_score()

# Async version
async with btv_async.session("sess-001") as s:
    v = await s.decide("text")
```

---

## Response models

```python
from buildtovalue.models import (
    Verdict,        # response from /v1/decide
    ValidateVerdict, # response from /v1/validate
    Appeal,         # response from /v1/appeals
    TrustScore,     # response from /v1/trust/{id}
    SanitizeResult, # response from /v1/sanitize
)
from buildtovalue.models import VerdictAction, AppealStatus, AppealGrounds
```

### Verdict

```python
verdict.verdict_id          # "VRD-01ARZ3NDEK..."
verdict.action              # VerdictAction.ALLOW | BLOCK | EDUCATE | ...
verdict.original_action     # before mercy was applied
verdict.mercy_applied       # bool
verdict.composite_risk      # float [0.0, 1.0]
verdict.finding_count       # int
verdict.critical_count      # int
verdict.hard_blocked        # bool
verdict.contestable         # bool
verdict.appeal_deadline_hours # int
verdict.signature           # HMAC-SHA256

# Computed properties
verdict.is_blocked  # bool
verdict.is_allowed  # bool
verdict.explanation # rationale + explain.summary

# Philosophical rationale
verdict.explain.summary
verdict.explain.rawls_rationale
verdict.explain.levinas_rationale
verdict.explain.jonas_rationale
verdict.explain.gilligan_rationale
verdict.explain.trust_score   # float
verdict.explain.mercy_score   # float
```

---

## Error handling

```python
from buildtovalue.exceptions import (
    BTVError,          # base
    BTVAuthError,      # 401 — invalid API key
    BTVBlockedError,   # action==BLOCK when raise_on_block=True
    BTVRateLimitError, # 429 — .retry_after in seconds
    BTVGatewayError,   # 5xx
    BTVValidationError # 4xx
)

try:
    verdict = btv.decide("text")
except BTVAuthError:
    print("Invalid API key")
except BTVRateLimitError as e:
    print(f"Rate limit — retry in {e.retry_after}s")
except BTVGatewayError as e:
    print(f"Gateway error {e.status_code}")
```

---

## raise_on_block

```python
btv = BTVClient(api_key="...", raise_on_block=True)

try:
    verdict = btv.decide("DROP TABLE users")
except BTVBlockedError as e:
    print(e.verdict.verdict_id)  # access to the full verdict
    print(e.verdict.contestable)
```

---

## Automatic retry

The SDK retries automatically on `429`, `500`, `502`, `503`, `504` with
exponential backoff:

- Attempt 1: immediate
- Attempt 2: 2s
- Attempt 3: 4s
- Attempt 4: 8s

On 429, it honors the server's `Retry-After` header.

---

### Next steps / Related

- [Integrations — overview](./index.md)
- [API Reference](../api-reference.md)
- [Concepts](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
