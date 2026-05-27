[BuildToValue](../../README.md) › [Documentation](../README.md) › [Engineer Track](../for-engineers.md) › [Integrations](./index.md) › **TypeScript SDK**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

# TypeScript SDK

```bash
npm install @buildtovalue/sdk
```

Zero runtime dependencies. Uses the native `fetch` (Node 18+, Deno, Bun).
TypeScript 5.0+.

---

## BTVClient

```typescript
import { BTVClient } from "@buildtovalue/sdk";

const btv = new BTVClient({
  apiKey: "...",
  gatewayUrl: "http://localhost:8080",
  timeout: 30_000,   // ms, default 30s
  maxRetries: 3,     // retry on 5xx/429
  raiseOnBlock: false, // true → throws BTVBlockedError
});

// Full ethical pipeline
const verdict = await btv.decide("My CPF is 123.456.789-09", {
  sessionId: "sess-001",
  profile: "healthcare",
  agentId: "my-agent",
});

// Quick scan (Rust only)
const v = await btv.validate("SELECT * FROM users WHERE 1=1", {
  sessionId: "sess-001",
});

// Mask PII
const sanitized = await btv.sanitize("Email: user@example.com");

// Appeal
const appeal = await btv.appeal(
  verdict.verdict_id,
  "ABNT test data — not real PII.",
  { grounds: ["technical_error"], userId: "user-001" }
);

// Trust score
const ts = await btv.trustScore("sess-001");

// Health
const health = await btv.health();
```

---

## BTVSession

```typescript
const session = btv.session("sess-user-001");
// or with an auto-generated UUID:
const session = btv.session();

const v1 = await session.decide("Hello");
const v2 = await session.validate("SELECT ...");
const ts  = await session.trustScore();
```

---

## Types

```typescript
import type {
  Verdict,          // /v1/decide response
  ValidateVerdict,  // /v1/validate response
  Appeal,           // /v1/appeals response
  TrustScore,       // /v1/trust/{id} response
  SanitizeResult,   // /v1/sanitize response
  VerdictAction,    // "ALLOW" | "BLOCK" | "EDUCATE" | ...
  AppealStatus,     // "pending" | "under_review" | ...
  AppealGrounds,    // "rawls_equity" | "technical_error" | ...
} from "@buildtovalue/sdk";
```

---

## Error handling

```typescript
import {
  BTVAuthError,
  BTVBlockedError,
  BTVRateLimitError,
  BTVGatewayError,
  BTVValidationError,
} from "@buildtovalue/sdk";

try {
  const verdict = await btv.decide("text");
} catch (err) {
  if (err instanceof BTVAuthError) {
    console.error("Invalid API key");
  } else if (err instanceof BTVRateLimitError) {
    console.error(`Rate limit — retry in ${err.retryAfter}s`);
  } else if (err instanceof BTVBlockedError) {
    const { verdict_id, contestable } = err.verdict;
    console.error(`Blocked: ${verdict_id}, contestable: ${contestable}`);
  }
}
```

---

## Usage with Next.js / Edge Runtime

```typescript
// app/api/check/route.ts
import { BTVClient } from "@buildtovalue/sdk";

const btv = new BTVClient({ apiKey: process.env.BTV_API_KEY! });

export async function POST(req: Request) {
  const { text, sessionId } = await req.json();
  const verdict = await btv.decide(text, { sessionId });

  if (verdict.action === "BLOCK") {
    return Response.json({ blocked: true }, { status: 403 });
  }

  return Response.json({ verdict });
}
```

---

## Usage with Deno

```typescript
import { BTVClient } from "npm:@buildtovalue/sdk";

const btv = new BTVClient({ apiKey: Deno.env.get("BTV_API_KEY")! });
const verdict = await btv.decide("text");
```

---

### Next steps / Related

- [Integrations — overview](./index.md)
- [API Reference](../api-reference.md)
- [Concepts](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
