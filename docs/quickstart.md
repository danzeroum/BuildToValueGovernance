[Docs](./README.md) · [Engenheiro](./for-engineers.md) › **Quickstart**

![Engenheiro](https://img.shields.io/badge/Trilha-Engenheiro-1f6feb)

<!-- audience: engineer -->

---

# Quickstart — Under 5 Minutes

Choose your path. **No Docker required** for the primary flow.

---

## Path A — Rust (Compile-Time Guarantee)

The fastest way to see BTV's core invariant: a decision that compiles without evidence is impossible.

```bash
cargo new my-agent && cd my-agent
cargo add buildtovalue
```

```rust
use buildtovalue::{EvidenceToken, ComplianceToken, Verdict, Decision};

fn main() {
    // Simulate what your AI agent saw (prompt + context)
    let context = b"loan application: score=520, threshold=600";

    // 1. Bind evidence — BLAKE3 hash of the context
    let evidence = EvidenceToken::new(context);

    // 2. Declare compliance jurisdiction
    let compliance = ComplianceToken::new("GDPR", "v1", 720); // 720h = 30-day appeal window

    // 3. Issue verdict — atomically consumes both tokens
    let verdict = Verdict::new(evidence, compliance, Decision::Deny, "Score below threshold".into());

    // 4. Immutable receipt
    println!("evidence_id : {}", verdict.evidence_id());
    println!("hmac_seal   : {}", verdict.hmac());
    println!("contestable : {}", verdict.contestable());
}
```

```bash
cargo run
# evidence_id : a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0
# hmac_seal   : 9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
# contestable : true
```

> **Try breaking it:** Delete the `evidence` argument from `Verdict::new` and run `cargo build`. You will get a **compile error**, not a runtime failure. This is the BTV guarantee.

---

## Path B — HTTP Sidecar (Python / TypeScript / any stack)

For teams that do not write Rust. The sidecar wraps any agent decision.

```bash
docker run -p 3000:3000 \
  -e BTV_HMAC_KEY=dev-key-change-in-prod \
  buildtovalue/gateway:latest
```

```bash
curl -s -X POST http://localhost:3000/v1/decide \
  -H "Content-Type: application/json" \
  -d '{
    "context": "loan application: score=520, threshold=600",
    "decision": "deny",
    "explanation": "Score below threshold",
    "jurisdiction": "GDPR"
  }' | jq .
```

```json
{
  "verdict_id": "VRD-01ARZ3NDEK...",
  "decision": "deny",
  "evidence_id": "a3f8b2c1...",
  "hmac_seal": "9b2c3d4e...",
  "contestable": true,
  "appeal_deadline_hours": 720,
  "latency_us": 1670
}
```

**Python SDK:**

```bash
pip install buildtovalue-sdk
```

```python
from buildtovalue import BTVClient

client = BTVClient("http://localhost:3000")

receipt = client.decide(
    context="loan application: score=520, threshold=600",
    decision="deny",
    explanation="Score below threshold",
    jurisdiction="GDPR"
)

print(receipt.evidence_id)   # BLAKE3 hash — your immutable proof
print(receipt.hmac_seal)     # HMAC-SHA256 — tamper-evident seal
print(receipt.contestable)   # True — user can appeal within 720h
```

---

## Path C — MCP (Claude Desktop / Cursor)

For teams using MCP-compatible AI platforms.

```bash
pip install btv-mcp-server
```

Add to your MCP config:

```json
{
  "mcpServers": {
    "btv": {
      "command": "btv-mcp-server",
      "env": {
        "BTV_GATEWAY_URL": "http://localhost:3000"
      }
    }
  }
}
```

Your AI agent now calls `btv_decide()` as a tool — every decision is automatically wrapped with cryptographic evidence.

---

## Understanding the Receipt

Every BTV verdict contains:

| Field | What it means |
|---|---|
| `evidence_id` | BLAKE3 hash of exactly what the AI saw at decision time |
| `hmac_seal` | HMAC-SHA256 over the full verdict — detects tampering |
| `contestable` | Whether the affected party can file an appeal |
| `appeal_deadline_hours` | Time window for appeal (GDPR: 720h / 30 days) |
| `verdict_id` | Globally unique, immutable ID for audit trail |

To verify any stored verdict:

```rust
let is_valid = stored_verdict.verify_integrity(); // 327ns — audit at 3M/sec/core
```

---

## What Happens if Evidence is Missing?

This is BTV's core guarantee. Without evidence, `Verdict::new` does not compile:

```rust
// This fails at compile time — E0061: missing required argument
let bad_verdict = Verdict::new(compliance, Decision::Deny, "reason".into());
//                             ^^^^^^^^^^
//                             error: expected EvidenceToken, got ComplianceToken
```

No silent decisions. No logging pipeline to misconfigure. The compiler is the enforcement mechanism.

---

## Next Steps

- [API Reference](api-reference.md) — full endpoint documentation
- [Benchmarks](../benchmarks/) — comparative latency vs Guardrails AI / NeMo
- [LangChain integration](integrations/langchain.md)
- [Architecture](../docs/ARCHITECTURE_ATLAS.md)

---

<sub>[↑ Hub](./README.md) · [Trilha Engenheiro](./for-engineers.md) · [Trilha DPO/CISO](./for-dpo-ciso.md) · [Links de Referência](./reference-links.md)</sub>
