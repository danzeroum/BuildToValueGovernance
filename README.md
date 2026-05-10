# BuildToValue (BTV)

**Cryptographic Immutable Evidence for AI Agent Decisions. Compile-Time Guarantee.**

Every AI decision your system makes is either **provably accountable** or a liability. BTV makes accountability structurally impossible to bypass — if your agent tries to issue a decision without cryptographic evidence, the compiler rejects it. Not a runtime check. Not a policy. A **type error**.

```
Your agent decides → BTV fuses evidence + decision atomically → Immutable receipt (BLAKE3 + HMAC-SHA256)
                                        ↑
                           Compiler rejects any bypass
```

---

## The Problem BTV Solves

> *"Our AI denied a loan / rejected a candidate / blocked access. A regulator asked for the evidence trail. We had logs. The logs were incomplete."*

This is not a logging problem. It is a **structural accountability problem**. Runtime logs can be dropped under load, overwritten, or silently omitted. BTV eliminates this class of failure at compile time.

**Regulatory context:** GDPR Art. 22, EU AI Act Art. 86, LGPD Art. 18 — all require that AI decisions carry auditable evidence. BTV makes non-compliance a compiler error, not a runtime risk.

---

## Quick Start (< 5 minutes)

```bash
# 1. Add BTV to your Rust project
cargo add buildtovalue

# 2. Wrap any AI decision
use buildtovalue::{EvidenceToken, ComplianceToken, Verdict};

let evidence = EvidenceToken::new(&context_bytes);      // BLAKE3 hash of what the AI saw
let compliance = ComplianceToken::new("GDPR", "v1", 720); // jurisdiction + appeal window
let verdict = Verdict::new(evidence, compliance, Decision::Deny, explanation);
// ^ If you omit evidence or compliance, this line does NOT COMPILE.

# 3. Inspect the immutable receipt
println!("{}", verdict.receipt());
// {"decision":"Deny","evidence_id":"a3f8...","hmac":"9b2c...","timestamp":"..."}
```

**Python / TypeScript / Java:** Use the HTTP sidecar — no Rust required.

```bash
docker run -p 3000:3000 buildtovalue/gateway:latest
curl -X POST http://localhost:3000/v1/decide \
  -d '{"context": "...", "decision": "deny", "explanation": "..."}'
# Returns: signed receipt with BLAKE3 evidence hash
```

---

## Performance

BTV adds **~1.67μs** per decision for a 4KB context payload — five orders of magnitude less than a typical LLM inference call.

| Operation | Latency | Notes |
|---|---|---|
| `Verdict::new` (4KB context) | 1.67 μs | BLAKE3 + HMAC-SHA256 |
| `verify_integrity` | 327 ns | Retroactive audit |
| Gateway HTTP (sidecar) | < 50ms p99 | Includes network round-trip |

At 1 million decisions/year, total infrastructure cost is **~$5,000/year** — compared to median GDPR fines of **$10.8M** for evidential failures.

---

## Architecture

```
┌────────────────────────────────────────────────────┐
│               Axum HTTP Gateway                    │
│   /v1/decide   /v1/verify   /v1/audit   /health   │
├────────────────────┬───────────────────────────────┤
│   Rust Kernel      │      Python Governance        │
│   < 30ms p99       │      < 10ms p99               │
│                    │                               │
│  EvidenceToken     │  ComplianceEngine             │
│  BLAKE3 hash       │  explain_decision()           │
│  HMAC-SHA256       │  AppealEngine (24h SLA)       │
│  Fail-secure       │  BiasDetector                 │
│  Zero-heap hot path│                               │
├────────────────────┴───────────────────────────────┤
│              Immutable Ledger                      │
│   WAL + BLAKE3 chain   HMAC-SHA256 per record      │
└────────────────────────────────────────────────────┘
```

**Core invariants:**
- `TechnicalEvidence`: 9632 bytes fixed, BLAKE3, compile-time verified
- Zero-heap hot path: stack-only in evidence/gatekeeper
- Fail-secure: any error → BLOCK (never bypass)
- Every verdict signed: HMAC-SHA256
- Contestability: `contestable: true` + 24h appeal SLA

---

## Installation

### Rust (Open Core — MIT/Apache 2.0)

```toml
[dependencies]
buildtovalue = "2.3"
```

### Python SDK

```bash
pip install buildtovalue-sdk
```

```python
from buildtovalue import BTVClient

client = BTVClient("http://localhost:3000")
receipt = client.decide(
    context=my_agent_context,
    decision="deny",
    explanation="Credit score below threshold"
)
print(receipt.evidence_hash)  # BLAKE3 hash — immutable proof
```

### Docker Sidecar

```bash
docker run -p 3000:3000 \
  -e BTV_HMAC_KEY=your-key \
  buildtovalue/gateway:latest
```

---

## Kernel — 15 Validation Modules

| Stage | Modules |
|---|---|
| Deobfuscate | Base64, Hex, Leetspeak |
| Analyze | Entropy, ZScore, CharRatio, LanguageDetector |
| Validate | CPF, CNPJ, Email, CreditCard, Phone, PromptInjection, SSN |
| Multi-jurisdiction | NHS (UK), EU VAT, IBAN (jurisdiction-gated) |

---

## Use Cases

**Financial services** — Loan/credit decisions with immutable evidence trail for GDPR Art. 22 audits.

**HR / Hiring systems** — Automated screening verdicts with compile-time accountability under EU AI Act Art. 86.

**Healthcare triage** — AI-assisted allocation decisions with cryptographic audit for liability protection.

**Multi-agent pipelines** — Governance layer for LangChain, AutoGen, CrewAI — wrap any agent decision in < 10 lines.

---

## Known Limitations

- False positive rate ~15% on adversarial inputs (70 samples, not externally validated)
- Leetspeak FNR ~12% (Unicode homoglyphs not covered)
- No TLS on gateway (plain HTTP — add a reverse proxy for production)
- Ledger rotation not yet implemented (grows indefinitely)
- Rust BLAKE3 weights verification (full ADR-005 integration) pending v2.3
- SLM latency on CPU-only: 500ms–5s (supplementary module, never blocks pipeline)

---

## Development

```bash
# Rust kernel
cd rust && cargo build --workspace && cargo test --workspace

# Python governance
cd python && pip install -e ".[dev]" && pytest tests/ -v

# Full stack
cd ops && docker compose up
# Gateway: http://localhost:3000  |  Governance: http://localhost:8000
```

---

## Benchmarks

```bash
cd benchmarks && cargo bench --bench kernel_benchmark
```

See `benchmarks/` for comparative results against Guardrails AI and NeMo Guardrails.

---

## Roadmap

| Version | Status | Scope |
|---|---|---|
| v2.2 | ✅ Complete | PolicyEngine, AbliterationDetector v1.2.0, ManifestHashVerifier, IntegrityVerifier |
| v2.3 | 🚧 Current | Rust BLAKE3 weights verification, pipeline wiring, SDK stabilization |
| v3.0 | Planned | MCP server (Model Context Protocol), crates.io publish, Python SDK GA |

---

## License

Apache 2.0 — see [LICENSE-MIT](LICENSE-MIT).

---

## Contributing

- Multi-jurisdiction validators (new PII patterns)
- Benchmark scripts against Guardrails AI / NeMo
- Python SDK integrations (LangChain, AutoGen, CrewAI)
- Documentation improvements

See [docs/quickstart.md](docs/quickstart.md) to get started.
