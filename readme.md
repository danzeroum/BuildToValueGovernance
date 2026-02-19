# BuildToValue — Sovereign Trust OS

**Ethical governance infrastructure for AI agents. Rust kernel (facts) + Python governance (judgment).**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/buildtovalue/sovereign-trust-os/actions/workflows/ci.yml/badge.svg)](https://github.com/buildtovalue/sovereign-trust-os/actions/workflows/ci.yml)

---

## What It Does

BuildToValue is an ethical Trust OS that sits between AI agents and users, enforcing governance through a "República Algorítmica" (Algorithmic Republic):

**Legislative** (Policy-as-Code) → **Executive** (Rust Kernel < 30ms) → **Judiciary** (Python Governance < 10ms) → **Auditory** (Immutable Ledger)

Every decision is explainable, signed (HMAC-SHA256), and contestable (24h appeal SLA).

Runtime compliance enforcement evaluates every decision against EU AI Act and LGPD in real-time. High-risk AI systems are automatically classified per Annex III, with Fundamental Rights Impact Assessment (FRIA) generation.

## Architecture
```
User Input
  → Rust Gateway (:8080)
    → Kernel: validators, entropy, deobfuscator, policy engine
    → TechnicalEvidence (9596 bytes, BLAKE3)
  → Python Governance (:8000)
    → SLM Classifier (ambiguity zone only, fail-open)
    → EthicalContextEngine: trust + mercy + profile + sector
    → Signed EthicalVerdict (HMAC-SHA256)
  → Immutable Ledger (decisions.jsonl)
  → Webhook notification (BLOCK/HARD_BLOCK)
```

## Quick Start (Docker)
```bash
cd ops
docker compose up -d
```

| Service | Port | Purpose |
|---|---|---|
| Rust Gateway | 8080 | Validation + PII masking |
| Python Governance | 8000 | Ethical judgment + Trust + Appeals |
| Streamlit Dashboard | 8501 | Visual interface (9 pages) |
| Prometheus | 9090 | Metrics |
| Grafana | 3000 | Dashboard (admin/changeme) |

### Test It
```bash
# PII detection (BLOCK)
curl -s -X POST http://localhost:8080/v1/validate \
  -H "Content-Type: application/json" \
  -d '{"input": "CPF 123.456.789-09"}' | python -m json.tool

# SQL injection (HARD BLOCK)
curl -s -X POST http://localhost:8080/v1/validate \
  -H "Content-Type: application/json" \
  -d '{"input": "DROP TABLE users"}' | python -m json.tool

# PII masking
curl -s -X POST http://localhost:8080/v1/sanitize \
  -H "Content-Type: application/json" \
  -d '{"text": "email joao@empresa.com CPF 123.456.789-09"}' | python -m json.tool

# Mercy flow: build trust then test
for i in $(seq 1 8); do
  curl -s -X POST http://localhost:8080/v1/validate \
    -H "Content-Type: application/json" \
    -d '{"input": "ola tudo bem", "session_id": "demo-user"}' > /dev/null
done
curl -s -X POST http://localhost:8080/v1/validate \
  -H "Content-Type: application/json" \
  -d '{"input": "email teste@gmail.com", "session_id": "demo-user"}' | python -m json.tool
```

## API Endpoints

### Rust Gateway (:8080)

| Endpoint | Method | Function |
|---|---|---|
| `/v1/validate` | POST | Scan + Policy + Governance |
| `/v1/validate/batch` | POST | Batch scan |
| `/v1/sanitize` | POST | PII masking |
| `/v1/policy/test` | POST | Policy test |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus |

### Python Governance (:8000)

| Endpoint | Method | Function |
|---|---|---|
| `/v1/decide` | POST | Ethical judgment (SLM + mercy + trust + HMAC) |
| `/v1/trust/{session_id}` | GET | Trust score |
| `/v1/appeals` | POST/GET | Submit/list appeals |
| `/v1/appeals/{id}/resolve` | POST | Resolve appeal (human reviewer) |
| `/v1/ledger/query` | GET | Query audit ledger (filters + pagination) |
| `/v1/compliance/report/{fw}` | GET | Compliance report |
| `/v1/intelligence/bridge/sync` | POST | Threat→Policy sync |
| `/v1/webhooks/status` | GET | Webhook stats |
| `/v1/compliance/classify-risk` | POST | EU AI Act Annex III risk classification |
| `/v1/compliance/fria/generate` | POST | Fundamental Rights Impact Assessment (Art. 27) |

## Project Structure
```
buildtovalue/
├── rust/                              # Rust Hemisphere (facts)
│   ├── kernel/src/                    # buildtovalue-kernel
│   │   ├── lib.rs, core/, evidence/, gatekeeper.rs
│   │   ├── validators/               # CPF, CNPJ, email, phone, credit card
│   │   ├── statistics/               # entropy, zscore, char ratio
│   │   ├── deobfuscator/             # base64, hex, leetspeak, chain
│   │   ├── policy/                   # engine.rs (YAML -> runtime)
│   │   ├── security/                 # hmac, output_guard, session_guard
│   │   ├── ledger/                   # wal, chain, durable
│   │   └── compliance/, ffi/, batch.rs, observability/
│   ├── gateway/src/                   # Axum HTTP gateway
│   ├── bindings/                      # PyO3/Maturin bridge
│   └── cli/                           # btv command-line tool
├── python/buildtovalue/               # Python Hemisphere (judgment)
│   ├── api/                           # FastAPI + routes (ledger, webhooks, intelligence, compliance)
│   ├── governance/                    # EthicalContextEngine, mercy, trust, contestability, profiles
│   ├── intelligence/                  # SLM classifier, MISP ingestor, threat bridge
│   ├── compliance/                    # Framework evaluator, translator
│   └── dashboard/                     # Streamlit MVP (9 pages)
├── data/
│   ├── policies/                      # YAML (core, compliance, sectors, agents, penalties, webhooks)
│   └── ledger/decisions.jsonl         # Forensic audit log
├── ops/                               # Docker Compose + Dockerfiles
├── docs/                              # ADRs (26), PROJECT_CONTEXT.md
└── .github/workflows/ci.yml          # CI: Rust + Python + Ethical tests
```

## Technical Invariants

| Invariant | Rationale |
|---|---|
| TechnicalEvidence = 9596 bytes (fixed) | Zero heap allocation in hot path |
| BLAKE3 for all evidence hashing | Faster than SHA-256, collision-resistant |
| Ring buffer: [Finding; 10] + [Finding; 3] critical | Bounded memory, critical preserved |
| Any error/timeout → BLOCK | Fail-secure (Levinas: protect the user) |
| BiasDeclaration per validator | Transparency (Jonas: declare limitations) |
| explain_decision() on every verdict | Explainability (LGPD Art. 20) |
| HMAC-SHA256 on every EthicalVerdict | Non-repudiation |
| contestable: true on every verdict | 24h appeal SLA |
| SLM is fail-open | Never blocks pipeline on model failure |

## Philosophical Foundations

| Philosopher | Principle | Implementation |
|---|---|---|
| **Rawls** (1971) | Justice as fairness | Blind policy testing: evaluate without knowing identity |
| **Levinas** (1961) | Duty of care | Fail-secure: errors protect the user. Educate before punish. |
| **Gilligan** (1982) | Ethics of care | Mercy: uncertainty + trust + no critical → soften action |
| **Jonas** (1979) | Proportional responsibility | BiasDeclaration + immutable ledger + SLM data sovereignty |

## Local Development

### Rust
```bash
cd rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

### Python
```bash
cd python
pip install -e ".[dev]"
pytest tests/ -v
```

### SLM (optional)
```bash
pip install llama-cpp-python
# Place GGUF model in ops/models/
# Configure data/policies/core/slm.yaml
```

## Roadmap

| Version | Status | Scope |
|---|---|---|
| v1.5 — v1.9 | ✅ Complete | Kernel, Policy, Guard, Session, Mercy, Gateway, Observability |
| v2.0 Phase A | ✅ Complete | CI/CD, Streamlit 9 pages, Lifespan, Docs, SLM |
| v2.0 Phase B | ✅ Complete | Runtime Compliance Engine, Risk Classification, FRIA |
| OSS Q3/2027 | Planned | Apache 2.0 release, 100+ stars |
| LF Q4/2027 | Planned | LF AI & Data Sandbox submission |

## Known Limitations

- False positive rate ~15% (adversarial testing, 70 samples, not externally validated)
- Brazilian PII focus (CPF/CNPJ). International PII requires new modules.
- Compliance is runtime enforcement for EU AI Act and LGPD. Other frameworks (HIPAA, PCI-DSS) are self-assessment only.
- SLM latency on CPU-only (~500ms-5s depending on hardware)
- No TLS (plain HTTP)
- Ledger grows indefinitely (no rotation)
- No ML detection — validators are rule-based (SLM is supplementary)

## Contributing

We welcome contributions, especially:

- Validators for other jurisdictions (US SSN, UK NHS, EU VAT)
- Compliance framework mappings
- SLM model benchmarks
- Documentation improvements

## License

Apache 2.0 — see [LICENSE](LICENSE).

## ADRs

26 ADRs in `docs/adr/`, covering foundations, transparency, policy, governance, observability, intelligence, compliance, and gap implementations. See `docs/ARCHITECTURE_ATLAS.md` for the complete catalog.