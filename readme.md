# BuildToValue — Sovereign Trust OS

**Ethical governance infrastructure for AI agents. Rust kernel (facts) + Python governance (judgment).**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docs.docker.com/compose/)

---

## What This Is

BuildToValue is an ethical governance system that monitors AI agent behavior in real time. It detects policy violations (PII leakage, data misuse, obfuscated attacks) and responds with proportional actions — from education to blocking — while preserving the right to appeal.

The architecture follows a "República Algorítmica" (Algorithmic Republic) with separation of powers: a Legislative branch (Policy-as-Code), an Executive branch (Rust Kernel), a Judiciary branch (Python Governance), and an Auditory branch (Immutable Ledger).

**Current status:** v1.9 complete. República Algorítmica fully operational via Docker Compose. Rust Gateway (:8080) + Python Governance (:8000) + Prometheus + Grafana. Trust scores persist in SQLite across restarts.

---

## Why This Exists

AI agents processing sensitive data need guardrails that are fast, explainable, and fair. Existing approaches have tradeoffs:

- **Blocklists:** Fast but context-blind. A CPF number should be allowed for a medical agent but blocked for a chatbot.
- **ML classifiers:** Accurate but opaque. Cannot satisfy LGPD Art. 20 (right to explanation).
- **Rule engines:** Transparent but rigid. No concept of mercy, trust, or proportionality.

BuildToValue combines deterministic detection (Rust, < 30ms) with contextual ethical judgment (Python, < 10ms). Every decision is explainable, signed cryptographically, and contestable within 24 hours.

We draw on Rawls (fairness), Levinas (duty of care), Gilligan (contextual mercy), and Jonas (proportional responsibility) — not for novelty, but because these frameworks address exactly the problems automated governance creates.

---

## Architecture

### Monolito Modular (ADR-009)

Single process, logically separated modules. No microservices, no gRPC, no inter-process serialization in the hot path.
```
Request (user/agent)
  -> Ingestion (Unicode NFC, validation)                    < 1ms
  -> Rust Sovereign Kernel (scan_for_evidence)              < 30ms
    |-- Validators:   CPF, CNPJ, Email, Phone, CreditCard
    |-- Statistics:   Shannon Entropy, Z-Score, Char Ratios
    |-- Deobfuscator: Base64, Hex, Leetspeak
    |-- Policy:       Hard blocks (phf O(1) lookup)
    |-- Network:      IP classification (Tor/VPN/datacenter)
    |-- SessionGuard: Behavioral drift detection
    +-- Output: TechnicalEvidence (9596 bytes, fixed-size, BLAKE3)
  -> Python Governance (EthicalContextEngine)               < 10ms
    |-- Trust score lookup (SQLite persistent)
    |-- Mercy check (Gilligan)
    |-- HMAC-SHA256 signature
    +-- Output: EthicalVerdict (signed, contestable)
  -> Execution                                              < 5ms
    |-- Ledger append (JSONL)
    |-- Action: ALLOW | LOG | EDUCATE | REDACT | BLOCK
    +-- Response (with appeal window)

Total: < 50ms (p99) end-to-end
Observed (Docker): 6-15ms typical
```

### The Four Powers

| Power | Role | Implementation |
|-------|------|----------------|
| **Legislative** | Define rules | YAML policies in Git, blind testing (Rawls), Ethical Committee veto |
| **Executive** | Detect violations | Rust Kernel: deterministic validators, fixed-size evidence |
| **Judiciary** | Judge with context | Python Governance: mercy, trust scores, explain_decision() |
| **Auditory** | Record and verify | Immutable ledger: WAL, HMAC-SHA256, 24h appeal window |

---

## Quick Start (Docker)
```bash
cd ops
docker-compose up --build
```

This starts 4 services:

| Service | Port | Function |
|---------|------|----------|
| Gateway (Rust) | 8080 | Scan + Policy + Governance |
| Governance (Python) | 8000 | Mercy + Trust + HMAC |
| Prometheus | 9090 | Metrics scraper |
| Grafana | 3000 | Dashboard (admin/btv2026) |

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
# -> mercy_applied: true, REDACT -> LOG

# Prometheus metrics
curl -s http://localhost:8080/metrics
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/validate` | POST | Scan input + policy + governance verdict |
| `/v1/sanitize` | POST | Mask PII in LLM output (CPF, email, phone, credit card) |
| `/v1/policy/test` | POST | Test policy rules |
| `/v1/decide` | POST | Python governance judgment (internal) |
| `/v1/trust/{session_id}` | GET | Query trust score |
| `/health` | GET | Health check (both services) |
| `/metrics` | GET | Prometheus exposition format |

---

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
│   │   ├── security/                 # hmac, output_guard (PII mask), audit, session_guard
│   │   ├── ledger/                   # wal, chain, durable
│   │   ├── compliance/               # penalty calculator, AJL metrics
│   │   └── ffi/, batch.rs, observability/
│   ├── gateway/src/                   # Axum HTTP gateway
│   │   ├── main.rs, state.rs         # AppState + Prometheus metrics
│   │   └── routes/                   # validate, sanitize, health, metrics, policy_test
│   ├── bindings/                      # PyO3/Maturin bridge
│   └── cli/                           # btv command-line tool
│
├── python/buildtovalue/               # Python Hemisphere (judgment)
│   └── api/app.py                     # FastAPI v1.3 — Mercy + Trust (SQLite) + HMAC
│
├── ops/                               # Docker infrastructure
│   ├── docker-compose.yml             # gateway + governance + prometheus + grafana
│   ├── Dockerfile.rust, Dockerfile.python
│   └── prometheus.yml
│
├── data/
│   ├── policies/core/default.yaml     # Policy-as-Code
│   ├── ledger/decisions.jsonl         # Forensic audit log
│   └── trust.db                       # SQLite (Docker volume)
│
└── docs/                              # ADRs, PROJECT_CONTEXT.md
```

---

## Technical Invariants

These are non-negotiable. Violation blocks any merge.

| Invariant | Rationale |
|-----------|-----------|
| TechnicalEvidence = 9596 bytes (fixed) | Zero heap allocation in hot path |
| BLAKE3 for all evidence hashing | 2-3x faster than SHA-256, collision-resistant |
| Ring buffer: [Finding; 10] + [Finding; 3] critical | Bounded memory, critical findings preserved |
| Any error/timeout -> BLOCK | Fail-secure (Levinas: protect the user) |
| BiasDeclaration per validator | Transparency (Jonas: declare limitations) |
| explain_decision() on every verdict | Explainability (LGPD Art. 20 compliance) |
| HMAC-SHA256 on every EthicalVerdict | Non-repudiation (signatures, not trust) |
| contestable: true on every verdict | Contestability (24h appeal SLA) |

---

## Philosophical Foundations

We cite these philosophers to acknowledge intellectual debt, not to claim novelty.

| Philosopher | Principle | Implementation |
|-------------|-----------|----------------|
| **Rawls** (1971) | Justice as fairness | Blind policy testing: evaluate policies without knowing identity |
| **Levinas** (1961) | Duty of care | Fail-secure: errors protect the user. Educate before blocking |
| **Gilligan** (1982) | Ethics of care | Mercy algorithm: high uncertainty + trust + no critical findings -> soften response |
| **Jonas** (1984) | Proportional responsibility | BiasDeclaration: every module declares its FPR/FNR. Immutable ledger |

---

## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `btv_decisions_total{action}` | Counter | Decisions by action (ALLOW/LOG/EDUCATE/REDACT/BLOCK) |
| `btv_mercy_applied_total` | Counter | Mercy applications (Gilligan) |
| `btv_hard_blocks_total` | Counter | Hard blocks (injection, dangerous content) |
| `btv_latency_ms` | Histogram | Request latency p50/p95/p99 |
| `btv_findings_total{type}` | Counter | Findings by type (cpf, email, etc.) |
| `btv_sanitize_total` | Counter | Sanitize requests |
| `btv_sanitize_masked_total{type}` | Counter | PII masked by type |

---

## Technical Status (Honest)

### What Works (v1.9 Complete)

- 11 Rust validators (CPF, CNPJ, Email, Phone, CreditCard, Entropy, ZScore, CharRatio, Base64, Hex, Leetspeak)
- TechnicalEvidence v2.1: fixed-size 9596 bytes, BLAKE3 hashing, ring buffer
- PolicyEngine: YAML policies with hard blocks (O(1) lookup)
- OutputGuard v2.4: PII masking endpoint (CPF, CNPJ, email, phone, credit card)
- Deobfuscator: Base64 -> CPF detection (evasion prevention)
- MercyCalculator (Gilligan): trust > 0.6, first offense, critical == 0 -> soften action
- Trust score tracking with SQLite persistence (survives container restarts)
- HMAC-SHA256 signed verdicts with 24h contestability window
- explain_decision() on every verdict (LGPD Art. 20)
- Axum Gateway with Prometheus metrics (7 metric families)
- Docker Compose: Rust + Python + Prometheus + Grafana
- Forensic ledger (decisions.jsonl, append-only)
- Observed latency: 6-15ms (Docker), < 30ms p99

### What's Missing (v2.0 Target)

- **Intelligence Hub:** MISP/STIX threat feed integration not yet implemented.
- **Compliance Translator:** PDF regulations -> YAML policies via LLM not yet built.
- **Streamlit dashboard:** No web UI yet.
- **HMAC signatures symmetric:** Need PKI for public audit.
- **No ML detection:** Validators are rule-based only.
- **Brazilian PII focus:** CPF/CNPJ validators only. International PII requires new modules.

### Known Limitations

1. **False positive rate ~15%** from adversarial testing (70 samples). Not externally validated.
2. **Ring buffer drops older findings** when > 10 normal findings. Critical findings (max 3) always preserved.
3. **Leetspeak decoder covers common substitutions only.** Unicode homoglyphs not covered (FNR ~12%).
4. **Performance benchmarks from Docker dev environment.** Production latency may differ.

---

## Roadmap

### v1.5.0 ✅ Complete

- [x] TechnicalEvidence v2.1 refactor + BiasDeclaration mandate (ADR-010)
- [x] BatchProcessor (timeout 10ms, Protobuf serialization)
- [x] DurableLedger (WAL + recovery < 5s)
- [x] 60+ tests (ethical + technical)
- [x] Benchmarks: kernel < 30ms p99

### v1.6.0 ✅ Complete

- [x] PolicyEngine (YAML -> runtime, phf hard blocks)
- [x] OutputGuard v2.4 (PII masking in agent responses)
- [x] Deobfuscator v2 (chaining: base64 -> hex -> leet)

### v1.7.0 ✅ Complete

- [x] SessionGuard (trust tracking per session)
- [x] Offense tracking (first offense detection)
- [x] Network module (ip_classifier.rs)
- [x] Interceptor hooks

### v1.8.0 ✅ Complete

- [x] MercyCalculator (Gilligan: uncertainty + trust + critical)
- [x] soften_action (BLOCK->EDUCATE, REDACT->LOG, EDUCATE->LOG)
- [x] explain_decision() + HMAC-SHA256 on all verdicts
- [x] Contestability (24h appeal window)

### v1.9.0 ✅ Complete

- [x] Axum Gateway (POST /v1/validate, /v1/sanitize)
- [x] Prometheus metrics (7 metric families)
- [x] Docker Compose (Rust + Python + Prometheus + Grafana)
- [x] SQLite trust persistence (survives restarts)

### v2.0.0 <- Next Focus

- [ ] Intelligence Hub (MISP/STIX integration)
- [ ] Compliance Translator (PDF regulations -> YAML policies via LLM)
- [ ] CompliancePlugin architecture (LGPD, EU AI Act, NIST, ISO 42001)
- [ ] Streamlit MVP dashboard

### Open Source (Q3 2027)

- [ ] Apache 2.0 public release
- [ ] 100+ stars, 10+ contributors, 5+ case studies

### Linux Foundation (Q4 2027)

- [ ] LF AI & Data Sandbox submission
- [ ] 3+ co-submitting organizations

---

## Local Development (without Docker)

### Rust Gateway
```bash
cd rust
cargo build --release -p btv-gateway
cargo run -p btv-gateway
# Listening on 0.0.0.0:8080
```

### Python Governance
```bash
cd python
pip install fastapi uvicorn
python -m uvicorn python.buildtovalue.api.app:app --port 8000
```

### Rust Kernel Tests
```bash
cd rust
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

---

## Contributing

We welcome contributions, especially:

- **Validators for other jurisdictions** (US SSN, UK NHS, EU VAT, etc.)
- **External audits of BiasDeclaration** (validate our FPR/FNR claims)
- **Formal policy verification** (TLA+, Alloy, or similar)
- **Production deployment guides** (Kubernetes, observability)
- **Translations** of documentation and policy templates

**Code of Conduct:** Be respectful. Critique code, not people. Admit mistakes openly (we do).

**Testing requirement:** All PRs must include tests. Coverage must not decrease. Zero `.unwrap()` in library code.

---

## License

**Apache 2.0 (Open Core Model)**

- **Kernel (Rust):** Free and open (Apache 2.0)
- **Governance (Python):** Free and open (Apache 2.0)
- **Enterprise features (future):** Paid license (multi-tenant UI, managed cloud, SLA guarantees)

**Philosophy:** Security is not a paywall. Core governance logic remains free.

---

## Citations & Acknowledgments

**Philosophical foundations:**

- Rawls, J. (1971). *A Theory of Justice*. Harvard University Press.
- Levinas, E. (1961). *Totality and Infinity*. Duquesne University Press.
- Gilligan, C. (1982). *In a Different Voice*. Harvard University Press.
- Jonas, H. (1984). *The Imperative of Responsibility*. University of Chicago Press.

**Technical references (guidance, not certification):**

- NIST Cybersecurity Framework / NIST AI RMF
- OWASP ASVS 4.0
- ISO 42001 (AI management system)
- EU AI Act (Art. 13: Transparency)
- LGPD (Art. 20: Right to explanation)

**Team:**

- Daniel Camargo — Tech Lead, Architect
- Ethical Committee — Policy review
- Early testers — Adversarial validation

**We stand on the shoulders of giants.** Any errors are ours alone.

---

## Contact

- **Issues:** [GitHub Issues](https://github.com/buildtovalue/sovereign-trust-os/issues)
- **Security vulnerabilities:** security@buildtovalue.com (PGP key in repo)
- **General inquiries:** contact@buildtovalue.com

**Response time:** Best effort. This is a research project, not a commercial product (yet).

---

## Disclaimer

BuildToValue is experimental software provided "as is" without warranty of any kind. Do not use in production systems without thorough testing and security review.

**In particular:**

- False positives are inevitable (we measure ~15%, but your data may differ)
- Appeals require human review (24h SLA is aspirational, not guaranteed)
- Performance benchmarks are from Docker dev environment, not production
- BiasDeclaration values are self-reported estimates, not externally audited

**If you deploy this, you assume responsibility for outcomes.** We provide tools, not guarantees.

---

**Built with philosophy, implemented with care, acknowledged with humility.**

*Version 3.1 — February 2026*


# BuildToValue — Sovereign Trust OS

Ethical Trust OS for AI agents. Intercepts agent I/O, detects PII and policy
violations, applies algorithmic justice with radical transparency and
contestability by design.

**Not a firewall. Not a WAF. A Republic of Algorithms.**

## Architecture

Hybrid Rust+Python monolith (ADR-009):

- **Rust Kernel** — Technical facts: evidence forensics (9596B fixed-size),
  PII validators, statistics, deobfuscation, policy engine, immutable ledger.
  Zero heap on hot path. Target < 30ms p99.
- **Python Governance** — Ethical judgments: context engine, mercy calculator
  (Gilligan), trust scoring, compliance frameworks, intelligence hub.
  Target < 10ms p99.
- **Bridge** — PyO3/Maturin FFI. Protobuf for batch processing.

## Philosophical Foundations

| Philosopher | Principle | Implementation |
|---|---|---|
| Rawls | Veil of Ignorance | Blind Policy Testing — rules tested without knowing who they affect |
| Levinas | Face of the Other | Fail-Secure — errors protect the user, never bypass |
| Gilligan | Ethics of Care | Algorithmic Mercy — uncertainty + trust + no critical → soften |
| Jonas | Imperative of Responsibility | BiasDeclaration + Immutable Ledger + HMAC signatures |

## Current Status

**Version:** v1.5.0 in development (Feb-Apr 2026)

**What works:**
- Full validation pipeline (Rust scan → Python governance → signed verdict)
- 6 PII validators (CPF, CNPJ, email, phone, credit card, Brazilian PII)
- 3 statistics modules (entropy, z-score, char ratio)
- 3 deobfuscators (base64, hex, leetspeak)
- Mercy algorithm with trust scoring
- Appeals system (ContestabilityLoop + API endpoints)
- Compliance self-assessment (LGPD, EU AI Act, NIST, OWASP, ISO 42001)
- Intelligence Hub (MISP ingest, threat classification)
- Threat→Policy Bridge (auto-generate policy YAMLs from threats)
- Ledger Query API (audit trail search)
- Webhook notifications for critical decisions
- 26 Architecture Decision Records

**What doesn't work yet:**
- BiasDeclaration not enforced in all validators (ADR-010 in progress)
- No CI/CD pipeline
- No TLS
- HMAC key hardcoded
- Appeals in-memory only (no persistence)
- FPR ~15% (small adversarial sample, not externally validated)
- Brazilian PII only (CPF/CNPJ). International PII requires new modules.
- No ML/SLM — all detection is rule-based

**Deliberately not implemented yet:**
- Frontend (v2.0+)
- Axum gateway (v1.9+)
- ML/SLM features (v1.8+)
- NATS JetStream (v1.9+)

## ADRs

26 ADRs in `docs/adr/`, covering:
- Foundations (001-009): Hybrid arch, evidence protocol, mercy, ledger, policy-as-code, timing, monolith
- Transparency (010): BiasDeclaration mandate
- Policy & Output (011-013): PolicyEngine, OutputGuard, Deobfuscator v2
- Context (014-015): IP classification, session drift, interceptor hooks
- Governance (016-017): Ethical context engine, contestability loop
- API & Observability (018-019): Axum gateway, Prometheus
- Intelligence & Compliance (020-022): MISP hub, compliance translator, frontend
- Gap implementations (023-026): Appeals API, threat→policy bridge, ledger query, webhooks

## Installation

### Prerequisites

- Rust 1.75+ (stable)
- Python 3.10+
- (Optional) Docker for containerized development

### Rust Kernel
```bash
cd rust
cargo build --release
cargo test --workspace
cargo clippy --workspace -- -D warnings
cd kernel && cargo bench
```

### Python Governance
```bash
cd python
pip install -e ".[dev]"
pytest tests/ -v
mypy buildtovalue/ --strict
```

### FFI Bridge
```bash
cd rust/bindings
maturin develop --release
python -c "import buildtovalue_governance; print(buildtovalue_governance.version())"
```

### Full Build
```bash
make install   # Python deps + Rust FFI
make test      # Rust tests + Python tests
make build     # Rust release build
```

## API Endpoints

| Endpoint | Method | Port | Function |
|---|---|---|---|
| `/v1/validate` | POST | 8080 | Scan + Policy + Governance |
| `/v1/sanitize` | POST | 8080 | PII masking |
| `/v1/decide` | POST | 8000 | Ethical judgment |
| `/v1/appeals` | POST/GET | 8000 | Submit/list appeals |
| `/v1/appeals/{id}/resolve` | POST | 8000 | Resolve appeal (human) |
| `/v1/ledger/query` | GET | 8000 | Query audit ledger |
| `/v1/webhooks/status` | GET | 8000 | Webhook config + stats |
| `/v1/intelligence/bridge/sync` | POST | 8000 | Threat→Policy sync |
| `/v1/compliance/report/{fw}` | GET | 8000 | Compliance report |
| `/v1/trust/{session_id}` | GET | 8000 | Trust score |
| `/health` | GET | both | Health check |
| `/metrics` | GET | 8080 | Prometheus metrics |

## Development with AI Squad

Features are developed via structured multi-AI workflow:
```
Human (requirement) → Architect (ADR + traits) → Dev Rust/Python → Reviewer → Human (integrates)
```

Max 3 Dev↔Reviewer iterations. Compile before review. Update `PROJECT_CONTEXT.md` after each cycle.

Key docs:
- `docs/PROJECT_CONTEXT.md` — Full context for AI sessions
- `docs/HANDOFF_TEMPLATES.md` — Standardized handoff formats
- `docs/ARCHITECTURE_ATLAS.md` — Complete architectural map

## License

Open Core model planned:
- Kernel (Rust): Apache 2.0 (Q3 2027)
- Enterprise (UI, Multi-tenant): Paid

## Roadmap

v1.5 (current) → v1.6 (PolicyEngine) → v1.7 (Network+Session) → v1.8 (Ethical Engine v4) → v1.9 (Axum+Observability) → v2.0 (Intelligence+Compliance+UI) → OSS Q3/2027 → LF AI & Data Q4/2027