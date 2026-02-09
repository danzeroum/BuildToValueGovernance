# BuildToValue — Sovereign Trust OS

**Ethical governance infrastructure for AI agents. Rust kernel (facts) + Python governance (judgment).**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)

---

## What This Is

BuildToValue is an ethical governance system that monitors AI agent behavior in real time. It detects policy violations (PII leakage, data misuse, obfuscated attacks) and responds with proportional actions — from education to blocking — while preserving the right to appeal.

The architecture follows a "República Algorítmica" (Algorithmic Republic) with separation of powers: a Legislative branch (Policy-as-Code), an Executive branch (Rust Kernel), a Judiciary branch (Python Governance), and an Auditory branch (Immutable Ledger).

**Current status:** Active development. Kernel v2.3.1 functional. Governance layer documented but undergoing v1.5 refactor. Not production-ready.

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
  → Ingestion (Unicode NFC, validation)                    < 1ms
  → FFI Bridge (Protobuf batch, py.allow_threads)          < 2ms
  → Rust Sovereign Kernel (scan_for_evidence)              < 30ms
    ├─ Validators:   CPF, CNPJ, Email, Phone, CreditCard
    ├─ Statistics:   Shannon Entropy, Z-Score, Char Ratios
    ├─ Deobfuscator: Base64, Hex, Leetspeak
    ├─ Policy:       Hard blocks (phf O(1) lookup)
    ├─ Network:      IP classification (Tor/VPN/datacenter)
    ├─ SessionGuard: Behavioral drift detection
    └─ Output: TechnicalEvidence (9596 bytes, fixed-size, BLAKE3)
  → Python Governance (EthicalContextEngine)               < 10ms
    ├─ Profile resolution (YAML hierarchy)
    ├─ Trust score lookup
    ├─ Ethical analysis (Rawls + Levinas + Jonas)
    ├─ Mercy check (Gilligan)
    └─ Output: EthicalVerdict (HMAC-SHA256 signed)
  → Execution                                              < 5ms
    ├─ Ledger append (WAL + remote sync)
    ├─ Action: ALLOW | LOG | EDUCATE | REDACT | BLOCK
    └─ Response (with appeal URL)

Total: < 50ms (p99) end-to-end
```

### The Four Powers

| Power | Role | Implementation |
|-------|------|----------------|
| **Legislative** | Define rules | YAML policies in Git, blind testing (Rawls), Ethical Committee veto |
| **Executive** | Detect violations | Rust Kernel: deterministic validators, fixed-size evidence |
| **Judiciary** | Judge with context | Python Governance: mercy, trust scores, explain_decision() |
| **Auditory** | Record and verify | Immutable ledger: WAL, HMAC-SHA256, 24h appeal window |

---

## Project Structure
```
buildtovalue/
├── rust/                              # Rust Hemisphere (facts)
│   ├── kernel/                        # buildtovalue-kernel (main crate)
│   │   └── src/
│   │       ├── lib.rs                 # Re-exports + version
│   │       ├── core/                  # types.rs, errors.rs
│   │       ├── evidence/              # TechnicalEvidence v2.1 (9596 bytes)
│   │       ├── gatekeeper.rs          # Orchestrator (scan_for_evidence)
│   │       ├── validators/            # PII detection (CPF, CNPJ, email, phone, credit card)
│   │       ├── statistics/            # Anomaly detection (entropy, zscore, char ratio)
│   │       ├── deobfuscator/          # Anti-evasion (base64, hex, leetspeak)
│   │       ├── policy/               # Hard block rules (v1.6+)
│   │       ├── network/              # IP classification (v1.7+)
│   │       ├── session_guard/        # Drift detection (v1.7+)
│   │       ├── output_guard/         # Response sanitization (v1.6+)
│   │       ├── interceptor/          # Pre/post hooks (v1.7+)
│   │       ├── ledger/               # WAL, chain-of-hashes, durable sync
│   │       ├── compliance/           # Penalty calculator, AJL metrics
│   │       ├── security/             # HMAC-SHA256, constant-time comparison
│   │       ├── api/                  # Response types
│   │       └── ffi/                  # Batch processor (conditional)
│   ├── bindings/                      # PyO3/Maturin bridge
│   ├── gateway/                       # Axum HTTP (v1.9+ only)
│   └── cli/                           # btv command-line tool
│
├── python/buildtovalue/               # Python Hemisphere (judgment)
│   ├── governance/                    # EthicalContextEngine, mercy, trust, profiles
│   ├── compliance/                    # PDF→YAML translator, AJL, ROI engine
│   ├── intelligence/                  # MISP/STIX ingestor, threat classifier
│   ├── api/                           # FastAPI routes (validate, appeals, health)
│   ├── core/                          # Config, exceptions, shared types
│   ├── observability/                 # Logging, metrics, tracing
│   └── cli/                           # CLI commands
│
├── data/policies/                     # YAML policies (core, compliance, profiles)
├── spec/                              # Protobuf + OpenAPI contracts
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
| Any error/timeout → BLOCK | Fail-secure (Levinas: protect the user) |
| BiasDeclaration per validator | Transparency (Jonas: declare limitations) |
| explain_decision() on every verdict | Explainability (LGPD Art. 20 compliance) |
| HMAC-SHA256 on every EthicalVerdict | Non-repudiation (signatures, not trust) |
| contestable: true on every verdict | Contestability (24h appeal SLA) |

---

## Philosophical Foundations

We cite these philosophers to acknowledge intellectual debt, not to claim novelty.

| Philosopher | Principle | Implementation |
|-------------|-----------|----------------|
| **Rawls** (1971) | Justice as fairness | Blind policy testing: evaluate policies without knowing if you're author, target, or auditor |
| **Levinas** (1961) | Duty of care | Fail-secure: errors protect the user. Educate (L2) before blocking (L4) |
| **Gilligan** (1982) | Ethics of care | Mercy algorithm: high uncertainty + trust + no critical findings → soften response |
| **Jonas** (1984) | Proportional responsibility | BiasDeclaration: every module declares its false positive/negative rates. Immutable ledger |

---

## Technical Status (Honest)

### What Works

- 11 Rust validators (CPF, CNPJ, Email, Phone, CreditCard, Entropy, ZScore, CharRatio, Base64, Hex, Leetspeak) with < 30ms kernel latency
- TechnicalEvidence v2.1: fixed-size 9596 bytes, BLAKE3 hashing, ring buffer, tamper detection
- Gatekeeper orchestrator: multi-stage pipeline (validators → statistics → deobfuscator → finalize)
- PyO3/Maturin FFI bridge: Rust↔Python in-process (no network serialization)
- CLI tool (`btv`): basic scan and validation commands
- 60+ tests passing (Rust unit + Python unit)

### What's Missing

- **BiasDeclaration not yet populated:** Struct exists in TechnicalEvidence but validators return defaults. ADR-010 addresses this (v1.5.0 target).
- **Python Governance not yet integrated:** EthicalContextEngine documented but awaiting v1.8.0 implementation cycle.
- **No observability:** Prometheus/Grafana planned for v1.9.0.
- **No REST API serving:** FastAPI routes documented, not deployed. Axum gateway in v1.9.0.
- **Appeals in-memory:** Production needs persistent storage.
- **HMAC signatures symmetric:** Need PKI for public audit (HMAC requires shared secret).
- **No ML detection:** Validators are rule-based. Obfuscated patterns may evade detection.
- **Brazilian PII focus:** CPF/CNPJ validators only. International PII requires new modules.

### Known Limitations

1. **False positive rate ~15%** from adversarial testing (70 samples). Not externally validated.
2. **Ring buffer drops older findings** when > 10 normal findings. Critical findings (max 3) are always preserved.
3. **Leetspeak decoder covers common substitutions only.** Regional variants and Unicode homoglyphs not covered (FNR ~12%).
4. **Performance benchmarks from dev environment.** Production latency depends on workload and I/O.

---

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

# Benchmarks
cd kernel && cargo bench
```

### Python Governance
```bash
cd python
pip install -e ".[dev]"
pytest tests/ -v

# Type checking
mypy buildtovalue/ --strict
```

### FFI Bridge (Rust → Python)
```bash
cd rust/bindings
maturin develop --release

# Verify
python -c "import buildtovalue_governance; print(buildtovalue_governance.version())"
```

### Full Build
```bash
make install   # Python deps + Rust FFI
make test      # Rust tests + Python tests
make build     # Rust release build
```

---

## Development with AI Squad

This project uses a structured multi-AI workflow for development. Each feature follows:
```
Human (defines requirement)
  → AI Architect (generates ADR + Rust traits + contracts)
  → AI Dev Rust/Python (implements exactly as specified)
  → AI Reviewer (validates against ADR + checklists)
  → Human (integrates, compiles, updates PROJECT_CONTEXT.md)
```

Key artifacts:

- `docs/PROJECT_CONTEXT.md` — Full context pasted into every AI chat session
- `docs/HANDOFF_TEMPLATES.md` — Standardized handoff formats between AI roles
- `docs/adrs/` — Architecture Decision Records with philosophical rationale

Rules: max 3 Dev↔Reviewer iterations per feature. Compile locally before review. Update PROJECT_CONTEXT.md after every review cycle.

See the [AI Squad Workflow documentation](docs/PROJECT_CONTEXT.md) for system prompts and templates.

---

## Roadmap

### v1.5.0 ← Current Focus (Feb 18 – Apr 12, 2026)

- [ ] TechnicalEvidence v2.1 refactor + BiasDeclaration mandate (ADR-010)
- [ ] BatchProcessor (timeout 10ms, Protobuf serialization)
- [ ] DurableLedger (WAL + recovery < 5s)
- [ ] 60+ tests (ethical + technical)
- [ ] Benchmarks: kernel < 30ms p99

### v1.6.0 — Policy & Output

- [ ] PolicyEngine (YAML → runtime, phf hard blocks)
- [ ] OutputGuard (PII masking in agent responses)
- [ ] Deobfuscator v2 (chaining: base64 → hex → leet, max 3 layers)

### v1.7.0 — Context

- [ ] IpClassifier (Tor, VPN, datacenter detection)
- [ ] SessionDriftDetector (behavioral cosine similarity)
- [ ] Interceptor (pre/post request hooks)
- [ ] Contextual tests: same input, different profiles → different actions

### v1.8.0 — Governance

- [ ] EthicalContextEngine (Rawls + Levinas + Jonas + Gilligan)
- [ ] MercyCalculator (6 calibrated scenarios)
- [ ] ContestabilityLoop (submit, status, resolve appeals)
- [ ] explain_decision() + HMAC-SHA256 on all verdicts

### v1.9.0 — API & Observability

- [ ] Axum Gateway (replaces FastAPI for HTTP serving)
- [ ] Prometheus metrics + distributed tracing
- [ ] PolicyTester API (blind review)

### v2.0.0 — Intelligence & Compliance

- [ ] Intelligence Hub (MISP/STIX integration)
- [ ] Compliance Translator (PDF regulations → YAML policies via LLM)
- [ ] Streamlit MVP dashboard

### Open Source (Q3 2027)

- [ ] Apache 2.0 public release
- [ ] 100+ stars, 10+ contributors, 5+ case studies

### Linux Foundation (Q4 2027)

- [ ] LF AI & Data Sandbox submission
- [ ] 3+ co-submitting organizations

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
- Performance benchmarks are from development environment, not production
- BiasDeclaration values are self-reported estimates, not externally audited

**If you deploy this, you assume responsibility for outcomes.** We provide tools, not guarantees.

---

**Built with philosophy, implemented with care, acknowledged with humility.**

*Version 3.0 — February 2026*