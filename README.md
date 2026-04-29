# BuildToValue — Sovereign Trust OS

Ethical trust infrastructure for AI agents. Hybrid Rust + Python architecture implementing the **Algorithmic Republic** — separation of powers between technical fact-finding (Rust) and ethical judgment (Python).

## Architecture
```
┌─────────────────────────────────────────────────────────┐
│                    Axum Gateway v2.0                     │
│  /v1/validate  /v1/decide  /v1/appeals  /health/bias    │
├─────────────┬───────────────────────────┬───────────────┤
│  EXECUTIVE  │        JUDICIARY          │   AUDITORY    │
│  Rust Kernel│   Python Governance       │   Ledger +    │
│  <30ms p99  │   <10ms p99              │   Prometheus  │
│             │                           │               │
│ 15 modules: │ Pipeline v4.0:           │ WAL + BLAKE3  │
│ Deobfuscate │  Rawls → Levinas →       │ HMAC-SHA256   │
│ Analyze     │  Jonas → Gilligan        │ 21+ metrics   │
│ Validate    │                           │ SLA 24h       │
│ +Language   │ BiasGuardian (ADR-036)   │               │
│ +Security   │ AppealEngine (ADR-037)   │               │
│             │ TrustScore v2 (ADR-039)  │               │
│             │ AbliterationDet (ADR-051)│               │
│             │ ManifestHashVer (ADR-042)│               │
│             │ IntegrityVerif. (ADR-049)│               │
├─────────────┴───────────────────────────┴───────────────┤
│                    LEGISLATIVE                           │
│            Policy-as-Code (YAML + Git)                  │
│         PatternRegistry (Tier 0/1/2 + Epoch)            │
│      model_integrity.yaml (ADR-042, ADR-049, ADR-051)   │
└─────────────────────────────────────────────────────────┘
```

## Key Properties

| Property | Implementation |
|---|---|
| TechnicalEvidence | 9632 bytes fixed, BLAKE3 hash, compile-time verified |
| ScanContextFlags | 64 bytes: lang, jurisdiction, capability, tenant, epoch |
| Zero-heap hot path | Stack-only in evidence/gatekeeper |
| Fail-secure | Any error → BLOCK, never bypass |
| BiasDeclaration | Mandatory on every Module, calibration < 90 days |
| HMAC-SHA256 | Every EthicalVerdict signed |
| Contestability | `contestable: true` + 24h appeal SLA on every verdict |
| SLM | Supplementary, fail-open (never blocks pipeline) |
| PolicyEngine typed accessors | `ModelIntegrityConfig` + `AbliterationConfig` frozen dataclasses; `rglob` YAML discovery |
| ManifestHashVerifier | SHA-256 Python fast-path before Rust BLAKE3 weights check; `block_on_failure` respected |
| probe_timeout_ms | `threading.Thread + queue.Queue` per probe; cross-platform (no `signal.alarm`) |

## Pipeline

**Rust Kernel — 15 modules across 4 stages:**

| Stage | Modules |
|---|---|
| Deobfuscate | Base64, Hex, Leetspeak |
| Analyze | Entropy, ZScore, CharRatio, LanguageDetector (whatlang) |
| Validate | CPF, CNPJ, Email, CreditCard, Phone, PromptInjection, SSN |
| Available | NHS (UK), EU VAT, IBAN (ADR-035, jurisdiction-gated in pipeline v2.2) |

**Python Governance — Philosophical Pipeline (ADR-038):**

| Stage | Philosopher | Role |
|---|---|---|
| Rawls | John Rawls (1971) | Blind testing, anomaly detection |
| Levinas | Emmanuel Levinas (1961) | Duty of care, appeal hints |
| Jonas | Hans Jonas (1979) | Proportional responsibility, bias expiry check |
| Gilligan | Carol Gilligan (1982) | Mercy (6 calibrated scenarios S1–S6) |

**Python Model Integrity — ADR-042 / ADR-049 / ADR-051 (v2.2):**

| Component | Version | Role |
|---|---|---|
| `PolicyEngine` | v1.1.0 | Typed accessors: `ModelIntegrityConfig`, `AbliterationConfig`, `manifest_path_for()` |
| `AbliterationDetector` | v1.2.0 | 8 calibrated probes (5 HARMFUL + 3 BENIGN); `probe_timeout_ms` via `threading+queue` |
| `ManifestHashVerifier` | v1.0.0 | SHA-256 manifest JSON fast-path; 6 audited paths; `block_on_failure` respected |
| `IntegrityVerifier` | v1.2.0 | Orchestrates: manifest hash → blacklist → whitelist → behavioral (Python→Rust chain) |

Verification chain:
```
IntegrityVerifier.verify(model_id)
  ↓ Python: ManifestHashVerifier   ← SHA-256 manifest JSON          (<1ms)
  ↓ Python: blacklist check         ← is_known_abliterated()         (<1ms)
  ↓ Python: whitelist fast-path     ← get_model_info()               (<1ms)
  ↓ Rust kernel: BLAKE3 weights    ← full weights hash (ADR-005)    (planned)
```

## Philosophical Foundations

| Philosopher | Principle | Implementation |
|---|---|---|
| **Rawls** | Justice as fairness | Blind policy testing, PatternRegistry epoch tracking |
| **Levinas** | Duty of care | Fail-secure, educate before punish, appeal_hint |
| **Gilligan** | Ethics of care | Mercy: trust + first_offense + low_risk → soften |
| **Jonas** | Proportional responsibility | BiasDeclaration, BiasGuardian divergence enforcement, immutable ledger, manifest hash chain |

## Local Development

### Rust
```bash
cd rust
cargo build --workspace
cargo test --workspace      # 357+ tests
cargo clippy --workspace -- -D warnings
cargo bench --bench kernel_benchmark  # Criterion
```

### Python
```bash
cd python
pip install -e ".[dev]"
pytest tests/ -v            # 39+ governance tests (ADR-042/049/051)
```

### Docker (full stack)
```bash
cd ops
docker compose up
# Gateway: http://localhost:3000
# Governance: http://localhost:8000
# Streamlit: http://localhost:8501
```

### E2E Tests
```bash
cd ops && bash e2e-tests.sh
# 27 tests: 21 pass, 4 fail (known), 2 skip
```

### ARIA Arena Demo (Track 2)
Iterative, step-by-step walkthrough of the Scaling Trust Arena scenarios —
the same five tests in `python/tests/agentic/test_arena_simulation.py`,
replayed one NegotiationMessage / guard verdict / drift check at a time.

```bash
make arena-demo            # Streamlit on http://localhost:8501
make arena-demo-cli        # Terminal walkthrough (all 5 scenarios)
```

Single scenario, machine-readable export:
```bash
cd python && python -m buildtovalue.cli.main arena-demo \
    --scenario red_team --auto --json /tmp/arena.json
```

Scenarios: `cooperative`, `red_team`, `drift`, `generalisation`, `leaderboard`.
See ADR-0058 for the (Utility; Security; Cost Efficiency) scoring rubric.

## ADRs

52+ ADRs referenced (42 formal in `docs/adr/` + ADR-042, 049, 051 implemented in v2.2):

| Group | IDs | Scope |
|---|---|---|
| Foundations | 001–009 | Hybrid arch, Evidence, Mercy, Ledger, Policy, Monolith |
| Governance | 010, 016 | BiasDeclaration mandate, EthicalContextEngine |
| Security | 011–015 | PolicyEngine, OutputGuard, Deobfuscator, Network, Interceptor |
| API & Obs | 017–019 | ContestabilityLoop, Axum Gateway, Observability |
| Intelligence | 020–022 | Intelligence Hub, Compliance Plugins, Streamlit |
| Gap Impl | 023–026 | Appeals HTTP, Threat→Policy, Ledger Query, Webhooks |
| Prompt Injection | 028 | Heuristic detector (3-layer: regex+structural+cross-signal) |
| Integrations | 029–031 | External Agent PDP, Internal LLM, External LLM |
| Multi-lang | 032–035 | ScanContextFlags, PatternRegistry, Language Detection, Multi-jurisdiction PII |
| Red-team & Gov | 036–039 | BiasGuardian, AppealEngine v2, ECE v4, TrustScore v2 |
| Gateway & Obs v2 | 040–041 | Gateway extensions, República metrics |
| **Model Integrity** | **042, 049, 051** | **PolicyEngine typed accessors, AbliterationDetector v1.2.0, ManifestHashVerifier v1.0.0 ✅ v2.2** |

See `docs/adr/0000-adr-index.md` for full catalog with dependency map.

## Roadmap

| Version | Status | Scope |
|---|---|---|
| v1.5 – v1.9 | ✅ Complete | Kernel, Policy, Guard, Session, Mercy, Gateway, Observability |
| v2.0 Phase A | ✅ Complete | CI/CD, Streamlit, Lifespan, SLM, Docs |
| v2.0 Phase B | ✅ Complete | Runtime Compliance, Risk Classification, FRIA |
| v2.1 | ✅ Complete | ADRs 032–041: ScanContextFlags, PatternRegistry, Language, Multi-PII, BiasGuardian, AppealEngine v2, ECE v4, TrustScore v2, Gateway v2, Observability v2 |
| v2.2 | ✅ Complete | ADR-042/049/051: PolicyEngine typed accessors, AbliterationDetector v1.2.0 (probe timeout), ManifestHashVerifier v1.0.0 (SHA-256 fast-path), IntegrityVerifier v1.2.0; 39 Python governance tests |
| v2.3 | 🚧 Current | Rust BLAKE3 weights verification (ADR-005 integration), pipeline wiring ADR-035, debt cleanup |
| OSS Q3/2027 | Planned | Apache 2.0, 100+ stars, 10+ contributors |
| LF Q4/2027 | Planned | LF AI & Data Sandbox submission |

## Known Limitations

- FPR ~15% adversarial (70 samples, not externally validated)
- FNR leetspeak ~12% (Unicode homoglyphs not covered)
- SSN bare (9 digits no separator) FPR ~25%
- PromptInjection is heuristic (regex + structural), not ML
- NHS/VAT/IBAN validators are jurisdiction-gated (require JURISDICTION_UK or JURISDICTION_EU bitmask in scan context)
- Ledger grows indefinitely (no rotation)
- No TLS (plain HTTP)
- SLM latency on CPU-only (~500ms-5s)
- Two EthicalContextEngine versions coexist (debt: decomposition planned)
- `ManifestHashVerifier` requires `BTV_<MODEL>_MANIFEST_HASH` env var in production; unset → BLOCK (fail-secure)
- `AbliterationDetector` probe_timeout_ms=5000 × 8 probes = 40s max sequential; reduce timeout for production LLMs
- Rust BLAKE3 weights check (ADR-005 full integration) pending v2.3

## Contributing

We welcome contributions:

- Multi-jurisdiction validators (integration + red-team scripts)
- Compliance framework mappings
- SLM model benchmarks
- Pattern contributions for PatternRegistry (new languages)
- Documentation improvements

## License

Apache 2.0 — see [LICENSE](LICENSE).
