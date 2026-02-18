# BuildToValue — PROJECT_CONTEXT.md
# Versão: 3.1 | Atualizado: 17 fev 2026

## 1. O QUE É

Trust OS ético para agentes de IA. Intercepta I/O de agentes, detecta PII e
violações, aplica governança ética com transparência radical e contestabilidade.
Não é firewall. Não é WAF. É um sistema de justiça algorítmica.

Filosofia: Rawls (equidade via blind testing), Levinas (fail-secure protege o
usuário), Gilligan (misericórdia algorítmica), Jonas (responsabilidade via
BiasDeclaration + ledger imutável).

## 2. ARQUITETURA

Monolito Modular (ADR-009). Dois hemisférios:

- **Rust Kernel** (`rust/kernel/`): Fatos técnicos. Evidence Protocol, validators,
  statistics, deobfuscator, policy engine, ledger. Zero heap no hot path. < 30ms p99.
- **Python Governance** (`python/buildtovalue/`): Julgamentos éticos. Context engine,
  mercy calculator, trust score, compliance, intelligence hub. < 10ms p99.
- **Ponte**: PyO3/Maturin (`rust/bindings/`). Protobuf para batch.
```
buildtovalue/
├── rust/
│   ├── kernel/src/         # Crate principal (módulos internos)
│   ├── bindings/           # PyO3/Maturin
│   ├── gateway/            # Axum (v1.9+ APENAS — não implementar agora)
│   └── cli/
├── python/buildtovalue/
│   ├── governance/         # context_engine, mercy, trust, contestability
│   ├── compliance/         # translator, frameworks, roi
│   ├── intelligence/       # misp, threat_classifier, policy_generator, bridge
│   ├── api/                # FastAPI app, routes/, schemas, auth, webhook, ledger
│   ├── core/               # config, exceptions
│   └── observability/      # logger, metrics
├── data/policies/          # YAML versionado (agents/, compliance/, sectors/, auto-generated/)
├── docs/adr/               # 26 ADRs (001-026)
└── docs/                   # PROJECT_CONTEXT.md, HANDOFF_TEMPLATES.md, ARCHITECTURE_ATLAS.md
```

## 3. ADRs (26 total)

| Grupo | IDs | Status |
|---|---|---|
| A: Fundamentos | 001-009 | ✅ 8 ativos, 002 obsoleto |
| B: Evidence+Transparency | 010 | 🚧 Em implementação (v1.5) |
| C: Policy+Output | 011-013 | 🔒 Planejado (v1.6) |
| D: Context | 014-015 | 🔒 Planejado (v1.7) |
| E: Governance | 016-017 | 016 🔒, 017 ✅ |
| F: API+Obs | 018-019 | 🔒 Planejado (v1.9) |
| G: Intel+Compliance | 020-022 | 🔒 Planejado (v2.0) |
| H: Gaps implementados | 023-026 | ✅ Ativos (Appeals, Bridge, Ledger Query, Webhooks) |

**Débito**: numeração de arquivos 0024-0026 diverge do ID interno (off-by-one).

## 4. FOCO ATUAL: v1.5.0 (18 fev — 12 abr 2026)

- TechnicalEvidence v2.1 refactor + BiasDeclaration mandate (ADR-010)
- BatchProcessor (timeout 10ms, Protobuf)
- DurableLedger (WAL + recovery < 5s)
- 60+ testes (ethical + technical)
- Benchmarks kernel < 30ms p99

## 5. GAPS RESOLVIDOS (Chats Parte 1-3 + Gap #8)

| # | Gap | Status |
|---|---|---|
| 1 | Appeals endpoint | ✅ ContestabilityLoop exposto via API |
| 2 | Compliance YAML mappings | ✅ 7 frameworks em `data/policies/compliance/` |
| 3 | Sector patterns → YAML | ✅ `data/policies/sectors/` |
| 4 | Profiles no `/v1/validate` | ✅ ProfileManager + SectorLoader |
| 5 | Penalty schedules | ✅ `data/policies/penalties.yaml` |
| 6 | Rate limiting | ⚠️ Parcial (auth API key, sem throttle formal) |
| 7 | Webhooks | ✅ WebhookDispatcher (ADR-026) |
| 8 | Threat→Policy Bridge | ✅ ThreatPolicyBridge (ADR-024) |
| 9 | Ledger Query | ✅ LedgerReader + API (ADR-025) |
| 10 | Key management | ❌ HMAC key hardcoded — pendente |

## 6. LIMITAÇÕES CONHECIDAS (Honestidade)

- FPR ~15% (adversarial, 70 amostras — não validado externamente)
- FNR leetspeak ~12% (homoglyphs Unicode não cobertos)
- Appeals em memória (produção precisa persistência)
- HMAC simétrico (PKI necessário para auditoria pública)
- Sem ML/SLM — validators são rule-based
- Foco em PII brasileira (CPF/CNPJ). PII internacional requer novos módulos
- Sem CI/CD automatizado
- Sem TLS
- 5 testes legados excluídos (pending cleanup)

## 7. INVARIANTES (Violação = REJECT)

- TechnicalEvidence: 9596 bytes fixos (`size_of` assert)
- Hot path: ZERO heap allocations
- Hash: BLAKE3 (nunca DefaultHasher ou SHA-256 para evidence)
- Ring buffer: [Finding; 10] + [Finding; 3] critical preserved
- Fail-secure: erro/timeout → BLOCK (nunca bypass)
- `explain_decision()` obrigatório em decisões éticas
- HMAC-SHA256 em todo EthicalVerdict
- `contestable: true` + `appeal_deadline: 24h` em todo verdict
- Funções ≤ 50 linhas, arquivos ≤ 200 linhas

## 8. ANTI-PADRÕES PROIBIDOS

`.unwrap()` em lib, `.clone()` sem justificativa, `any` em Python,
`DefaultHasher`, heap no hot path, lógica em `bindings/`, microserviços,
gRPC, Node.js.

## 9. ROADMAP

| Versão | Escopo | Prazo |
|---|---|---|
| **v1.5.0** | Evidence refactor, BiasDeclaration, Batch, Ledger WAL | Fev-Abr 2026 |
| v1.6.0 | PolicyEngine, OutputGuard, Deobfuscator v2 | |
| v1.7.0 | Network, SessionGuard, Interceptor | |
| v1.8.0 | EthicalContextEngine v4, Misericórdia, ContestabilityLoop v2 | |
| v1.9.0 | Axum Gateway, Observability | |
| v2.0.0 | Intelligence Hub, Compliance Translator, Streamlit MVP | |
| OSS Q3/2027 | Apache 2.0, 100+ stars | |
| LF Q4/2027 | LF AI & Data Sandbox | |

## 10. AI SQUAD WORKFLOW

Humano → Arquiteta (ADR+traits) → Dev Rust/Python → Reviewer → Humano integra.
Max 3 iterações Dev↔Reviewer. Compilar antes de review. Atualizar este documento após cada ciclo.
Handoff templates em `docs/HANDOFF_TEMPLATES.md`.