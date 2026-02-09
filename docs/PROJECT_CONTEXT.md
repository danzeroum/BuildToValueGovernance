# Project Context Document — BuildToValue v3.0
**Projeto**: BuildToValue — Sovereign Trust OS for AI Agents
**Versão do Contexto**: 3.0.1 (atualizado 2026-02-09)
**Stack**: Rust (kernel fático) + Python (governance ética) via PyO3/Maturin
**Licença**: Apache 2.0 (Open Core)
**Arquitetura**: Monolito Modular (ADR-009)

## Visão Geral (5 frases)
BuildToValue é um Trust Operating System que governa agentes de IA em tempo real.
A arquitetura segue a metáfora de "República Algorítmica" com separação de poderes:
Legislativo (Policy-as-Code YAML), Executivo (Rust Kernel < 30ms), Judiciário 
(Python Governance < 10ms), Auditivo (Ledger imutável). O Kernel Rust produz um 
dossiê forense determinístico (TechnicalEvidence, 9596 bytes fixos); o Python 
interpreta esse dossiê com contexto ético (Rawls, Levinas, Gilligan, Jonas) e 
emite um EthicalVerdict assinado criptograficamente. Toda decisão é explicável 
(explain_decision obrigatório), contestável (appeal em 24h), e auditável 
(ledger com HMAC-SHA256).

## Filosofia Core (OBRIGATÓRIO entender antes de codificar)
- RAWLS: Blind Policy Testing — testa políticas sem saber se é autor/alvo/auditor
- LEVINAS: Educar antes de Punir — EDUCATE (L1) antes de BLOCK (L4)
- GILLIGAN: Misericórdia Algorítmica — alta incerteza + contexto → abrandamento
- JONAS: Responsabilidade Proporcional — cada decisão assinada, BiasDeclaration obrigatório
- FAIL-SECURE: Qualquer erro → BLOCK (nunca bypass, nunca ALLOW silencioso)

## Arquitetura Vigente (Monolito Modular v3.0)
- Padrão: Monolito Modular com Cargo Workspace
- Rust: Kernel soberano (fatos técnicos, determinístico, zero heap no hot path)
- Python: Governance Layer (julgamentos éticos, contextuais, explicáveis)
- Comunicação Rust↔Python: PyO3/Maturin (in-process, não gRPC)
- Web: FastAPI (v1.5-v1.8) → Axum (v1.9+) → Angular serving (v2.0+)
- Mensageria: NATS JetStream (auditoria assíncrona, v1.9+)

## Performance SLOs (INEGOCIÁVEIS)
| Componente          | Latência Target | Medição              |
|---------------------|-----------------|----------------------|
| End-to-end          | < 50ms (p99)    | Request → Response   |
| Rust Kernel         | < 30ms (p99)    | scan_for_evidence()  |
| Python Governance   | < 10ms (p99)    | decide()             |
| FFI Bridge          | < 2ms (p99)     | Protobuf serialize   |
| Ingestion           | < 1ms           | NFC + validation     |
| Ledger append       | < 5ms           | WAL + flush          |

## Estrutura de Pastas (IMUTÁVEL — NÃO criar novas pastas)
```
buildtovalue/                          # Raiz Git
├── rust/                              # HEMISFÉRIO RUST
│   ├── kernel/                        # buildtovalue-kernel (crate principal)
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs                 # Re-exports + version
│   │   │   ├── core/                  # types.rs, errors.rs
│   │   │   ├── evidence/              # technical.rs (9596B), finding.rs
│   │   │   ├── gatekeeper.rs          # Orquestrador (scan_for_evidence)
│   │   │   ├── validators/            # brazilian/{cpf,cnpj}, communication/{email,phone}, financial/credit_card
│   │   │   ├── statistics/            # entropy, zscore, char_ratio
│   │   │   ├── deobfuscator/          # base64, hex, leetspeak
│   │   │   ├── policy/               # engine.rs (YAML → runtime)
│   │   │   ├── network/              # ip_classifier.rs (v1.7+)
│   │   │   ├── session_guard/        # drift.rs (v1.7+)
│   │   │   ├── output_guard/         # sanitizer.rs (v1.6+)
│   │   │   ├── interceptor/          # hooks.rs (v1.7+)
│   │   │   ├── ledger/               # wal.rs, chain.rs, durable.rs
│   │   │   ├── compliance/           # penalty.rs (phf), ajl.rs
│   │   │   ├── security/             # hmac.rs, constant_time.rs
│   │   │   ├── observability/        # metrics.rs (v1.9+)
│   │   │   ├── api/                  # response.rs
│   │   │   └── ffi/                  # batch.rs, bridge.rs (conditional)
│   │   ├── tests/
│   │   └── benches/
│   │
│   ├── bindings/                      # buildtovalue-bindings (PyO3 cdylib)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                 # #[pymodule] entry
│   │       ├── ffi_evidence.rs
│   │       ├── ffi_compliance.rs
│   │       └── ffi_batch.rs
│   │
│   ├── gateway/                       # btv-gateway (Axum, v1.9+)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── routes/
│   │       └── middleware/
│   │
│   └── cli/                           # buildtovalue-cli
│       ├── Cargo.toml
│       └── src/main.rs
│
├── python/                            # HEMISFÉRIO PYTHON
│   ├── buildtovalue/
│   │   ├── __init__.py
│   │   ├── governance/                # context_engine, mercy_calculator, profile_manager, trust_score
│   │   ├── compliance/                # translator, ajl_exporter, roi_engine, frameworks
│   │   ├── intelligence/              # misp_ingestor, threat_classifier, policy_generator
│   │   ├── api/                       # app.py, routes/{validate,appeals,health}, middleware, schemas
│   │   ├── core/                      # config, exceptions, types
│   │   ├── observability/             # logger, metrics, tracing
│   │   └── cli/                       # main.py, commands/
│   ├── tests/{unit,integration,e2e}/
│   └── pyproject.toml
│
├── data/                              # DADOS COMPARTILHADOS
│   ├── policies/{core,compliance,profiles,_metadata}/
│   ├── ledger/{wal,snapshots}/
│   └── intelligence/threats.db
│
├── spec/                              # CONTRATOS
│   ├── protobuf/{evidence,verdict,batch}.proto
│   └── openapi/api_v2.yaml
│
├── docs/
│   ├── adrs/                          # Architecture Decision Records
│   ├── PROJECT_CONTEXT.md             # ESTE ARQUIVO
│   └── HANDOFF_TEMPLATES.md
│
├── Cargo.toml                         # Workspace root
├── pyproject.toml
├── Makefile
└── docker-compose.yml
```

## Cargo.toml (Workspace Root — REFERÊNCIA)
```toml
[workspace]
members = [
    "rust/kernel",
    "rust/bindings",
    "rust/cli",
    # "rust/gateway",  # Descomentado em v1.9+
]
resolver = "2"

[workspace.package]
version = "2.3.1"
edition = "2021"
authors = ["BuildToValue Team <team@buildtovalue.com>"]
license = "Apache-2.0"

[workspace.dependencies]
blake3 = "1.5"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
pyo3 = { version = "0.20", features = ["extension-module"] }
prost = "0.12"
phf = { version = "0.11", features = ["macros"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "1.0"
tracing = "0.1"
tokio = { version = "1", features = ["full"] }
anyhow = "1.0"
lazy_static = "1.4"
clap = { version = "4", features = ["derive"] }
colored = "2.0"
```

## Convenções de Código

### Rust
- Naming: snake_case funções/variáveis, PascalCase types/traits
- Error handling: `thiserror` para custom errors, ZERO `.unwrap()` em lib code
- Cada `.clone()` DEVE ter justificativa em comentário
- Traits em `validators/mod.rs` definem TODAS as interfaces
- Máximo 50 linhas por função, máximo 200 linhas por arquivo
- Hot path (evidence/, gatekeeper.rs): ZERO heap allocations (fixed-size arrays)
- Hash: BLAKE3 (NUNCA DefaultHasher, NUNCA SHA-256 para evidence)
- Fail-secure: todo `match` e `Result` DEVE ter branch de erro → BLOCK

### Python
- PEP 8, type hints obrigatórios em TODA função pública
- Pydantic para validação na fronteira (schemas.py)
- `explain_decision()` OBRIGATÓRIO em toda decisão ética
- HMAC-SHA256 para assinar EthicalVerdict
- Async-first para I/O (FastAPI)

### PyO3 Boundary (rust/bindings/)
- Camada FINA: APENAS conversão de tipos + delegação
- ZERO lógica de negócio na camada de binding
- `py.allow_threads()` para operações > 1ms no Rust
- Owned types na fronteira: String, Vec<T> (não &str, não &[u8])
- PyBytes para dados binários (evita cópia desnecessária)
- Timeout: 10ms por batch FFI (fail-secure: BLOCK em timeout)

## Tipo Central: TechnicalEvidence (9596 bytes)
```rust
// rust/kernel/src/evidence/technical.rs
#[repr(C)]
pub struct TechnicalEvidence {
    pub protocol_version: u16,         // 0x0201 (v2.1)
    pub audit_trail_id: u128,          // ID único da requisição
    pub timestamp: u128,               // Microseconds since epoch
    pub evidence_hash: u64,            // BLAKE3 de todos os campos
    pub composite_risk: u8,            // 0-255 (weighted average)
    pub _reserved: [u8; 7],
    pub findings: [Finding; 10],       // Ring buffer (normais)
    pub finding_count: u8,
    pub finding_position: u8,          // Posição atual no ring buffer
    pub _padding1: [u8; 6],
    pub critical: [Finding; 3],        // Preserved (nunca sobrescritos)
    pub critical_count: u8,
    pub _padding2: [u8; 7],
    pub stats: InputStatistics,        // Entropy, zscore, ratios
    pub bias: BiasDeclaration,         // FPR, calibration_date
    pub original_request_hash: u64,    // BLAKE3 do input original
    pub input_size: u32,
    pub processing_flags: u32,
    pub executed_modules: u64,         // Bitmask de módulos executados
    pub processing_time_us: u64,
    pub _reserved_metadata: [u8; 7000],
    pub checksum: u64,                 // BLAKE3 integridade
}
// INVARIANTE: size_of::<TechnicalEvidence>() == 9596
```

## Trait Central: Validator
```rust
// rust/kernel/src/validators/mod.rs
pub trait Validator: Send + Sync {
    fn validate(&self, input: &str) -> Vec<Finding>;
    fn module_id(&self) -> ValidatorModule;
    fn bias_declaration(&self) -> BiasDeclaration;
}
```

## Ações Possíveis (5 níveis de severidade)
```
L0: ALLOW   → Passa sem modificação
L1: LOG     → Passa + registra no ledger
L2: EDUCATE → Passa + mensagem educativa ao agente
L3: REDACT  → Mascara PII (CPF: ***.XXX.XXX-**)
L4: BLOCK   → Rejeita com rationale explicável
```

## Decisões Arquiteturais Vigentes
| ID | Decisão | Rationale | Data |
|----|---------|-----------|------|
| ADR-001 | Monolito Modular | Elimina latência gRPC + simplifica ops | 2026-02-08 |
| ADR-002 | PyO3+Maturin (não FFI puro) | Ergonomia, type safety | 2026-01-15 |
| ADR-003 | Workspace com crates separados | Core testa sem Python | 2026-01-16 |
| ADR-004 | BLAKE3 (não SHA-256) | 2-3x mais rápido, collision-resistant | 2026-01-20 |
| ADR-005 | TechnicalEvidence v2.1 (fixed-size) | Zero heap, determinístico | 2026-01-25 |
| ADR-006 | Ring Buffer para Findings | Bounded memory, O(1) insert | 2026-01-25 |
| ADR-007 | BiasDeclaration obrigatório | Transparência radical (Jonas) | 2026-01-28 |
| ADR-008 | Constant-time comparison | Previne timing attacks | 2026-02-01 |
| ADR-009 | Monolito Modular (Pivot v3.0) | Elimina gRPC, Node.js, multi-container | 2026-02-08 |

## Dependências Aprovadas

### Rust (NÃO adicionar sem ADR)
blake3, serde, serde_json, pyo3, prost, phf, chrono, thiserror, 
tracing, tokio, anyhow, lazy_static, clap, colored, regex, 
base64, hex, ring, rand, spin_sleep, unicode-normalization,
criterion (dev-only)

### Python (NÃO adicionar sem ADR)
fastapi, pydantic, uvicorn, httpx, PyYAML, click, 
prometheus-client, opentelemetry-api, opentelemetry-sdk,
pytest, pytest-cov, pytest-asyncio, black, ruff, mypy (dev-only)

## Anti-padrões PROIBIDOS
- ❌ `.unwrap()` em código de biblioteca Rust
- ❌ `.clone()` sem justificativa em comentário
- ❌ `DefaultHasher` ou `SHA-256` para evidence (usar BLAKE3)
- ❌ `Vec<Finding>` no hot path (usar arrays fixos [Finding; N])
- ❌ Heap allocation no hot path (evidence/, gatekeeper.rs)
- ❌ `any` type em Python
- ❌ Decisão ética sem `explain_decision()` retornando rationale
- ❌ Decisão ética sem assinatura HMAC-SHA256
- ❌ Timeout sem fail-secure (timeout → BLOCK, nunca ALLOW)
- ❌ Erro sem fail-secure (erro → BLOCK, nunca bypass)
- ❌ Dependências não listadas acima sem ADR aprovado
- ❌ Lógica de negócio na camada PyO3 (rust/bindings/)
- ❌ Criar pastas/módulos fora da estrutura definida
- ❌ Acesso direto a data/policies/ sem checksums.json validation
- ❌ Microserviços, gRPC, Node.js, containers separados por módulo
- ❌ Magic numbers sem named constants
- ❌ Funções > 50 linhas
- ❌ Arquivos > 200 linhas (refatorar em submódulos)

## Padrão de Referência: Validator + Finding
```rust
// rust/kernel/src/validators/brazilian/cpf.rs — PADRÃO A SEGUIR

use crate::evidence::Finding;
use crate::core::types::{ValidatorModule, TechnicalSeverity};
use crate::validators::Validator;

pub struct CpfValidator {
    regex: regex::Regex,
}

impl CpfValidator {
    pub fn new() -> Self {
        Self {
            regex: regex::Regex::new(r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}").unwrap(),
        }
    }

    fn verify_digits(digits: &[u8; 11]) -> bool {
        // Mod 11 check (dois dígitos verificadores)
        let sum1: u32 = digits[..9].iter().enumerate()
            .map(|(i, &d)| d as u32 * (10 - i as u32))
            .sum();
        let check1 = (sum1 * 10 % 11) % 10;
        if check1 != digits[9] as u32 { return false; }

        let sum2: u32 = digits[..10].iter().enumerate()
            .map(|(i, &d)| d as u32 * (11 - i as u32))
            .sum();
        let check2 = (sum2 * 10 % 11) % 10;
        check2 == digits[10] as u32
    }
}

impl Validator for CpfValidator {
    fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for mat in self.regex.find_iter(input) {
            let digits_only: Vec<u8> = mat.as_str().chars()
                .filter(|c| c.is_ascii_digit())
                .map(|c| c as u8 - b'0')
                .collect();
            
            if digits_only.len() == 11 {
                let arr: [u8; 11] = digits_only.try_into().unwrap();
                if Self::verify_digits(&arr) {
                    findings.push(Finding::new(
                        ValidatorModule::CPF,
                        TechnicalSeverity::PolicyViolation,
                        "CPF_DETECTED",
                        "Valid CPF number detected",
                        "Brazilian Individual Taxpayer ID (sensitive PII)",
                    ).with_position(mat.start() as u32, mat.end() as u32)
                     .with_confidence(255)); // 100% certeza (algoritmo determinístico)
                }
            }
        }
        findings
    }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::CPF }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration {
            false_positive_rate: 0,    // 0% — mod 11 é determinístico
            false_negative_rate: 5,    // ~2% — CPFs ofuscados escapam
            calibration_date: 20260209, // YYYYMMDD
            known_limitations: *b"Ofuscated CPFs (spaced/encoded) may evade regex\0\0\0\0\0\0\0\0\0",
        }
    }
}
```

## Padrão de Referência: PyO3 Binding (FINO)
```rust
// rust/bindings/src/ffi_evidence.rs — PADRÃO A SEGUIR

use pyo3::prelude::*;
use buildtovalue_kernel::Gatekeeper;

#[pyclass]
pub struct PyGatekeeper {
    inner: Gatekeeper,  // Delega TUDO ao kernel
}

#[pymethods]
impl PyGatekeeper {
    #[new]
    fn new() -> Self {
        Self { inner: Gatekeeper::new() }
    }

    fn scan(&mut self, py: Python, input: &str, audit_id: u128) -> PyResult<Vec<u8>> {
        // 1. Libera GIL (operação > 1ms)
        let evidence = py.allow_threads(|| {
            self.inner.scan_for_evidence(input, audit_id)
        });
        // 2. Serializa para bytes (crossing boundary)
        Ok(evidence.to_bytes().to_vec())
    }
}
```

## Fluxo End-to-End Resumido
```
Request → Ingestion (<1ms) → FFI Bridge (<2ms) → Rust Kernel (<30ms)
  → [Validators → Statistics → Deobfuscator → Policy → Finalize]
  → TechnicalEvidence (9596 bytes) → FFI Bridge (<2ms)
  → Python Governance (<10ms)
  → [ProfileManager → TrustScore → EthicalContext → MercyCheck → Verdict]
  → EthicalVerdict (signed) → Execution (<5ms)
  → [Ledger.append + TrustScore.update + Action.execute]
  → HTTP Response
```

## Roadmap Atual
- **v1.5.0** ← FOCO (18 fev - 12 abr 2026): Evidence Protocol, Batch, Ledger
- v1.6.0: Deobfuscator, OutputGuard, Policies (6 módulos)
- v1.7.0: Network, SessionGuard, Interceptor
- v1.8.0: EthicalContextEngine, Misericórdia, ContestabilityLoop
- v1.9.0: REST API (Axum), Observability, PolicyTester
- v2.0.0: Intelligence Hub, Compliance Translator, Frontend

## Bloqueios Atuais (NÃO implementar)
- ❌ Frontend/Angular (v2.0+)
- ❌ ML features (v1.8+)
- ❌ Axum gateway (v1.9+)
- ❌ NATS JetStream (v1.9+)
- ❌ SLM/Phi-4 Mini (v2.0+)
- ❌ Otimizações prematuras (profile first, optimize second)

## Comandos de Build
| Ação | Comando |
|------|---------|
| Build Rust | `cd rust && cargo build --release` |
| Test Rust | `cargo test --workspace` |
| Benchmark Rust | `cd rust/kernel && cargo bench` |
| Clippy | `cd rust && cargo clippy --workspace -- -D warnings` |
| Build FFI | `cd rust/bindings && maturin develop --release` |
| Install Python | `cd python && pip install -e ".[dev]"` |
| Test Python | `cd python && pytest tests/ -v` |
| Format Python | `cd python && black . && ruff check --fix .` |
| Full CI | `make test` |