# BuildToValue — Architecture Atlas & Vision (v3.0)

> **NOTA DE CONTEXTO:** Este documento contém a VISÃO COMPLETA do projeto (v1.0 até v3.0).
> O `README.md` na raiz reflete apenas o estado atual de implementação.
> O `PROJECT_CONTEXT.md` é a verdade técnica para a versão em desenvolvimento (v1.5).
> Use este Atlas para decisões arquiteturais de longo prazo e compatibilidade futura.

---

## 📚 Hierarquia de Verdade (Ordem de Precedência)

| Prioridade | Documento | Função | Aviso |
|:---:|---|---|---|
| 1 | `docs/PROJECT_CONTEXT.md` | Verdade técnica absoluta (v1.5) | Fonte primária para código e estrutura |
| 2 | `docs/ARCHITECTURE_ATLAS.md` | Verdade arquitetural (visão v3.0) | Consultar para compatibilidade futura |
| 3 | `README.md` | Estado público atual | Deve refletir apenas o que existe |
| 4 | `documentacao.md` | Regras de negócio detalhadas | ⚠️ Paths e stack de rede OBSOLETOS |
| 5 | `documentacaoInicial.md` | Filosofia e missão (imutável) | ⚠️ IGNORE tecnologias e estrutura de pastas |

### Regras de Conflito

- **Estrutura de pastas** → `PROJECT_CONTEXT.md` vence sempre
- **Lógica de negócio** → `documentacao.md` pode ser consultado, adaptado ao Monolito Modular
- **Princípios éticos** → `documentacaoInicial.md` é canônico e imutável
- **Decisões futuras** → Este Atlas é referência, mas não autoriza implementação fora do roadmap

---

## 🗺️ Roadmap de Evolução Arquitetural

### FASE 1: A Fundação (Atual — v1.5)

- **Foco:** Determinismo, segurança de memória, ponte Rust↔Python funcional.
- **Tech:** Rust Kernel (`buildtovalue-kernel`), PyO3/Maturin (`rust/bindings/`), Evidence Protocol v2.1 (9596 bytes).
- **Infra:** Processo único, logs locais (WAL), FastAPI para API.
- **Entregáveis:** BiasDeclaration mandate, BatchProcessor, DurableLedger, 60+ testes.

### FASE 2: Expansão de Contexto e Governança (v1.6 — v1.9)

- **Foco:** Detecção avançada, governança ética runtime, observabilidade.
- **v1.6:** PolicyEngine, OutputGuard, Deobfuscator v2 (chaining).
- **v1.7:** IpClassifier, SessionDriftDetector, Interceptor, testes contextuais.
- **v1.8:** EthicalContextEngine (Python), MercyCalculator, ContestabilityLoop.
- **v1.9:** Axum Gateway (substitui FastAPI para serving), Prometheus, NATS JetStream (logs duráveis).
- **Infra:** Docker hardening (Distroless), distributed tracing.

### FASE 3: Inteligência Soberana (Futuro — v2.0+)

- **Foco:** Elucidação ética automatizada, compliance multi-framework, interface enterprise.
- **v2.0:** Intelligence Hub (MISP/STIX), Compliance Translator (PDF→YAML), Streamlit MVP.
- **Futuro (pós v2.0):** Local SLM (Phi-4 Mini via `llama-cpp-2`), Angular Enterprise Dashboard.
- **Infra:** Orquestração de recursos (CPU pinning, mmap para SLM), multi-tenant.

### FASE 4: Comunidade e Governança Aberta (2027)

- **Q3 2027:** Apache 2.0 release, 100+ stars, 10+ contributors, ISO 42001 assessment.
- **Q4 2027:** LF AI & Data Sandbox submission, 3+ co-submitting orgs.

---

## 📚 Catálogo Completo de ADRs

### Grupo A: Fundamentos Estabelecidos (ADR-001 a ADR-009)

| ID | Título | Status | Versão | Resumo |
|:---|:---|:---|:---|:---|
| **001** | Hybrid Architecture | ✅ Ativo | v1.0 | Rust = Fatos Técnicos, Python = Julgamentos Éticos. Ponte via PyO3. |
| **002** | Evidence Protocol v1.0 | ⛔ Obsoleto | v1.0 | Substituído por ADR-005 (v2.1). |
| **003** | Mercy Algorithm | ✅ Ativo | v1.0 | Gilligan: uncertainty > 0.7 + trust > 0.6 + critical == 0 → abrandar. |
| **004** | Immutable Ledger | ✅ Ativo | v1.0 | WAL + BLAKE3 chain. Sync remoto via S3 (ADR-007). |
| **005** | Evidence Protocol v2.1 | ✅ Ativo | v1.5 | TechnicalEvidence: 9596 bytes fixos, BLAKE3, ring buffer [10]+[3]. |
| **006** | Policy-as-Code | ✅ Ativo | v1.0 | YAML versionado, herança hierárquica, blind testing (Rawls). |
| **007** | Remote Sync (S3) | ✅ Ativo | v1.5 | S3 upload real com retry (3x, backoff exp.), DLQ, idempotência. |
| **008** | Timing Mitigation | ✅ Ativo | v1.0 | Validadores constant-time para evitar side-channel leaks. |
| **009** | Modular Monolith | ✅ Ativo | v3.0 | Processo único, módulos lógicos. Sem microserviços/gRPC/Node.js. |

### Grupo B: v1.5 — Evidence & Transparency (ADR-010)

| ID | Título | Status | Versão | Resumo |
|:---|:---|:---|:---|:---|
| **010** | BiasDeclaration Mandate | 🚧 Em Implementação | v1.5 | `bias_declaration()` obrigatório em todo Validator. FPR/FNR + calibration_date. |

### Grupo C: v1.6 — Policy & Output (ADR-011 a ADR-013)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **011** | PolicyEngine | 🔒 Planejado | v1.6 | YAML → runtime. `phf` para hard blocks O(1). Pattern matching regex pré-compilado. |
| **012** | OutputGuard | 🔒 Planejado | v1.6 | PII masking em respostas de agentes. Re-scan após sanitização. |
| **013** | Deobfuscator v2 (Chaining) | 🔒 Planejado | v1.6 | Cadeia base64→hex→leet, max 3 layers. Overhead máx 5ms. 3 falhas = critical. |

### Grupo D: v1.7 — Context (ADR-014 a ADR-015)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **014** | IpClassifier + SessionDrift | 🔒 Planejado | v1.7 | Tor/VPN/datacenter detection. Cosine similarity para drift comportamental. |
| **015** | Interceptor (Pre/Post Hooks) | 🔒 Planejado | v1.7 | Trait `RequestInterceptor` + `ResponseInterceptor`. Chain ordenada, fail-secure. |

### Grupo E: v1.8 — Governance (ADR-016 a ADR-017)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **016** | EthicalContextEngine v4.0 | 🔒 Planejado | v1.8 | Fluxo completo: Rawls → Levinas → Jonas → Gilligan. `explain_decision()` obrigatório. |
| **017** | ContestabilityLoop (SLA 24h) | 🔒 Planejado | v1.8 | Submit → Status → Resolve. Feedback loop: appeals bem-sucedidas melhoram sistema. |

### Grupo F: v1.9 — API & Observability (ADR-018 a ADR-019)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **018** | Axum Gateway | 🔒 Planejado | v1.9 | Substitui FastAPI para HTTP serving. `rust/gateway/` (único crate novo). Tokio runtime. |
| **019** | Observability (Prometheus + Tracing) | 🔒 Planejado | v1.9 | Métricas Prometheus, W3C Trace Context. Kernel + Governance. |

### Grupo G: v2.0 — Intelligence & Compliance (ADR-020 a ADR-022)

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---|:---|:---|
| **020** | Intelligence Hub (MISP/STIX) | 🔒 Planejado | v2.0 | Threat intel ingest → auto-policy generation. |
| **021** | Compliance Translator | 🔒 Planejado | v2.0 | PDF regulations → YAML policies via LLM. Multi-framework (LGPD, GDPR, EU AI Act). |
| **022** | Frontend MVP | 🔒 Planejado | v2.0 | Streamlit para MVP. Angular Enterprise é meta pós-v2.0. |

### Grupo H: Pós-v2.0 — Visão de Longo Prazo (Não numerados)

Estas decisões **não têm ADR formal** e só serão formalizadas quando entrarem no roadmap ativo.

| Tema | Alvo | Notas |
|:---|:---|:---|
| Local SLM (Phi-4 Mini) | Pós-v2.0 | `llama-cpp-2`, GGUF Q4_K_M, CPU-only, mmap. Privacidade total. |
| Angular Enterprise Dashboard | Pós-v2.0 | Substitui Streamlit. Multi-tenant, XSS/CSP nativo. |
| NATS JetStream (full) | v1.9+ | Logs duráveis com criptografia em repouso. Complementa S3 (ADR-007). |
| Hardened Container (Distroless) | v1.9+ | Dockerfile 4 estágios. Non-root, sem compiladores na imagem final. |
| Zero-Knowledge Proofs | Pós-v2.0 | Validar permissão sem revelar identidade. Conceito exploratório. |
| Verificação Formal (Kani/Prusti) | Pós-v2.0 | Provas matemáticas de ausência de panic no Kernel. |

---

## 🔍 Detalhamento dos ADRs Críticos

### ADR-005: Evidence Protocol v2.1 (Ativo)

O coração forense do sistema. Cada scan produz exatamente 9596 bytes.
```
TechnicalEvidence (9596 bytes)
├── Header (64B): version, audit_trail_id, timestamp, evidence_hash, composite_risk
├── Findings normais (1280B): Ring buffer [Finding; 10] × 128B
├── Findings críticos (384B): [Finding; 3] preservados (nunca sobrescritos)
├── Statistics (256B): Entropy, Z-Score, CharRatio agregados
├── BiasDeclaration (512B): FPR, FNR, calibration_date, known_limitations
├── Metadata (7092B): request_hash, input_size, executed_modules, processing_time
└── Checksum (8B): BLAKE3 de toda a struct
```

**Invariantes:** Zero heap no hot path. `size_of::<TechnicalEvidence>()` é assert estático. Hash BLAKE3 (nunca SHA-256 ou DefaultHasher).

### ADR-007: Remote Sync via S3 (Ativo)

Resolve a promessa de 99.99% durabilidade do Ledger.
```
Entry → WAL (RAM, <1ms) → Disk (SSD, <5ms) → S3 (async, <10ms)
                                                ├─ Retry 1 (100ms)
                                                ├─ Retry 2 (200ms)
                                                ├─ Retry 3 (400ms)
                                                └─ DLQ (se falhar)
```

Key format: `{prefix}/{year}/{month}/{day}/{entry_id:08x}.bin` — idempotente (mesmo entry_id = mesma chave S3).

### ADR-009: Modular Monolith (Ativo)

Decisão reconciliada v2.2→v3.0. Estrutura física preservada:
```
rust/kernel/         → buildtovalue-kernel (crate único, módulos internos)
rust/bindings/       → buildtovalue-bindings (PyO3/Maturin)
rust/cli/            → buildtovalue-cli
rust/gateway/        → btv-gateway (v1.9+ APENAS, único crate novo)
python/buildtovalue/ → Namespace hierárquico (governance/, compliance/, etc.)
```

**Rejeitado:** 7 crates `btv-*` separados (overhead CI/CD, namespace break, rewrite risk).

### ADR-010: BiasDeclaration Mandate (Em Implementação)

Todo Validator, StatisticsModule e DeobfuscatorModule deve implementar `bias_declaration()`:
```rust
fn bias_declaration(&self) -> BiasDeclaration {
    BiasDeclaration {
        false_positive_rate: u8,     // 0-255 (resolução ~0.4%)
        false_negative_rate: u8,     // 0-255
        calibration_date: u32,       // YYYYMMDD (< 90 dias validade)
        known_limitations: [u8; 128] // null-padded string
    }
}
```

Gatekeeper agrega: max(FPR), max(FNR), min(calibration_date) — worst-case de todos os módulos executados.

**Filosofia (Jonas):** Ocultar margem de erro viola responsabilidade proporcional. BiasDeclaration é o "rótulo nutricional" do sistema.

---

## 🧠 Fundamentos Filosóficos (Imutáveis)

Estes princípios são a Constituição da República Algorítmica. Não mudam entre versões.

| Filósofo | Princípio | Implementação |
|:---|:---|:---|
| **Rawls** (1971) | Justiça como equidade | Blind Policy Testing: avaliar sem saber se é autor, alvo ou auditor. Princípio da Diferença: favorecer continuidade em alta incerteza. |
| **Levinas** (1961) | Dever de cuidado | Fail-secure: erros protegem o usuário (BLOCK, não bypass). Educar antes de punir (EDUCATE → BLOCK). |
| **Gilligan** (1982) | Ética do cuidado | Misericórdia algorítmica: uncertainty > 0.7 + trust > 0.6 + critical == 0 → abrandar. Contexto > regra rígida. |
| **Jonas** (1984) | Responsabilidade proporcional | BiasDeclaration obrigatório. Ledger imutável. Cada decisão assinada (HMAC-SHA256). Auditoria externa. |

---

## 🔮 Diretriz para Compatibilidade Futura

Ao implementar features da v1.5, a Squad deve garantir:

1. **Interfaces limpas:** Traits de validação devem aceitar extensão sem quebrar assinatura. Novos módulos (v1.6+) plugam no Gatekeeper sem alterar os existentes.

2. **Separação Kernel↔Governance:** Nenhuma lógica ética em Rust. Nenhuma lógica de detecção em Python. A ponte FFI (PyO3) é o único ponto de contato.

3. **Evidence extensível:** Os 7000 bytes de `_reserved_metadata` em TechnicalEvidence existem para módulos futuros (Network, SessionGuard, PolicyEngine) sem alterar o tamanho total.

4. **Ledger preparado para NATS:** O `DurableLedger` atual (WAL + S3) deve usar uma trait `LedgerBackend` que permita plugar NATS JetStream na v1.9 sem rewrite.

5. **Sem dependências prematuras:** Não importar crates/libs que só serão necessários em versões futuras. Cada versão deve compilar com o mínimo necessário.

---

## 📊 Compliance Roadmap (Multi-Framework)

Baseado nas análises ISO 42001, NIST CSF e EU AI Act realizadas em fevereiro 2026:

| Framework | Score Atual | Alvo | Gaps Críticos |
|:---|:---|:---|:---|
| ISO 42001 | 78% (Silver) | Gold (Q3 2027) | SoA formal, AI Impact Assessment, Competence docs, Incident Comm. Plan |
| NIST CSF 2.0 | ~70% | 85% (Q2 2027) | Supply chain risk, formal recovery testing, external audit |
| EU AI Act | ~40% | 80% (Q3 2026) | Prohibited Practices Detector (⚠️ Art.5 já em vigor), Risk Classification, FRIA, Conformity Assessment |

**Prioridade:** EU AI Act Art. 5 (práticas proibidas) está em vigor desde fev/2025. Art. 4 (literacia IA) idem. Maioria dos requisitos high-risk aplica-se a partir de ago/2026 (~6 meses).

**Arquitetura de compliance:** Runtime Engine é único. Cada framework gera artefatos diferentes via plugins `CompliancePlugin`:
```python
class CompliancePlugin(Protocol):
    def framework_id(self) -> str: ...
    def generate_artifacts(self, evidence, verdict) -> list[ComplianceArtifact]: ...
    def validate_requirements(self) -> ComplianceReport: ...
```

---

## ⚠️ Headers de Aviso para Documentos Legados

### Para `documentacaoInicial.md`
```
┌─────────────────────────────────────────────────────────────┐
│ Status: 🏛️ Manifesto Filosófico (Imutável)                 │
│ Como usar: APENAS para princípios éticos e missão.          │
│ Aviso: IGNORE tecnologias e estrutura de pastas.            │
│ Este é o documento de fundação (v1.0).                      │
└─────────────────────────────────────────────────────────────┘
```

### Para `documentacao.md`
```
┌─────────────────────────────────────────────────────────────┐
│ Status: 📚 Referência Lógica (Legado)                       │
│ Como usar: Regras de negócio, algoritmos, specs de          │
│ conformidade (LGPD/AI Act).                                 │
│ Aviso: Estrutura física (src/, gRPC, Node.js) OBSOLETA.     │
│ Se conflitar com PROJECT_CONTEXT.md → PROJECT_CONTEXT vence.│
│ Se conflitar em lógica → adaptar ao Monolito Modular.       │
└─────────────────────────────────────────────────────────────┘
```

---

*Última atualização: 09 de fevereiro de 2026*
*Versão do Atlas: 1.0 (sincronizado com Roadmap Iteração 3)*