# BuildToValue (BTV)

**Governança de Agentes de IA com Evidência Criptográfica Imutável.**

> **📚 Documentação:** [Hub da Documentação](docs/README.md) — com trilhas dedicadas para **[Engenheiros](docs/for-engineers.md)** e **[DPO / CISO](docs/for-dpo-ciso.md)**.

---

## O que você ganha em 10 minutos

```bash
git clone https://github.com/danzeroum/BuildToValueGovernance
cd BuildToValueGovernance
docker compose -f ops/docker-compose.quickstart.yml up -d
# Abra http://localhost:8501
```

Seu agente existente passa a ter **toda chamada LLM interceptada, validada contra LGPD/GDPR/EU AI Act e auditada com evidência criptográfica** — zero modificação no código do agente:

```bash
# Antes: agente chama OpenAI diretamente
OPENAI_BASE_URL=https://api.openai.com

# Depois: BTV intercepta, valida e encaminha (ou bloqueia)
OPENAI_BASE_URL=http://localhost:8080/v1/proxy
OPENAI_API_KEY=sk-...   # encaminhado transparentemente ao upstream
```

Decisões em violação retornam HTTP 451 com evidência criptográfica linkada. Decisões conformes são encaminhadas sem latência perceptível (<50ms P99).

---

## Como isso se traduz em conformidade real

| Bundle | Artigo coberto | O que bloqueia |
|--------|---------------|----------------|
| `gdpr_art22_chatbot` | GDPR Art. 22 | Decisões automatizadas de crédito/emprego sem revisão humana |
| `hipaa_phi_audit` | HIPAA §164.312 | PHI em output de LLM sem sanitização ou consentimento |
| `baseline_trust` | LGPD Art. 46 | Dados sensíveis (CPF, cartão) sem base legal |

Cada bloqueio gera um recibo de evidência com HMAC-SHA256, armazenado em ledger imutável e contestável em 24h (LGPD Art. 20 / EU AI Act Art. 14).

---

## O Problema

> *"Nossa IA negou um empréstimo / rejeitou um candidato / bloqueou acesso. O regulador pediu a trilha de evidências. Tínhamos logs. Os logs estavam incompletos."*

Isso não é um problema de logging. É um **problema de accountability estrutural**. Logs de runtime podem ser descartados sob carga, sobrescritos ou omitidos silenciosamente. O BTV elimina essa classe de falha tornando o estado padrão do sistema o bloqueio, não a permissão.

**Contexto regulatório:** GDPR Art. 22, EU AI Act Art. 86, LGPD Art. 18 — todos exigem que decisões de IA carreguem evidências auditáveis. O BTV torna a não-conformidade detectável em runtime com latência de microssegundos, antes de qualquer resposta ser emitida.

---

## Performance

O BTV adiciona **~1,67μs** por decisão para um payload de contexto de 4KB — cinco ordens de magnitude menos do que uma chamada típica de inferência LLM.

| Operação | Latência | Notas |
|---|---|---|
| `scan_for_evidence` (4KB) | 1,67 μs | BLAKE3 + pipeline de 15 módulos |
| Verificação de integridade | 327 ns | Auditoria retroativa |
| Gateway HTTP (sidecar) | < 50ms p99 | Inclui round-trip de rede |

A 1 milhão de decisões/ano, o custo total de infraestrutura é **~$5.000/ano** — comparado à multa mediana do GDPR de **$10,8M** por falhas evidenciais.

---

## Quickstart (< 5 minutos)

### Path 0 — Docker (zero instalação)

```bash
docker compose -f ops/docker-compose.quickstart.yml up -d
# Dashboard: http://localhost:8501
# Gateway:   http://localhost:8080
# Mock upstream (httpbin): http://localhost:8082
```

### Path A — Rust (integração nativa)

```toml
# Cargo.toml
[dependencies]
btv-kernel = { path = "rust/kernel" }
```

```rust
use btv_kernel::Gatekeeper;

fn main() {
    let mut gatekeeper = Gatekeeper::new();
    let audit_id: u128 = 1;

    // scan_for_evidence() sempre retorna TechnicalEvidence com hash BLAKE3 selado.
    // O pipeline executa 15 módulos (deobfuscação, análise, validação de PII).
    let evidence = gatekeeper.scan_for_evidence("Aprovar crédito para CPF 123.456.789-09", audit_id);

    println!("Hash BLAKE3:    {:?}", &evidence.hash[..8]);
    println!("Findings:       {}", evidence.finding_count);
    println!("Critical:       {}", evidence.critical_count);
    println!("Risco composto: {:.2}", evidence.composite_risk);
    println!("Latência:       {}μs", evidence.processing_time_us);
}
```

### Path B — HTTP Gateway / Sidecar (LangChain, Python, qualquer stack)

```bash
cd ops && docker compose up gateway
```

```bash
curl -X POST http://localhost:3000/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"input": "Aprovar crédito para CPF 123.456.789-09", "audit_trail_id": 1}'
# Retorna: TechnicalEvidence serializada com hash BLAKE3 imutável
```

### Path C — Python SDK

```bash
pip install -e python/
```

```python
from buildtovalue import BTVClient

client = BTVClient("http://localhost:3000")
evidence = client.scan(
    input_text="Aprovar crédito para CPF 123.456.789-09",
    audit_trail_id=1
)
print(evidence["hash"])          # hash BLAKE3 — prova imutável
print(evidence["critical_count"])  # > 0 = BLOCK recomendado
```

---

## Verificabilidade Matemática, não apenas Log

### Por que é impossível tomar uma decisão silenciosa?

O design Fail-Secure do BTV parte de uma invariante simples: **o estado inicial de qualquer evidência é inválido**.

```rust
// Estado inicial: hash = [0u8; 32] — evidência inválida por construção
let mut evidence = TechnicalEvidence::new(audit_trail_id);

// Sem chamar finalize(), o hash permanece zerado.
// Qualquer consumidor que verificar validate_hash() receberá false.
assert!(!evidence.validate_hash()); // ← sempre verdadeiro sem finalize()

// O único caminho para uma evidência válida é selar o hash BLAKE3:
evidence.finalize().expect("falha ao finalizar evidência");
assert!(evidence.validate_hash()); // ← agora verdadeiro

// O Gatekeeper chama finalize() internamente via scan_for_evidence().
// Se o pipeline falhar em qualquer ponto, o fallback é evidence com
// critical_count > 0 — sinalização de BLOCK para o camada de decisão.
```

**Papel do compilador:** O tipo `TechnicalEvidence` é anotado com `#[must_use]`:

```rust
#[must_use = "TechnicalEvidence must be used or logged — do not discard audit data"]
pub struct TechnicalEvidence { ... }
```

Em desenvolvimento, o compilador emite um **warning** se o resultado de `scan_for_evidence()` for descartado. Em ambientes de CI/CD com `#![deny(warnings)]` — que é o padrão recomendado para produção — esse warning se torna um **erro de compilação**, tornando o descarte de dados de auditoria detectável antes do deploy.

A combinação é: **descarte acidental → erro de build em CI; evidência não-finalizada → BLOCK em runtime**. Os dois mecanismos são complementares e verificáveis independentemente.

---

## Arquitetura

```
┌────────────────────────────────────────────────────┐
│               Axum HTTP Gateway                    │
│   /v1/scan    /v1/verify   /v1/audit   /health    │
├────────────────────┬───────────────────────────────┤
│   Rust Kernel      │      Python Governance        │
│   < 30ms p99       │      < 10ms p99               │
│                    │                               │
│  Gatekeeper        │  ComplianceEngine             │
│  BLAKE3 hash       │  explain_decision()           │
│  15 módulos        │  AppealEngine (SLA 24h)       │
│  Fail-secure       │  BiasDetector                 │
│  Zero-heap hot path│                               │
├────────────────────┴───────────────────────────────┤
│              Ledger Imutável                       │
│   WAL + cadeia BLAKE3   HMAC-SHA256 por registro   │
└────────────────────────────────────────────────────┘
```

**Invariantes do kernel:**
- `TechnicalEvidence`: 9632 bytes fixos, `repr(C, align(8))`, BLAKE3
- Zero-heap no hot path: stack-only em evidence/gatekeeper
- Fail-secure: qualquer erro → evidência com `critical_count > 0`
- `#[must_use]` em `TechnicalEvidence`: descarte acidental é detectável
- Contestabilidade: campo `contestable` + SLA de 24h via AppealEngine

---

## Módulos do Kernel — 15 Validadores

| Estágio | Módulos |
|---|---|
| Deobfuscate | Normalizer, Base64Detector, HexDecoder, LeetspeakDetector |
| Analyze | EntropyCalculator, ZScoreCalculator, CharRatioAnalyzer, LanguageDetector |
| Validate | CPF, CNPJ, Email, CreditCard, Phone, PromptInjectionDetector, SSN |
| Multi-jurisdição | NHS (UK), EU VAT, IBAN (ativados por jurisdição) |

---

## Casos de Uso

**Serviços financeiros** — Decisões de crédito/empréstimo com trilha de evidências imutável para auditorias GDPR Art. 22.

**RH / Hiring** — Triagem automatizada com accountability sob EU AI Act Art. 86.

**Saúde** — Decisões de triagem assistidas por IA com auditoria criptográfica para proteção de responsabilidade.

**Pipelines multi-agente** — Camada de governança para LangChain, AutoGen, CrewAI — envolva qualquer decisão de agente em < 10 linhas.

---

## Limitações Conhecidas

- Taxa de falso positivo ~15% em inputs adversariais (70 amostras, não validadas externamente)
- FNR de Leetspeak ~12% (homóglifos Unicode não cobertos)
- Sem TLS no gateway (HTTP simples — adicione reverse proxy para produção)
- Rotação de ledger não implementada (cresce indefinidamente)
- Verificação de pesos BLAKE3 em Rust (integração completa ADR-005) pendente v2.3
- `cargo add buildtovalue` não disponível ainda — publicação no crates.io prevista para v3.0

---

## Desenvolvimento

```bash
# Kernel Rust
cd rust && cargo build --workspace && cargo test --workspace

# Governança Python
cd python && pip install -e ".[dev]" && pytest tests/ -v

# Stack completo
cd ops && docker compose up
# Gateway: http://localhost:3000  |  Governance: http://localhost:8000
```

---

## Benchmarks

```bash
cd benchmarks && cargo bench --bench kernel_benchmark
```

Veja `benchmarks/` para resultados comparativos contra Guardrails AI e NeMo Guardrails.

---

## Roadmap

| Versão | Status | Escopo |
|---|---|---|
| v2.2 | ✅ Completo | PolicyEngine, AbliterationDetector v1.2.0, ManifestHashVerifier, IntegrityVerifier |
| v2.3 | 🚧 Atual | Verificação de pesos BLAKE3 em Rust, wiring de pipeline, estabilização do SDK |
| v3.0 | Planejado | Servidor MCP (Model Context Protocol), publicação no crates.io, Python SDK GA |

---

## Licença

Apache 2.0 — veja [LICENSE-MIT](LICENSE-MIT).

---

## Contribuição

- Validadores multi-jurisdição (novos padrões de PII)
- Scripts de benchmark contra Guardrails AI / NeMo
- Integrações do Python SDK (LangChain, AutoGen, CrewAI)
- Melhorias de documentação

Veja [docs/quickstart.md](docs/quickstart.md) para começar.
