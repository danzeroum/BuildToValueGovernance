Claro! Aqui está a tradução fiel do arquivo `readme.md` para o português:

---

# BuildToValue — Sistema Operacional de Confiança Soberana

**Infraestrutura de governança ética para agentes de IA. Kernel em Rust (fatos) + Governança em Python (julgamento).**

[![Licença: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)

---

## O que é isso

BuildToValue é um sistema de governança ética que monitora o comportamento de agentes de IA em tempo real. Detecta violações de políticas (vazamento de PII, uso indevido de dados, ataques ofuscados) e responde com ações proporcionais — de educação a bloqueio — preservando o direito de apelação.

A arquitetura segue uma “República Algorítmica” com separação de poderes: Poder Legislativo (Política como Código), Poder Executivo (Kernel Rust), Poder Judiciário (Governança Python) e Poder Auditório (Livro-razão Imutável).

**Status atual:** Desenvolvimento ativo. Kernel v2.3.1 funcional. Camada de governança documentada, mas passando por refatoração v1.5. Não está pronto para produção.

---

## Por que isso existe

Agentes de IA que processam dados sensíveis precisam de guardrails rápidos, explicáveis e justos. As abordagens existentes têm tradeoffs:

- **Listas de bloqueio:** Rápidas, mas cegas ao contexto. Um CPF deve ser permitido para um agente médico, mas bloqueado para um chatbot.
- **Classificadores de ML:** Precisos, mas opacos. Não atendem ao Art. 20 da LGPD (direito à explicação).
- **Motores de regras:** Transparentes, mas rígidos. Não há conceito de misericórdia, confiança ou proporcionalidade.

BuildToValue combina detecção determinística (Rust, < 30ms) com julgamento ético contextual (Python, < 10ms). Toda decisão é explicável, assinada criptograficamente e contestável em até 24 horas.

Nos baseamos em Rawls (justiça), Levinas (dever de cuidado), Gilligan (ética do cuidado/contextual) e Jonas (responsabilidade proporcional) — não por novidade, mas porque esses referenciais resolvem exatamente os problemas criados pela governança automatizada.

---

## Arquitetura

### Monólito Modular (ADR-009)

Processo único, módulos logicamente separados. Sem microsserviços, sem gRPC, sem serialização entre processos no caminho crítico.
```
Requisição (usuário/agente)
  → Ingestão (Unicode NFC, validação)                    < 1ms
  → Ponte FFI (batch Protobuf, py.allow_threads)         < 2ms
  → Kernel Soberano Rust (scan_for_evidence)             < 30ms
    ├─ Validadores:   CPF, CNPJ, Email, Telefone, Cartão de Crédito
    ├─ Estatísticas:  Entropia de Shannon, Z-Score, Proporções de caracteres
    ├─ Desofuscador:  Base64, Hex, Leetspeak
    ├─ Política:      Bloqueios duros (phf O(1))
    ├─ Rede:          Classificação de IP (Tor/VPN/datacenter)
    ├─ Guarda de Sessão: Detecção de desvio comportamental
    └─ Saída: Evidence Técnica (9596 bytes, tamanho fixo, BLAKE3)
  → Governança Python (EthicalContextEngine)             < 10ms
    ├─ Resolução de perfil (hierarquia YAML)
    ├─ Consulta de score de confiança
    ├─ Análise ética (Rawls + Levinas + Jonas)
    ├─ Checagem de misericórdia (Gilligan)
    └─ Saída: Veredito Ético (assinado HMAC-SHA256)
  → Execução                                              < 5ms
    ├─ Append ao livro-razão (WAL + sincronização remota)
    ├─ Ação: ALLOW | LOG | EDUCATE | REDACT | BLOCK
    └─ Resposta (com URL de apelação)

Total: < 50ms (p99) ponta a ponta
```

### Os Quatro Poderes

| Poder | Papel | Implementação |
|-------|------|----------------|
| **Legislativo** | Definir regras | Políticas YAML no Git, testes cegos (Rawls), veto do Comitê Ético |
| **Executivo** | Detectar violações | Kernel Rust: validadores determinísticos, evidence de tamanho fixo |
| **Judiciário** | Julgar com contexto | Governança Python: misericórdia, scores de confiança, explain_decision() |
| **Auditório** | Registrar e verificar | Livro-razão imutável: WAL, HMAC-SHA256, janela de apelação de 24h |

---

## Estrutura do Projeto
```
buildtovalue/
├── rust/                              # Hemisfério Rust (fatos)
│   ├── kernel/                        # buildtovalue-kernel (crate principal)
│   │   └── src/
│   │       ├── lib.rs                 # Re-exportações + versão
│   │       ├── core/                  # types.rs, errors.rs
│   │       ├── evidence/              # TechnicalEvidence v2.1 (9596 bytes)
│   │       ├── gatekeeper.rs          # Orquestrador (scan_for_evidence)
│   │       ├── validators/            # Detecção de PII (CPF, CNPJ, email, telefone, cartão)
│   │       ├── statistics/            # Detecção de anomalia (entropia, zscore, proporção de caracteres)
│   │       ├── deobfuscator/          # Anti-evasão (base64, hex, leetspeak)
│   │       ├── policy/               # Regras de bloqueio duro (v1.6+)
│   │       ├── network/              # Classificação de IP (v1.7+)
│   │       ├── session_guard/        # Detecção de desvio (v1.7+)
│   │       ├── output_guard/         # Sanitização de resposta (v1.6+)
│   │       ├── interceptor/          # Hooks pré/pós (v1.7+)
│   │       ├── ledger/               # WAL, cadeia de hashes, sincronização durável
│   │       ├── compliance/           # Calculadora de penalidades, métricas AJL
│   │       ├── security/             # HMAC-SHA256, comparação em tempo constante
│   │       ├── api/                  # Tipos de resposta
│   │       └── ffi/                  # Processador batch (condicional)
│   ├── bindings/                      # Ponte PyO3/Maturin
│   ├── gateway/                       # HTTP Axum (somente v1.9+)
│   └── cli/                           # Ferramenta de linha de comando btv
│
├── python/buildtovalue/               # Hemisfério Python (julgamento)
│   ├── governance/                    # EthicalContextEngine, misericórdia, confiança, perfis
│   ├── compliance/                    # Tradutor PDF→YAML, AJL, motor de ROI
│   ├── intelligence/                  # Ingestor MISP/STIX, classificador de ameaças
│   ├── api/                           # Rotas FastAPI (validação, apelações, saúde)
│   ├── core/                          # Config, exceções, tipos compartilhados
│   ├── observability/                 # Logging, métricas, tracing
│   └── cli/                           # Comandos CLI
│
├── data/policies/                     # Políticas YAML (core, compliance, perfis)
├── spec/                              # Contratos Protobuf + OpenAPI
└── docs/                              # ADRs, PROJECT_CONTEXT.md
```

---

## Invariantes Técnicos

Estes são inegociáveis. Qualquer violação impede merge.

| Invariante | Justificativa |
|-----------|-----------|
| TechnicalEvidence = 9596 bytes (fixo) | Zero alocação de heap no caminho crítico |
| BLAKE3 para todos os hashes de evidence | 2-3x mais rápido que SHA-256, resistente a colisões |
| Buffer circular: [Finding; 10] + [Finding; 3] críticos | Memória limitada, findings críticos preservados |
| Qualquer erro/tempo esgotado → BLOCK | Fail-secure (Levinas: proteger o usuário) |
| BiasDeclaration por validador | Transparência (Jonas: declarar limitações) |
| explain_decision() em todo veredito | Explicabilidade (conformidade com LGPD Art. 20) |
| HMAC-SHA256 em todo EthicalVerdict | Não repúdio (assinaturas, não confiança) |
| contestable: true em todo veredito | Contestabilidade (SLA de apelação de 24h) |

---

## Fundamentos Filosóficos

Citamos esses filósofos para reconhecer dívida intelectual, não para reivindicar novidade.

| Filósofo | Princípio | Implementação |
|-------------|-----------|----------------|
| **Rawls** (1971) | Justiça como equidade | Teste cego de políticas: avaliar sem saber se é autor, alvo ou auditor |
| **Levinas** (1961) | Dever de cuidado | Fail-secure: erros protegem o usuário. Educar (L2) antes de bloquear (L4) |
| **Gilligan** (1982) | Ética do cuidado | Algoritmo de misericórdia: alta incerteza + confiança + sem findings críticos → resposta mais branda |
| **Jonas** (1984) | Responsabilidade proporcional | BiasDeclaration: cada módulo declara taxas de falso positivo/negativo. Livro-razão imutável |

---

## Status Técnico (Honesto)

### O que funciona

- 11 validadores Rust (CPF, CNPJ, Email, Telefone, Cartão de Crédito, Entropia, ZScore, Proporção de caracteres, Base64, Hex, Leetspeak) com latência do kernel < 30ms
- TechnicalEvidence v2.1: 9596 bytes fixos, hash BLAKE3, buffer circular, detecção de adulteração
- Orquestrador Gatekeeper: pipeline multietapa (validadores → estatísticas → desofuscador → finalização)
- Ponte FFI PyO3/Maturin: Rust↔Python no processo (sem serialização de rede)
- Ferramenta CLI (`btv`): comandos básicos de varredura e validação
- 60+ testes passando (unitários Rust + unitários Python)

### O que falta

- **BiasDeclaration ainda não populada:** Estrutura existe em TechnicalEvidence, mas validadores retornam valores padrão. ADR-010 trata disso (meta v1.5.0).
- **Governança Python ainda não integrada:** EthicalContextEngine documentado, mas aguardando ciclo de implementação v1.8.0.
- **Sem observabilidade:** Prometheus/Grafana planejados para v1.9.0.
- **Sem API REST em produção:** Rotas FastAPI documentadas, não implantadas. Gateway Axum em v1.9.0.
- **Apelações em memória:** Produção precisa de armazenamento persistente.
- **Assinaturas HMAC simétricas:** Precisa de PKI para auditoria pública (HMAC requer segredo compartilhado).
- **Sem detecção por ML:** Validadores são baseados em regras. Padrões ofuscados podem escapar.
- **Foco em PII brasileiro:** Apenas validadores CPF/CNPJ. PII internacional requer novos módulos.

### Limitações conhecidas

1. **Taxa de falso positivo ~15%** em testes adversariais (70 amostras). Não validado externamente.
2. **Buffer circular descarta findings antigos** após > 10 findings normais. Findings críticos (máx. 3) sempre preservados.
3. **Decodificador leetspeak cobre apenas substituições comuns.** Variantes regionais e homógrafos Unicode não cobertos (FNR ~12%).
4. **Benchmarks feitos em ambiente de desenvolvimento.** Latência em produção depende de carga e I/O.

---

## Instalação

### Pré-requisitos

- Rust 1.75+ (stable)
- Python 3.10+
- (Opcional) Docker para desenvolvimento em contêiner

### Kernel Rust
```bash
cd rust
cargo build --release
cargo test --workspace
cargo clippy --workspace -- -D warnings

# Benchmarks
cd kernel && cargo bench
```

### Governança Python
```bash
cd python
pip install -e ".[dev]"
pytest tests/ -v

# Checagem de tipos
mypy buildtovalue/ --strict
```

### Ponte FFI (Rust → Python)
```bash
cd rust/bindings
maturin develop --release

# Verifique
python -c "import buildtovalue_governance; print(buildtovalue_governance.version())"
```

### Build completo
```bash
make install   # Deps Python + FFI Rust
make test      # Testes Rust + Python
make build     # Build release Rust
```

---

## Desenvolvimento com Esquadrão de IA

Este projeto usa um fluxo de trabalho estruturado com múltiplas IAs. Cada feature segue:
```
Humano (define requisito)
  → Arquiteto IA (gera ADR + traits Rust + contratos)
  → Dev IA Rust/Python (implementa conforme especificado)
  → Revisor IA (valida contra ADR + checklists)
  → Humano (integra, compila, atualiza PROJECT_CONTEXT.md)
```

Principais artefatos:

- `docs/PROJECT_CONTEXT.md` — Contexto completo colado em toda sessão de IA
- `docs/HANDOFF_TEMPLATES.md` — Formatos padronizados de handoff entre papéis de IA
- `docs/adrs/` — Registros de Decisão de Arquitetura com justificativa filosófica

Regras: máximo 3 iterações Dev↔Revisor por feature. Compilar localmente antes de revisar. Atualizar PROJECT_CONTEXT.md após cada ciclo de revisão.

Veja a [documentação do fluxo do Esquadrão de IA](docs/PROJECT_CONTEXT.md) para prompts e templates.

---

## Roadmap

### v1.5.0 ← Foco atual (18 fev – 12 abr 2026)

- [ ] Refatoração TechnicalEvidence v2.1 + exigência de BiasDeclaration (ADR-010)
- [ ] BatchProcessor (timeout 10ms, serialização Protobuf)
- [ ] DurableLedger (WAL + recuperação < 5s)
- [ ] 60+ testes (éticos + técnicos)
- [ ] Benchmarks: kernel < 30ms p99

### v1.6.0 — Política & Saída

- [ ] PolicyEngine (YAML → runtime, bloqueios duros phf)
- [ ] OutputGuard (mascaramento de PII em respostas de agentes)
- [ ] Desofuscador v2 (encadeamento: base64 → hex → leet, máx. 3 camadas)

### v1.7.0 — Contexto

- [ ] IpClassifier (detecção Tor, VPN, datacenter)
- [ ] SessionDriftDetector (similaridade cosseno comportamental)
- [ ] Interceptor (hooks pré/pós requisição)
- [ ] Testes contextuais: mesmo input, perfis diferentes → ações diferentes

### v1.8.0 — Governança

- [ ] EthicalContextEngine (Rawls + Levinas + Jonas + Gilligan)
- [ ] MercyCalculator (6 cenários calibrados)
- [ ] ContestabilityLoop (submissão, status, resolução de apelações)
- [ ] explain_decision() + HMAC-SHA256 em todos os vereditos

### v1.9.0 — API & Observabilidade

- [ ] Gateway Axum (substitui FastAPI para HTTP)
- [ ] Métricas Prometheus + tracing distribuído
- [ ] API PolicyTester (revisão cega)

### v2.0.0 — Inteligência & Compliance

- [ ] Hub de Inteligência (integração MISP/STIX)
- [ ] Tradutor de Compliance (regulamentos PDF → políticas YAML via LLM)
- [ ] Dashboard MVP Streamlit

### Open Source (Q3 2027)

- [ ] Lançamento público Apache 2.0
- [ ] 100+ estrelas, 10+ contribuidores, 5+ estudos de caso

### Linux Foundation (Q4 2027)

- [ ] Submissão ao LF AI & Data Sandbox
- [ ] 3+ organizações co-submissoras

---

## Contribuindo

Aceitamos contribuições, especialmente:

- **Validadores para outras jurisdições** (SSN dos EUA, NHS do Reino Unido, VAT da UE, etc.)
- **Auditorias externas de BiasDeclaration** (validar nossas alegações de FPR/FNR)
- **Verificação formal de políticas** (TLA+, Alloy, etc.)
- **Guias de implantação em produção** (Kubernetes, observabilidade)
- **Traduções** da documentação e templates de política

**Código de Conduta:** Seja respeitoso. Critique o código, não as pessoas. Admita erros abertamente (nós fazemos).

**Requisito de testes:** Todo PR deve incluir testes. Cobertura não pode diminuir. Zero `.unwrap()` em código de biblioteca.

---

## Licença

**Apache 2.0 (Modelo Open Core)**

- **Kernel (Rust):** Gratuito e aberto (Apache 2.0)
- **Governança (Python):** Gratuito e aberto (Apache 2.0)
- **Recursos empresariais (futuro):** Licença paga (UI multi-tenant, cloud gerenciado, garantias de SLA)

**Filosofia:** Segurança não é paywall. A lógica central de governança permanece livre.

---

## Citações & Agradecimentos

**Fundamentos filosóficos:**

- Rawls, J. (1971). *Uma Teoria da Justiça*. Harvard University Press.
- Levinas, E. (1961). *Totalidade e Infinito*. Duquesne University Press.
- Gilligan, C. (1982). *Uma Voz Diferente*. Harvard University Press.
- Jonas, H. (1984). *O Princípio Responsabilidade*. University of Chicago Press.

**Referências técnicas (orientação, não certificação):**

- NIST Cybersecurity Framework / NIST AI RMF
- OWASP ASVS 4.0
- ISO 42001 (sistema de gestão de IA)
- EU AI Act (Art. 13: Transparência)
- LGPD (Art. 20: Direito à explicação)

**Equipe:**

- Daniel Camargo — Tech Lead, Arquiteto
- Comitê Ético — Revisão de políticas
- Testadores iniciais — Validação adversarial

**Estamos sobre os ombros de gigantes.** Quaisquer erros são de nossa responsabilidade.

---

## Contato

- **Issues:** [GitHub Issues](https://github.com/buildtovalue/sovereign-trust-os/issues)
- **Vulnerabilidades de segurança:** security@buildtovalue.com (chave PGP no repositório)
- **Dúvidas gerais:** contact@buildtovalue.com

**Tempo de resposta:** Melhor esforço. Este é um projeto de pesquisa, não um produto comercial (ainda).

---

## Aviso

BuildToValue é software experimental fornecido “no estado em que se encontra”, sem qualquer garantia. Não utilize em sistemas de produção sem testes e revisão de segurança aprofundados.

**Em especial:**

- Falsos positivos são inevitáveis (medimos ~15%, mas seus dados podem variar)
- Apelações exigem revisão humana (SLA de 24h é aspiracional, não garantido)
- Benchmarks são de ambiente de desenvolvimento, não de produção
- Valores de BiasDeclaration são auto-relatados, não auditados externamente

**Se você implantar este software, assume responsabilidade pelos resultados.** Fornecemos ferramentas, não garantias.

---

**Construído com filosofia, implementado com cuidado, reconhecido com humildade.**

*Versão 3.0 — Fevereiro de 2026*

---