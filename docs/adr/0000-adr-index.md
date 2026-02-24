# ADR-0000: Architecture Decision Record Index

**Status:** 🟢 ATIVO (Documento Vivo)
**Última Atualização:** 23 de fevereiro de 2026
**Escopo:** BuildToValue v1.0 → v3.0

---

## 📖 Como usar este Índice

Este catálogo documenta todas as decisões arquiteturais significativas (ADRs)
tomadas no projeto.

* **Status:** ✅ Ativo (Vigente), 🚧 Em Implementação, 🔒 Planejado (Futuro),
  ⛔ Obsoleto (Histórico), 🔮 Visão (sem spec detalhada ainda).
* **Versão:** Indica em qual release a decisão foi ou será implementada.

> **Nota para Desenvolvedores:**
> Antes de iniciar qualquer feature, verifique se existe um ADR correspondente.
> Se o código desviar do ADR, o Pull Request será rejeitado. Para propor
> mudanças, crie um novo ADR e submeta para aprovação do Staff Engineer.

---

## 🏗️ Grupo A: Fundamentos Arquiteturais (Core)

*Decisões estruturais que definem "o que é" o sistema.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0001** | **Hybrid Architecture** | ✅ Ativo | v1.0 | [Ver Detalhes](./0001-hybrid-architecture.md) | Rust (Fatos) + Python (Valores). Ponte via PyO3. |
| **0002** | **Evidence Protocol v1.0** | ⛔ Obsoleto | v1.0 | [Ver Detalhes](./0002-evidence-protocol-v1-obsolete.md) | Tentativa inicial com heap allocation (falhou). Substituído por ADR-0005. |
| **0003** | **Mercy Algorithm** | ✅ Ativo | v1.0 | [Ver Detalhes](./0003-mercy-algorithm.md) | Lógica de Gilligan: Contexto > Regra Rígida. mercy_score > 0.5 → EDUCATE. |
| **0004** | **Immutable Ledger** | ✅ Ativo | v1.0 | [Ver Detalhes](./0004-immutable-ledger.md) | BLAKE3 Chain multi-camada (WAL→Disk→Remote). NATS JetStream na v3.0. |
| **0005** | **Evidence Protocol v2.1** | ✅ Ativo | v1.5 | [Ver Detalhes](./0005-evidence-protocol-v2-fixed-size.md) | Struct fixo de 9596 bytes. Zero-heap no hot path. Ring buffer FIFO. |
| **0006** | **Policy-as-Code** | ✅ Ativo | v1.0 | [Ver Detalhes](./0006-policy-as-code.md) | YAML versionado com herança hierárquica. Blind Policy Testing (≥95%). |
| **0007** | **Trust Score Algorithm** | ✅ Ativo | v2.0 | [Ver Detalhes](./0007-trust-score-algorithm.md) | Algoritmo multifatorial: base + history + appeals + decay + consistency. |
| **0008** | **Timing Mitigation** | ✅ Ativo | v1.0 | [Ver Detalhes](./0008-side-channel-timing-mitigation.md) | Constant-time validators. ORAM blacklist lookup. T-test p=0.67. |
| **0009** | **Modular Monolith** | ✅ Ativo | v3.0 | [Ver Detalhes](./0009-modular-monolith-pivot.md) | Estrutura v2.2 preservada. `rust/gateway/` único crate novo (v1.9+). |

---

## 🧠 Grupo B: Governança & Transparência (v1.5 – v1.8)

*Decisões sobre ética, explicabilidade e confiança.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0010** | **Bias Declaration Mandate** | 🚧 Impl. | v1.5 | [Ver Detalhes](./0010-bias-declaration-mandate.md) | Todo `Validator` deve declarar FPR/FNR (Jonas). `bias_declaration()` obrigatório no trait. |
| **0016** | **Ethical Context Engine v4** | 🔒 Futuro | v1.8 | [Ver Detalhes](./0016-ethical-context-engine-v4.md) | Pipeline ético completo (Rawls→Levinas→Jonas→Gilligan). `explain_decision()` obrigatório. |
| **0036** | **Red-team Formal e Bias Guardian** | 🔒 Planejado | v1.7.0 | [Ver Detalhes](./0036-redteam-bias-guardian.md) | Protocolo formal de red-team com cadência CI obrigatória. `BiasGuardian` Python verifica divergência FPR/FNR declarado vs medido. Thresholds: warning 5pp / block 15pp (FNR). Fecha loop de ADR-010. |
| **0038** | **EthicalContextEngine v4.0 — Pipeline Filosófico Explícito** | 🔒 Planejado | v1.8.0 | [Ver Detalhes](./0038-ethical-context-engine-v4.md) | 4 estágios nomeados: Rawls→Levinas→Jonas→Gilligan. `ExplainDecision` estruturado (EU AI Act Art. 13). `pipeline_trace` auditável. Integração AppealEngine. Substitui esboço ADR-016. |
| **0039** | **TrustScoreCalculator v2.0** | 🔒 Planejado | v1.8.0 | [Ver Detalhes](./0039-trust-score-calculator-v2.md) | Fórmula 5 componentes (ADR-007) com TrustStore Protocol (InMemory\|SQLite\|Redis-ready). Fix decay overflow. `adjust()` para AppealEngine (+0.1/−0.05). `TrustExplain` estruturado. Substitui esboço ADR-007. |


---

## 🛡️ Grupo C: Segurança & Detecção Avançada (v1.6 – v2.2)

*Decisões para combater evasão, ataques e vazamento de dados.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0011** | **Policy Engine Design** | 🔒 Futuro | v1.6 | [Ver Detalhes](./0011-policy-engine.md) | Compilação de YAML para Runtime Rust (phf). Lookup O(1) para Hard Blocks. |
| **0012** | **Output Guard** | 🔒 Futuro | v1.6 | [Ver Detalhes](./0012-output-guard.md) | Sanitização de PII nas respostas da IA antes de entregar ao usuário. |
| **0013** | **Deobfuscator Chain v2** | 🔒 Futuro | v1.6 | [Ver Detalhes](./0013-deobfuscator-chaining-v2.md) | Loop de decodificação (max 3 níveis) anti-evasão. CRITICAL_RISK após 3 tentativas. |
| **0014** | **IP & Session Drift** | 🔒 Futuro | v1.7 | [Ver Detalhes](./0014-ip-classifier-session-drift.md) | Classificação de origem (Tor/VPN). Cosseno de similaridade → IdentityChallenge. |
| **0015** | **Interceptor Hooks** | 🔒 Futuro | v1.7 | [Ver Detalhes](./0015-interceptor-hooks.md) | Traits `RequestInterceptor`/`ResponseInterceptor`. Chain of Responsibility + fail-secure. |
| **0028** | **Heuristic Prompt Injection Detector** | ✅ Ativo | v2.2 | [Ver Detalhes](./0028-heuristic-prompt-injection-detector.md) | Detecção heurística de prompt injection sem ML. Padrões PTBR + EN. Integra Gate 3 de RAG. |

---

## 🔮 Grupo D: Visão de Longo Prazo

*Conceitos aprovados sem especificação técnica detalhada ou com ADR formal em andamento.*

| ID | Título | Status | Alvo | Resumo |
|:---|:---|:---:|:---:|:---|
| **0027** | **Local SLM Strategy** | 🔒 Futuro | v2.1 | Phi-4 Mini local via `btv-slm` (mmap, CPU-only). ADR formal criado. Ver Grupo I. |
| **---** | **Angular Dashboard** | 🔮 Visão | v3.0+ | Interface Enterprise para gestão de políticas e contestabilidade. |
| **---** | **NATS JetStream** | 🔮 Visão | v1.9+ | Logs duráveis e mensageria assíncrona. Alternativa ao S3 (ver ADR-004 Emenda v3.0). |

---

## 🏛️ Grupo E: Governance (v1.8)

*Contestabilidade, appeals e ciclo de feedback ético.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0017** | **Contestability Loop** | ✅ Ativo | v1.8 | [Ver Detalhes](./0017-contestability-loop.md) | Appeals HTTP: submit, status, resolve. SLA 24h. Levinas. Trust score feedback. |
| **0037** | **Contestability Loop — AppealEngine v2.0 + SLA 24h Enforcement** | 🔒 Planejado | v1.8.0 | [Ver Detalhes](./0037-contestability-loop-appeal-engine.md) | Judiciário de segundo grau. HMAC verify antes de aceitar appeal. SLAMonitor worker ativo (Jonas). Trust bidirecional: +0.1 aceito / −0.05 rejeitado (Gilligan). Toda appeal no Ledger. Substitui esboço ADR-017. |
---

## 🌐 Grupo F: API & Observability (v1.9 – v2.0)

*Gateway, métricas, endpoints públicos e notificações.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0018** | **Axum Gateway** | ✅ Ativo | v1.9 | [Ver Detalhes](./0018-axum-gateway.md) | Gateway HTTP Rust. Orquestra kernel + governance. Latência 6–18ms observada. |
| **0019** | **Observability** | ✅ Ativo | v1.9 | [Ver Detalhes](./0019-observability.md) | Prometheus + Grafana. 7 famílias de métricas. Scrape 5s. |
| **0023** | **Appeals HTTP Endpoint** | ✅ Ativo | v2.0 | [Ver Detalhes](./0023-appeals-http-endpoint.md) | Expõe ContestabilityLoop via 5 endpoints REST. LGPD Art. 20 + EU AI Act Art. 86. |
| **0025** | **Ledger Query API** | ✅ Ativo | v2.1 | [Ver Detalhes](./0025-ledger-query-api.md) | API de consulta ao DurableLedger por `evidence_id`, janela temporal e `agent_id`. |
| **0026** | **Webhook Notifications** | 🔒 Futuro | v2.1 | [Ver Detalhes](./0026-webhook-notifications.md) | Notificações push para eventos de BLOCK, appeal e deploy. Payload HMAC-assinado. |
| **0040** | **Axum Gateway v2.0 — Extensões República Algorítmica** | 🔒 Planejado | v1.9.0 | [Ver Detalhes](./0040-axum-gateway-v2-extensions.md) | +3 rotas: /v1/decide, /v1/appeals (proxy), /health/bias. Rate limit per-tenant (BLAKE3 hash). X-BTV-Jurisdiction → jurisdiction_bitmask. Estende ADR-018. |
| **0041** | **Observability v2.0 — Métricas da República Algorítmica** | 🔒 Planejado | v1.9.0 | [Ver Detalhes](./0041-observability-v2-republic-metrics.md) | +17 métricas: pipeline filosófico por estágio, SLA compliance rate, BiasDeclaration divergência em tempo real, mercy scenarios. 5 alerting rules. Dashboard Grafana 4 poderes. Estende ADR-019. |


---

## 🧠 Grupo G: Intelligence & Compliance (v2.0 – v2.1)

*Inteligência de ameaças, plugins de compliance e dashboards.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0020** | **Intelligence Hub** | ✅ Ativo | v2.0 | [Ver Detalhes](./0020-intelligence-hub.md) | Threat feed MISP/STIX. SQLite + BLAKE2b. Endpoints ingest/query/stats. |
| **0021** | **Compliance Plugins** | ✅ Ativo | v2.0 | [Ver Detalhes](./0021-compliance-plugins.md) | Plugin architecture. LGPD (Art. 6, 18, 20, 46, 48) + EU AI Act (Art. 5, 9, 13, 14, 15). |
| **0022** | **Streamlit Dashboard** | ✅ Ativo | v2.0 | [Ver Detalhes](./0022-streamlit-dashboard.md) | MVP visual. 6 pages. Democratiza acesso. Angular Enterprise planejado para v3.0+. |
| **0024** | **Threat→Policy Bridge** | ✅ Ativo | v2.1 | [Ver Detalhes](./0024-threat-policy-bridge.md) | MispIngestor→ThreatClassifier→PolicyGenerator. `enabled: false` + human-in-the-loop obrigatório. |

---

## 🤖 Grupo H: Local Intelligence (v2.1)

*Inferência local com modelos de linguagem leves, sem dependência de vendor.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0027** | **Local SLM Strategy** | 🔒 Futuro | v2.1 | [Ver Detalhes](./0027-local-slm-strategy.md) | Phi-4 Mini via `btv-slm` (mmap, CPU-only, zero GPU). Contexto de governança local sem vendor. Alternativa soberana ao vendor externo. |

---

## 🔗 Grupo I: Integrações de Agentes IA (v2.0+)

*Contratos e perfis para integração de agentes externos com o BTV como PDP.*
*Leia ADR-0029 (contrato canônico) antes de ler qualquer perfil de integração.*

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0029** | **External Agent PDP** | 🔒 Proposto | v2.0 | [Ver Detalhes](./0029-external-agent-pdp.md) | Contrato canônico para qualquer agente externo usar o BTV como Policy Decision Point. `AgentDecisionRequest` / `VerdictEnvelope` / `ActionImpact`. Base de todos os perfis de integração. |
| **0030** | **Chatbot — LLM Self-Hosted** | 🔒 Proposto | v2.0 | [Ver Detalhes](./0030-internal-chatbot-selfhosted-llm.md) | Perfil de integração BTV para chatbot com Llama 70B/vLLM. 5 gates: mensagem, indexação, RAG, training batch, LoRA deploy (`Irreversible`). Evidence LGPD. BiasDeclaration em treino. |
| **0031** | **Chatbot — LLM Vendor Externo** | 🔒 Proposto | v2.0 | [Ver Detalhes](./0031-external-chatbot-vendor-llm.md) | Delta do ADR-0030 para vendors externos (OpenAI, Anthropic, Google, Azure). Toda mensagem é `Irreversible`. `/v1/sanitize` obrigatório antes de cada envio. Gate de aprovação de vendor por `sector_id`. LGPD Art. 33. |


### Grupo J: v1.6 — Multilingual & Multi-tenant Foundation (ADR-0032 a ADR-0036)

| ID | Título | Status | Versão | Link | Resumo |
|:---|:---|:---:|:---:|:---|:---|
| **0032** | **ScanContextFlags** | 🚧 Impl. | v1.6.0 | [Ver Detalhes](./0032-scan-context-flags.md) | Substitui `_reserved: [u8; 64]` por struct nomeado de 64 bytes exatos. Fundação para language detection, jurisdição, capability mask e multi-tenant. |
| **0033** | **PatternRegistry (Tier 0/1/2)** | 🔒 Planejado | v1.6.0 | [Ver Detalhes](./0033-pattern-registry-tiers.md) | Substitui lazy_static por 3 tiers: Tier 0 hardcoded, Tier 1 build-time YAML, Tier 2 runtime ArcSwap. Epoch versionado para auditoria forense. |
| **0034** | **Language Detection Strategy** | 🔒 Planejado | v1.6.1 | [Ver Detalhes](./0034-language-detection-strategy.md) | whatlang-rs no Stage 1 do pipeline. Preenche `lang_bitmask` e `lang_scores` em ScanContextFlags. Threshold 0.75 + min 20 chars. Inputs ambíguos → undetermined → apenas Tier 0. |
| **0035** | **Multi-jurisdiction PII Validators** | 🔒 Planejado | v1.7.0 | [Ver Detalhes](./0035-multi-jurisdiction-pii-validators.md) | NHS Number (Mod 11), EU VAT (DE/FR/IT/ES/PT), IBAN (Mod 97). Dispatcher por `jurisdiction_bitmask`. Novos `ValidatorModule` entries. |

---

## 📐 Mapa de Dependências entre ADRs

```
ADR-0001 (Hybrid)
  └─► ADR-0005 (Evidence v2.1) ──► ADR-0010 (BiasDeclaration)
  └─► ADR-0009 (Monolito)     ──► ADR-0018 (Axum Gateway)
                                        └─► ADR-0019 (Observability)
                                        └─► ADR-0023 (Appeals HTTP)
                                        └─► ADR-0025 (Ledger Query)
                                        └─► ADR-0026 (Webhooks)

ADR-0004 (Ledger) ──► ADR-0025 (Ledger Query)
                  ──► ADR-0029/0030/0031 (evidence_id forense)

ADR-0006 (Policy-as-Code)
  └─► ADR-0011 (Policy Engine)
  └─► ADR-0024 (Threat→Policy Bridge)
  └─► ADR-0029/0030/0031 (YAML por sector_id)

ADR-0017 (Contestability)
  └─► ADR-0023 (Appeals HTTP)
  └─► ADR-0029/0030/0031 (contestable: true, SLA 24h)

ADR-0020 (Intelligence Hub)
  └─► ADR-0024 (Threat→Policy Bridge)
  └─► ADR-0028 (Heuristic Detector — padrões do feed)

ADR-0028 (Heuristic Detector)
  └─► ADR-0029 (Gate 3 RAG — anti-injection)
  └─► ADR-0030 (Gate 3 RAG interno)
  └─► ADR-0031 (Gate 4 RAG externo — padrões adicionais PTBR)

ADR-0029 (External Agent PDP — contrato canônico)
  └─► ADR-0030 (Chatbot LLM Interna)
  └─► ADR-0031 (Chatbot LLM Externa)
```

---

## 📁 Arquivos de Integração Associados

Os ADRs do Grupo I possuem documentos de referência de implementação
em `docs/integrations/` (perfis prontos para copy-paste):

| Perfil | ADR | Arquivo | Descrição |
|:---|:---:|:---|:---|
| Chatbot LLM Interna | 0030 | `docs/integrations/chatbot-internal-llm.md` | Implementação completa dos 5 gates, Angular + Rust + Python, Docker Compose dev, políticas YAML. |
| Chatbot LLM Externa | 0031 | `docs/integrations/chatbot-external-llm.md` | Delta completo: 4 gates, catálogo de vendors, políticas por sector_id, evidência LGPD Art. 33. |

---

## 📋 Políticas YAML Versionadas por Perfil

| Arquivo | ADR | Finalidade |
|:---|:---:|:---|
| `data/policies/base.yaml` | 0006 | Regras raiz — herança global |
| `data/policies/general.yaml` | 0006 | Perfil geral (agentes sem sector_id) |
| `data/policies/medical-agent.yaml` | 0006 | Override para setor saúde |
| `data/policies/auto-generated/` | 0024 | Policies geradas pelo Threat→Policy Bridge (todas `enabled: false`) |
| `data/policies/chatbot-internal-message.yaml` | 0030 | Mensagens com PII/CONFIDENTIAL no chatbot interno |
| `data/policies/chatbot-rag-injection.yaml` | 0030 | Anti-injection nos chunks RAG (chatbot interno) |
| `data/policies/chatbot-lora-deploy.yaml` | 0030 | Threshold de qualidade para deploy de LoRA |
| `data/policies/chatbot-lora-deploy-health.yaml` | 0030 | Override para sector_id: health (refusal ≥ 90%) |
| `data/policies/chatbot-vendor-approval.yaml` | 0031 | Quais vendors são aprovados por sector_id |
| `data/policies/chatbot-vendor-send.yaml` | 0031 | Regras por mensagem enviada a vendor externo |
| `data/policies/chatbot-vendor-response.yaml` | 0031 | Padrões de exfiltração na resposta do vendor |
| `data/policies/chatbot-rag-external.yaml` | 0031 | Anti-injection para RAG em prompts externos |

---

## 📝 Legenda de Status

| Símbolo | Significado |
|:---:|:---|
| ✅ | **Ativo:** Decisão tomada, implementada e em vigor. Código deve seguir estritamente. |
| ⛔ | **Obsoleto:** Decisão revogada ou substituída. Mantida apenas para histórico. |
| 🚧 | **Em Implementação:** Decisão aprovada, trabalho em andamento na versão atual. |
| 🔒 | **Planejado / Proposto:** Aprovado para versão futura ou proposto aguardando implementação. Não implementar agora, mas não bloquear. |
| 🔮 | **Visão:** Conceito aprovado, sem especificação técnica detalhada ainda. |

---

## 📊 Estatísticas do Índice

| Métrica | Valor |
|:---|:---:|
| Total de ADRs | 29 |
| ✅ Ativos | 16 |
| 🚧 Em Implementação | 1 |
| 🔒 Planejados / Propostos | 10 |
| ⛔ Obsoletos | 1 |
| 🔮 Visão (sem ADR formal) | 2 |
| Última entrada | ADR-0031 |
| Próximo disponível | ADR-0032 |


***

## O que foi atualizado

| Seção | Mudança |
|:---|:---|
| **Cabeçalho** | Data atualizada para 23/02/2026 |
| **0023** | Resumo preenchido (estava vazio) |
| **0024** | Resumo preenchido (estava vazio); versão corrigida para v2.1 |
| **Grupo C** | Adicionado ADR-0028 (Heuristic Prompt Injection Detector) |
| **Grupo D** | ADR-0027 (Local SLM) promovido de Visão `---` para entrada com ID, mantido como 🔒 Futuro |
| **Grupo F** | Adicionados ADR-0025 (Ledger Query API) e ADR-0026 (Webhook Notifications) |
| **Grupo H** | Novo grupo: Local Intelligence com ADR-0027 formal |
| **Grupo I** | Novo grupo: Integrações de Agentes IA — ADR-0029, 0030, 0031 |
| **Mapa de dependências** | Novo — rastreia relações entre ADRs |
| **Perfis de integração** | Nova seção — mapeia docs/integrations/ para ADRs |
| **Políticas YAML** | Nova seção — mapeia data/policies/ para ADRs responsáveis |
| **Estatísticas** | Nova seção — totais rápidos para onboarding |
