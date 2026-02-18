# ADR-0000: Architecture Decision Record Index

**Status:** 🟢 ATIVO (Documento Vivo)
**Última Atualização:** 09 de fevereiro de 2026
**Escopo:** BuildToValue v1.0 → v3.0

## 📖 Como usar este Índice

Este catálogo documenta todas as decisões arquiteturais significativas (ADRs) tomadas no projeto.

* **Status:** ✅ Ativo (Vigente), 🚧 Em Implementação, 🔒 Planejado (Futuro), ⛔ Obsoleto (Histórico).
* **Versão:** Indica em qual release a decisão foi ou será implementada.

---

## 🏗️ Grupo A: Fundamentos Arquiteturais (Core)

*Decisões estruturais que definem "o que é" o sistema.*

| ID | Título | Status | Versão | Link | Resumo |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **0001** | **Hybrid Architecture** | ✅ Ativo | v1.0 | [Ver Detalhes](./0001-hybrid-architecture.md) | Rust (Fatos) + Python (Valores). Ponte via PyO3. |
| **0002** | **Evidence Protocol v1.0** | ⛔ Obsoleto | v1.0 | [Ver Detalhes](./0002-evidence-protocol-v1-obsolete.md) | Tentativa inicial com heap allocation (falhou). |
| **0003** | **Mercy Algorithm** | ✅ Ativo | v1.0 | [Ver Detalhes](./0003-mercy-algorithm.md) | Lógica de Gilligan: Contexto > Regra Rígida. |
| **0004** | **Immutable Ledger** | ✅ Ativo | v1.0 | [Ver Detalhes](./0004-immutable-ledger.md) | BLAKE3 Chain. Inclui Remote Sync (S3) na v1.5. |
| **0005** | **Evidence Protocol v2.1** | ✅ Ativo | v1.5 | [Ver Detalhes](./0005-evidence-protocol-v2-fixed-size.md) | Struct fixo de 9596 bytes. Zero-heap no hot path. |
| **0006** | **Policy-as-Code** | ✅ Ativo | v1.0 | [Ver Detalhes](./0006-policy-as-code.md) | Configuração via YAML versionado e hierárquico. |
| **0007** | **Trust Score Algorithm** | ✅ Ativo | v2.0 | [Ver Detalhes](./0007-trust-score-algorithm.md) | Algoritmo multifatorial de confiança (Histórico/Decay). |
| **0008** | **Timing Mitigation** | ✅ Ativo | v1.0 | [Ver Detalhes](./0008-side-channel-timing-mitigation.md) | Validadores Constant-Time e proteção contra side-channels. |
| **0009** | **Modular Monolith** | ✅ Ativo | v3.0 | [Ver Detalhes](./0009-modular-monolith-pivot.md) | Unificação em Workspace único. Sem microserviços. |

---

## 🧠 Grupo B: Governança & Transparência (v1.5 - v1.8)

*Decisões sobre ética, explicabilidade e confiança.*

| ID | Título | Status | Versão | Link | Resumo |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **0010** | **Bias Declaration Mandate** | 🚧 Impl. | v1.5 | [Ver Detalhes](./0010-bias-declaration-mandate.md) | Todo validador deve declarar FPR/FNR (Jonas). |
| **0016** | **Ethical Context Engine v4** | 🔒 Futuro | v1.8 | [Ver Detalhes](./0016-ethical-context-engine-v4.md) | Pipeline ético completo (Rawls→Levinas→Jonas→Gilligan). |

---

## 🛡️ Grupo C: Segurança & Detecção Avançada (v1.6 - v1.7)

*Decisões para combater evasão, ataques e vazamento de dados.*

| ID | Título | Status | Versão | Link | Resumo |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **0011** | **Policy Engine Design** | 🔒 Futuro | v1.6 | [Ver Detalhes](./0011-policy-engine.md) | Compilação de YAML para Runtime Rust (phf). |
| **0012** | **Output Guard** | 🔒 Futuro | v1.6 | [Ver Detalhes](./0012-output-guard.md) | Sanitização de PII nas respostas da IA. |
| **0013** | **Deobfuscator Chain v2** | 🔒 Futuro | v1.6 | [Ver Detalhes](./0013-deobfuscator-chaining-v2.md) | Loop de decodificação (max 3 níveis) anti-evasão. |
| **0014** | **IP & Session Drift** | 🔒 Futuro | v1.7 | [Ver Detalhes](./0014-ip-classifier-session-drift.md) | Detecção de anomalias de rede e comportamento. |
| **0015** | **Interceptor Hooks** | 🔒 Futuro | v1.7 | [Ver Detalhes](./0015-interceptor-hooks.md) | Hooks de pré/pós processamento customizáveis. |

---

## 🔮 Grupo D: Visão de Longo Prazo (Pós-v2.0)

*Decisões mapeadas mas ainda sem ADR formal detalhado.*

| ID | Título | Status | Alvo | Resumo |
| :--- | :--- | :---: | :---: | :--- |
| **---** | **Local SLM Inference** | 🔮 Visão | v2.0+ | Phi-4 Mini local via `btv-slm` (mmap, CPU-only). |
| **---** | **Angular Dashboard** | 🔮 Visão | v2.0+ | Interface Enterprise para gestão de políticas. |
| **---** | **NATS JetStream** | 🔮 Visão | v1.9+ | Logs duráveis e mensageria assíncrona. |

---

## 🏛️ Grupo E: Governance (v1.8)

| ID | Título | Status | Versão | Link | Resumo |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **0017** | **Contestability Loop** | ✅ Ativo | v1.8 | [Ver Detalhes](./0017-contestability-loop.md) | Appeals HTTP: submit, status, resolve. SLA 24h. Levinas. |

---

## 🌐 Grupo F: API & Observability (v1.9)

| ID | Título | Status | Versão | Link | Resumo |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **0018** | **Axum Gateway** | ✅ Ativo | v1.9 | [Ver Detalhes](./0018-axum-gateway.md) | Gateway HTTP Rust. Orquestra kernel + governance. |
| **0019** | **Observability** | ✅ Ativo | v1.9 | [Ver Detalhes](./0019-observability.md) | Prometheus + Grafana. 7 famílias de métricas. |

---

## 🧠 Grupo G: Intelligence & Compliance (v2.0)

| ID       | Título                                    | Status | Versão | Link | Resumo |
|:---------|:------------------------------------------| :---: | :---: | :--- | :--- |
| **0020** | **Intelligence Hub**                      | ✅ Ativo | v2.0 | [Ver Detalhes](./0020-intelligence-hub.md) | Threat feed MISP/STIX. SQLite + BLAKE2b. |
| **0021** | **Compliance Plugins**                    | ✅ Ativo | v2.0 | [Ver Detalhes](./0021-compliance-plugins.md) | Plugin architecture. LGPD + EU AI Act. |
| **0022** | **Streamlit Dashboard**                   | ✅ Ativo | v2.0 | [Ver Detalhes](./0022-streamlit-dashboard.md) | MVP visual. 6 pages. Democratiza acesso. |
| **0023** | **Expose ContestabilityLoop as HTTP API** | ✅ Ativo | v2.0 | [Ver Detalhes](./0023-appeals-http-endpoint.md) |  |
| **0024** | **Threat→Policy Bridge**                  | ✅ Ativo | v2.0 | [Ver Detalhes](./0024-threat-policy-bridge) |  |

### 📝 Legenda de Status

* ✅ **Ativo:** Decisão tomada, implementada e em vigor. Código deve seguir estritamente.
* ⛔ **Obsoleto:** Decisão revogada ou substituída. Mantida apenas para histórico.
* 🚧 **Em Implementação:** Decisão aprovada, trabalho em andamento na versão atual.
* 🔒 **Planejado (Futuro):** Decisão aprovada para versões futuras. Não implementar agora, mas não bloquear.
* 🔮 **Visão:** Conceito aprovado, mas sem especificação técnica detalhada ainda.

---

> **Nota para Desenvolvedores:**
> Antes de iniciar qualquer feature, verifique se existe um ADR correspondente. Se o código desviar do ADR, o Pull Request será rejeitado. Para propor mudanças, crie um novo ADR (ex: ADR-0017) e submeta para aprovação do Staff Engineer.