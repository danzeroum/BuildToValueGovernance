# Arquitetura Completa — BuildToValueGovernance

> **Documento de arquitetura de todo o repositório** em modelo **C4** (Contexto → Contêiner → Componente → Código) mais **vistas transversais** (fluxos de dados, máquinas de estado, segurança, persistência, implantação e CI/CD).
> Todos os elementos foram extraídos por **análise estática direta do código-fonte deste repositório** — cada bloco cita os arquivos de origem. Diagramas em **Mermaid** (validados).
> Complementa o [Documento UML](arquitetura-uml.md) (nível de classes/sequência); aqui o foco é a **arquitetura de sistema**.

---

## Índice de vistas

| # | Vista | Nível C4 / tipo |
|---|---|---|
| 1 | [Contexto de Sistema](#1--c4-nível-1--contexto-de-sistema) | C4 L1 |
| 2 | [Contêineres](#2--c4-nível-2--contêineres) | C4 L2 |
| 3 | [Componentes por serviço](#3--c4-nível-3--componentes) | C4 L3 |
| 4 | [Fluxos de dados (DFD)](#4--fluxos-de-dados) | DFD |
| 5 | [Máquinas de estado](#5--máquinas-de-estado) | State |
| 6 | [Arquitetura de segurança](#6--arquitetura-de-segurança) | Security |
| 7 | [Arquitetura de persistência](#7--arquitetura-de-persistência) | Data |
| 8 | [Topologias de implantação](#8--topologias-de-implantação) | Deployment |
| 9 | [Pipeline de CI/CD](#9--pipeline-de-cicd) | Build |
| 10 | [Mapa de invariantes fail-secure](#10--mapa-de-invariantes-fail-secure) | Cross-cutting |
| 11 | [Rastreabilidade arquivo → componente](#11--rastreabilidade-arquivo--componente) | Índice |

**Convenção de cores C4:** 🟦 pessoa/ator · 🟩 sistema/contêiner interno · 🟨 componente · ⬜ sistema externo.

---

## 1 · C4 Nível 1 — Contexto de Sistema

**Objetivo:** situar o sistema entre seus usuários e sistemas externos.

**Escopo:** todo o repositório visto como uma caixa-preta.

```mermaid
flowchart TB
    subgraph people["Pessoas"]
        dev["👤 Dev / Integrador<br/>«pessoa»"]
        dpo["👤 DPO / Compliance<br/>«pessoa»"]
        auditor["👤 Auditor / Regulador<br/>«pessoa»"]
        subject["👤 Titular de Dados<br/>«pessoa»"]
        sre["👤 Operador / SRE<br/>«pessoa»"]
    end

    btv["🟩 BuildToValueGovernance<br/>Governança de agentes de IA com<br/>evidência criptográfica imutável<br/>(fail-secure, contestável em 24h)"]

    subgraph ext["Sistemas Externos"]
        agent["🤖 Agente de IA<br/>(LangChain/CrewAI/AutoGen/…)"]
        llm["☁️ LLM Upstream<br/>(OpenAI-compat / Anthropic)"]
        misp["🛰️ Feeds de Threat-Intel<br/>(MISP)"]
        obs["📊 Prometheus / Grafana"]
        idp["🔑 Fonte de segredos<br/>(.env / Secret k8s)"]
    end

    dev -->|integra SDK, define políticas| btv
    dpo -->|gera ROPA/FRIA/Art.20| btv
    auditor -->|consulta ledger e provas| btv
    subject -->|contesta decisão — appeal| btv
    sre -->|opera, observa /health /metrics| btv

    agent -->|intercepta decisão/chamada LLM| btv
    btv -->|encaminha ou bloqueia 451| llm
    misp -->|ingestão de ameaças| btv
    btv -->|expõe métricas / auditoria| obs
    idp -->|HMAC/JWT/Ed25519 keys| btv
```

**Notas de design:**
- O **agente de IA** é simultaneamente cliente e sujeito da governança — o sistema fica no caminho crítico entre o agente e o LLM.
- Todos os segredos são **injetados externamente** (`.env` / Secret k8s), nunca embarcados — pré-requisito do modelo fail-closed das chaves (`rust/kernel/src/keys.rs`, `python/buildtovalue/security/keys.py`).

---

## 2 · C4 Nível 2 — Contêineres

**Objetivo:** os processos executáveis do repositório e como se comunicam.

**Escopo:** artefatos de runtime derivados de `rust/` (12 crates), `python/`, `sdk/` e `ops/`.

```mermaid
flowchart TB
    dev["👤 Dev / Agente"]:::person
    subject["👤 Titular / Revisor"]:::person

    subgraph sys["🟩 BuildToValueGovernance"]
        direction TB
        nginx["nginx<br/>«TLS reverse proxy»<br/>ops/nginx"]:::cont
        gw["Gateway<br/>«contêiner: Rust/Axum»<br/>:8080 (+ gRPC :9090)<br/>rust/gateway"]:::cont
        kernel["Kernel<br/>«lib in-process + .so»<br/>rust/kernel + rust/bindings"]:::cont
        pyapi["API de Governança<br/>«contêiner: Python/FastAPI»<br/>:8000 · python/buildtovalue/api"]:::cont
        sigma["Σ Transparency Log<br/>«contêiner: Rust/Axum»<br/>:3100 · rust/btv-sigma"]:::cont
        republic["República Constitucional<br/>«libs Rust»<br/>btv-executive/judicial/governance/redaction"]:::cont
        dash["Dashboard<br/>«contêiner: Streamlit / React»<br/>:8501 · python/buildtovalue/dashboard"]:::cont
        mcp["MCP Server<br/>«processo stdio»<br/>sdk/mcp-server"]:::cont
        led[("Ledger imutável<br/>«volume» WAL + JSONL")]:::store
        sqlite[("SQLite<br/>trust/appeals/threats/users")]:::store
    end

    tssdk["📘 TS SDK · sdk/javascript"]:::ext
    pysdk["🐍 Py SDK · sdk/python"]:::ext
    llm["☁️ LLM Upstream"]:::ext

    dev --> tssdk & pysdk
    tssdk & pysdk -->|HTTPS X-API-Key| nginx
    subject -->|HTTPS JWT| nginx
    nginx -->|HTTP| gw
    nginx -->|HTTP| pyapi
    gw -->|link in-process| kernel
    gw -->|HTTP /v1/decide :8000| pyapi
    gw -->|HTTP proxy /v1/proxy| llm
    pyapi -->|FFI PyO3| kernel
    pyapi --> sqlite
    gw --> led
    pyapi --> led
    republic -->|POST /append| sigma
    republic -->|GET /root,/proof| sigma
    republic -.->|scan| kernel
    mcp -->|HTTP| gw
    dash -->|HTTP| gw
    gw -->|gRPC stream| obs["📊 Consumidor de auditoria"]:::ext

    classDef person fill:#08427b,color:#fff
    classDef cont fill:#1168bd,color:#fff
    classDef store fill:#2e7d32,color:#fff
    classDef ext fill:#999,color:#fff
```

**Legenda de portas:** gateway **8080** · governança **8000** · Σ **3100** · gRPC auditoria **9090** · dashboard **8501** · playground **8502** · Prometheus **9090** · Grafana **3000** · nginx TLS **8443/9443** (dev) ou **80/443** (prod).

**Notas de design:**
- **Dois caminhos ao kernel:** o gateway o linka em processo (`rust/gateway/Cargo.toml` → `buildtovalue-kernel`); a API Python o chama por FFI (`python/buildtovalue/governance/ffi_client.py`). Convergem em `Gatekeeper::scan_for_evidence`.
- A **República Constitucional** é um subsistema pura-Rust separado (Papers 5/6) que se comunica **exclusivamente através de Σ** — não importa nem chama o gateway/Python.

---

## 3 · C4 Nível 3 — Componentes

### 3.1 Componentes do Gateway (Rust)

**Escopo:** `rust/gateway/src/**`.

```mermaid
flowchart TB
    subgraph GW["🟩 Gateway (Axum :8080)"]
        direction TB
        router["create_router<br/>«controller» routes/mod.rs"]:::c
        subgraph mw["Middleware chain (routes/mod.rs)"]
            direction LR
            trace["trace_propagation<br/>W3C traceparent"]:::c
            rl["RateLimitLayer<br/>moka cache 60s"]:::c
            auth["ApiKeyLayer<br/>X-API-Key / JWT"]:::c
            tenant["TenantExtractorLayer<br/>BtvClaims→TenantId"]:::c
            trace --> rl --> auth --> tenant
        end
        subgraph routes["Rotas"]
            direction LR
            r1["validate / scan"]:::c
            r2["decide"]:::c
            r3["proxy /*"]:::c
            r4["sanitize / guard"]:::c
            r5["appeals /*"]:::c
            r6["trust / health / metrics"]:::c
            r7["policy/test · blind_review"]:::c
            r8["internal/* (InternalAuthLayer)"]:::c
        end
        state["AppState<br/>«estado» state.rs<br/>gatekeeper, tenant_router,<br/>rawls/jonas monitors, audit_tx"]:::c
        subgraph audit["Pipeline de auditoria"]
            ev["FairnessAuditEvent"]:::c
            drn["spawn_drainer (MPSC 10k)"]:::c
            sink["AuditSink JSONL/Stdout"]:::c
            grpc["GrpcAuditExposer :9090"]:::c
            ev --> drn --> sink --> grpc
        end
    end
    kernel["kernel: Gatekeeper,<br/>PolicyEngine, SessionTracker,<br/>OutputGuard, RawlsMonitor"]:::ext
    py["Governança Python :8000"]:::ext
    llm["LLM upstream"]:::ext

    router --> mw --> routes
    routes --> state
    r1 & r2 --> kernel
    r2 --> py
    r3 --> llm
    r2 --> audit
    r8 --> state

    classDef c fill:#f4c542,color:#000
    classDef ext fill:#999,color:#fff
```

**Notas:** o gateway acumula borda de segurança + scan + proxy + auditoria; `AppState` centraliza tudo (SPOF operacional mitigado por statelessness por tenant via `TenantStorageRouter`). A auditoria é **desacoplada** por MPSC com *drop-on-full*.

### 3.2 Componentes da API de Governança (Python)

**Escopo:** `python/buildtovalue/{api,governance,compliance,intelligence,agentic,core}`.

```mermaid
flowchart TB
    subgraph PY["🟩 API de Governança (FastAPI :8000)"]
        direction TB
        app["FastAPI app + lifespan<br/>api/app.py (15 routers)"]:::c
        subgraph rt["Routers"]
            direction LR
            dr["decide / multi_decide"]:::c
            ad["agent/decide"]:::c
            ap["appeals"]:::c
            cp["compliance / compliance_eval"]:::c
            il["intelligence"]:::c
            lg["ledger / metrics"]:::c
        end
        subgraph gov["governance (~90 módulos)"]
            ece["EthicalContextEngine<br/>+ Technical/Governance Layer"]:::c
            pol["PolicyEngine · SafeExprEval"]:::c
            cl["ContestabilityLoop"]:::c
            gd["GoalDriftSentinel"]:::c
            dl["DurableLedger (py)"]:::c
        end
        subgraph other["Serviços de apoio"]
            ffi["FFIClient (PyO3)"]:::c
            slm["SLMClassifier · NERDetector"]:::c
            comp["Compliance plugins<br/>LGPD/EU-AI-Act + geradores"]:::c
            intel["ThreatPolicyBridge · LLMAsyncClient"]:::c
            gg["core.GovernanceGateway"]:::c
        end
    end
    rustkernel["kernel Rust (.so)"]:::ext

    app --> rt
    dr --> ffi --> rustkernel
    dr --> slm --> ece
    dr --> comp
    ad --> gd
    ap --> cl
    cp --> comp
    il --> intel
    ece --> pol
    gg --> ece
    gd --> dl

    classDef c fill:#f4c542,color:#000
    classDef ext fill:#999,color:#fff
```

**Notas:** todos os singletons são injetados em `app.state` no `lifespan` (ADR-0093, sem globais). O pacote `governance` é o núcleo de domínio e o principal candidato a subdivisão.

### 3.3 Componentes do Kernel (Rust)

**Escopo:** `rust/kernel/src/**` (ver detalhamento de classes no [doc UML §5.1–5.2](arquitetura-uml.md#51--rust--kernel-pipeline-de-evidência)).

```mermaid
flowchart LR
    subgraph K["🟩 buildtovalue_kernel"]
        direction TB
        gk["Gatekeeper<br/>«orquestrador»"]:::c
        subgraph pipe["Pipeline (trait Module)"]
            deob["Deobfuscate ×4"]:::c
            ana["Analyze ×4"]:::c
            val["Validate ×14"]:::c
        end
        icept["InterceptorChain<br/>ToolScreen"]:::c
        ev["TechnicalEvidence<br/>9632B repr(C)"]:::c
        subgraph ledger["ledger/"]
            dl["DurableLedger<br/>Arc<RwLock>"]:::c
            wal["WriteAheadLog"]:::c
            eff["EffectLog + FrontierSet"]:::c
            tr["TenantStorageRouter"]:::c
        end
        pol["PolicyEngine"]:::c
        keys["keys: KERNEL_MAC_KEY<br/>OnceLock+Zeroizing"]:::c
    end
    gk --> icept --> pipe
    pipe --> ev
    gk --> ev
    gk --> pol
    ev --> dl
    dl --> wal
    tr --> dl
    dl --> eff
    keys -.-> gk

    classDef c fill:#f4c542,color:#000
```

### 3.4 Componentes da República Constitucional (Rust)

**Escopo:** `rust/{btv-core,btv-executive,btv-judicial,btv-governance,btv-redaction,btv-sigma,btv-types}` (detalhe de classes no [doc UML §5.3](arquitetura-uml.md#53--rust--república-constitucional-tipos-lineares)).

```mermaid
flowchart TB
    subgraph L["🟩 Legislativo/Constituinte (btv-governance)"]
        mandate["MandateToken «linear»"]:::c
        ratif["verify_tripartite_signatures"]:::c
        cstate["ConstitutionalState"]:::c
    end
    subgraph E["🟩 Executivo (btv-executive)"]
        exec["Executive.decide()"]:::c
        dm["DecisionMaker"]:::c
        gb["GatekeeperBridge"]:::c
    end
    subgraph CORE["🟩 Tokens lineares (btv-core)"]
        etok["EvidenceToken"]:::c
        ctok["ComplianceToken"]:::c
        verd["Verdict «⊗»"]:::c
        dtok["DeliveryToken"]:::c
    end
    subgraph J["🟩 Judiciário (btv-judicial)"]
        mon["Monitor.verify()"]:::c
        hv["HmacVerifier"]:::c
        rv["ReceiptVerifier (Ed25519)"]:::c
        lq["LedgerQuery"]:::c
    end
    subgraph SIG["🟩 Σ (btv-sigma :3100)"]
        merkle["MerkleTree (SHA-256)"]:::c
        signer["LogSigner (Ed25519)"]:::c
        store["LogStore"]:::c
    end
    R["btv-redaction<br/>AccountableRedaction (ε)"]:::c
    T["btv-types (folha)<br/>wire: MerkleProof, VerdictRecord…"]:::ext

    exec --> gb & dm
    exec --> etok & ctok --> verd --> dtok
    exec -->|POST /append| SIG
    SIG --> merkle & signer & store
    mon --> hv & rv & lq
    lq -->|GET /root,/proof| SIG
    L -->|publish_mandate| SIG
    R -->|receipt| SIG
    E -.-> T
    J -.-> T
    L -.-> T
    R -.-> T
    SIG -.-> T

    classDef c fill:#f4c542,color:#000
    classDef ext fill:#2e7d32,color:#fff
```

**Notas:** invariante de CI (`crate_release_audit.yml`, `fail_secure_ci.yml`) — J/Σ/redaction **não** dependem de btv-core; governança **não** importa executivo. Comunicação entre poderes só via Σ.

### 3.5 Componentes de SDK & Integrações

**Escopo:** `sdk/**`.

```mermaid
flowchart LR
    subgraph SDKS["🟩 SDKs"]
        ts["BTVClient (TS)<br/>sdk/javascript"]:::c
        py["BTVClient / AsyncBTVClient<br/>sdk/python"]:::c
        mcpsrv["MCP Server (8 tools)<br/>sdk/mcp-server"]:::c
    end
    subgraph INTEG["🟩 Guards de framework"]
        lc["BTVGuardrailCallback (LangChain)"]:::c
        cw["BTVCrewGuard (CrewAI)"]:::c
        ag["BTVAutoGenGuard (AutoGen)"]:::c
        li["BTVQueryEngineGuard (LlamaIndex)"]:::c
        gr["GrantGuard (Grants)"]:::c
    end
    gw["Gateway :8080<br/>/v1/decide /validate /sanitize /appeals /trust"]:::ext

    ts & py -->|HTTP| gw
    mcpsrv -->|AsyncBTVClient| py
    lc & cw & ag & li & gr -->|BTVClient| py

    classDef c fill:#f4c542,color:#000
    classDef ext fill:#999,color:#fff
```

**Notas:** paridade de API entre TS e Python (mesmo mapa de endpoints, mesma hierarquia de erros, retry 2/4/8s). Guards de framework dependem só do SDK Python (baixo acoplamento). MCP expõe 5 tools proxy (`validate/decide/appeal/trust/compliance`) + 3 locais (`elicit_policy/negotiate/select_protocol`).

---

## 4 · Fluxos de dados

### 4.1 Ciclo de vida de uma decisão (proxy transparente)

**Objetivo:** o dado (prompt do agente) atravessando o sistema até ALLOW/BLOCK.

```mermaid
flowchart LR
    a["🤖 Agente<br/>prompt"] -->|OPENAI_BASE_URL| gw["Gateway<br/>/v1/proxy/*"]
    gw --> scan["Gatekeeper.scan<br/>→ TechnicalEvidence"]
    scan --> pol["PolicyEngine<br/>→ PolicyAction"]
    pol --> dec["POST :8000/v1/decide<br/>(governança Python)"]
    dec --> verdict{"action?"}
    verdict -->|ALLOW| fwd["encaminha ao<br/>LLM upstream"] --> resp["resposta + OutputGuard.mask_pii"]
    verdict -->|BLOCK/REFUSE| http451["HTTP 451<br/>+ evidência linkada"]
    scan --> led[("append_with_key<br/>Ledger (BLAKE3 chain)")]
    dec --> audit[("FairnessAuditEvent<br/>→ MPSC → JSONL")]
    resp --> a
    http451 --> a
```

### 4.2 Ciclo de vida da evidência (criação → ledger → verificação independente)

**Objetivo:** como a evidência vira prova verificável e não-repudiável.

```mermaid
flowchart LR
    inp["input"] --> new["TechnicalEvidence::new<br/>hash=0 (inválido)"]
    new --> pipe["pipeline 22 módulos<br/>+ findings/bias"]
    pipe --> fin["finalize()<br/>hash = BLAKE3 selado"]
    fin --> entry["LedgerEntry<br/>previous_hash ← cabeça"]
    entry --> chain["entry_hash = BLAKE3(...prev)<br/>merkle_root = BLAKE3(prev‖entry)<br/>verdict_id = HMAC(TEK,...)"]
    chain --> wal[("WAL fsync")]
    chain --> disk[("disco bincode")]
    chain -.->|República| sig["Σ /append<br/>Merkle + Ed25519"]
    sig --> receipt["InclusionReceipt"]
    disk --> verify["verify_chain_integrity()<br/>→ ChainStatus"]
    receipt --> jverify["btv-judicial<br/>HMAC+Ed25519+Merkle (AND)"]
```

**Nota:** WAL-first garante recuperação pós-crash (`recover()` SLA < 5 s). Adulterar qualquer registro ⇒ `ChainStatus::TamperedAt`.

### 4.3 Threat-intel → política (human-in-the-loop)

**Objetivo:** transformar ameaças externas em políticas, sem ativação automática.

```mermaid
flowchart LR
    misp["🛰️ MISP / feed"] --> ing["MispIngestor<br/>ThreatEvent"]
    ing --> db[("SQLite threats")]
    ing --> cls["ThreatClassifier<br/>→ Classification"]
    cls --> gen["PolicyGenerator<br/>→ YAML"]
    gen --> disabled["data/policies/auto-generated<br/>⚠️ nascidas DESABILITADAS"]
    disabled --> review{"revisão<br/>humana"}
    review -->|aprova| active["política ativa<br/>→ PolicyEngine / kernel"]
    review -->|rejeita| discard["descartada"]
    bridge["ThreatPolicyBridge.sync()"] -.-> cls & gen
```

### 4.4 Auditoria de fairness (não-bloqueante → stream gRPC)

```mermaid
flowchart LR
    dec["decide_handler"] --> ev["FairnessAuditEvent<br/>(UUID v7, v1alpha)"]
    ev --> emit["audit_tx.try_emit"]
    emit --> mpsc[["MPSC cap 10.000<br/>(drop-on-full + métrica)"]]
    mpsc --> drain["spawn_drainer<br/>(catch_unwind)"]
    drain --> jsonl[("{audit_dir}/{tenant}/events.jsonl")]
    jsonl --> exposer["GrpcAuditExposer :9090<br/>tail read-only"]
    exposer -->|server-stream<br/>btv.audit.v1alpha| consumer["☕ Consumidor externo<br/>(x-btv-internal-key)"]
```

---

## 5 · Máquinas de estado

### 5.1 Negociação Agente-a-Agente

**Escopo:** `python/buildtovalue/agentic/negotiation_engine.py` (`NegotiationState`).

```mermaid
stateDiagram-v2
    [*] --> IDLE
    IDLE --> PROPOSED: propose()
    PROPOSED --> COUNTERED: respond() contra-proposta
    PROPOSED --> ACCEPTED: respond() aceita
    COUNTERED --> ACCEPTED: aceita
    COUNTERED --> ABORTED: guard/drift/deadlock
    ACCEPTED --> CONFIRMED: confirmação mútua
    PROPOSED --> ABORTED: NegotiationGuard veta
    CONFIRMED --> [*]
    ABORTED --> [*]
    note right of ABORTED: toda transição<br/>assinada (HMAC) e<br/>gravada no DurableLedger
```

### 5.2 Estado constitucional / mandato

**Escopo:** `rust/btv-governance/src/{constitutional_state,mandate}.rs`.

```mermaid
stateDiagram-v2
    [*] --> Genesis: genesis()
    Genesis --> Active: mandato vivo (is_live)
    Active --> Active: renew() (SunsetPolicy, max_renewals)
    Active --> Interregnum: mandato expirou
    Interregnum --> Active: apply_amendment() com<br/>ratificação tripartite (σL∧σJ∧σErep)
    Active --> Active: PolicyUpdate (σL apenas)
    note right of Interregnum: SystemState Interregnum<br/>= sem mandato ativo
```

### 5.3 Circuit breaker do cliente LLM

**Escopo:** `python/buildtovalue/intelligence/llm_async_client.py` (`CircuitState`).

```mermaid
stateDiagram-v2
    [*] --> CLOSED
    CLOSED --> OPEN: falhas ≥ limiar
    OPEN --> HALF_OPEN: após cooldown
    HALF_OPEN --> CLOSED: sucesso
    HALF_OPEN --> OPEN: nova falha
    note right of OPEN: LLMCircuitOpenError<br/>→ LLMFallbackOrchestrator
```

### 5.4 Contestação (Appeal)

**Escopo:** `governance/contestability/_types.py` (`AppealStatus`) + `/v1/appeals`.

```mermaid
stateDiagram-v2
    [*] --> pending: POST /v1/appeals (JWT, SLA +24h)
    pending --> under_review: revisor abre
    under_review --> accepted: resolve (HITL)
    under_review --> rejected: resolve (HITL)
    pending --> expired: SLA 24h estourado
    accepted --> [*]
    rejected --> [*]
    expired --> [*]
```

### 5.5 Reversibilidade de efeito (EffectLog)

**Escopo:** `rust/kernel/src/ledger/effect_log.rs` (`Reversibility` × `EffectResult`).

```mermaid
stateDiagram-v2
    [*] --> Buffered: buffer_and_await_frontier (WAL-first)
    Buffered --> Committed: frontier confirmada (≤40ms)
    Buffered --> Abort: WalWriteFailed / FrontierTimeout / HandlerFailed / RingFull
    Committed --> [*]
    Abort --> [*]
    note right of Committed: Reversible / ReversibleWithCost / Irreversible<br/>Irreversible → escrutínio extra (LivenessMonitor)
```

---

## 6 · Arquitetura de segurança

### 6.1 Cadeia de autenticação/autorização (gateway)

**Escopo:** `rust/gateway/src/middleware/*.rs`.

```mermaid
flowchart TB
    req["Requisição HTTP"] --> pub{"rota pública?<br/>/health /metrics /v1/auth"}
    pub -->|sim| pass["segue sem auth"]
    pub -->|não| tp["trace_propagation<br/>injeta TraceContext"]
    tp --> rl{"RateLimitLayer<br/>tenant-key ou IP"}
    rl -->|excedeu| e429["429 + X-RateLimit-*"]
    rl -->|ok| ak{"ApiKeyLayer<br/>X-API-Key ∈ BTV_API_KEYS<br/>ou Bearer JWT válido"}
    ak -->|inválido| e401["401"]
    ak -->|ok| te{"TenantExtractorLayer<br/>decodifica BtvClaims"}
    te -->|sem token| deftenant["DEFAULT_TENANT_ID"]
    te -->|token ruim| e401b["401 (MED-R05)"]
    te -->|tenant inválido| e403["403 E131"]
    te -->|ok| handler["handler da rota"]
    deftenant --> handler
    subgraph internal["/internal/v1/* — sub-router isolado"]
        ia{"InternalAuthLayer<br/>constant-time (subtle)<br/>X-BTV-Internal-Key ≥32B"}
        ia -->|WrongKey| e401c["401"]
        ia -->|Disabled| e503["503"]
        ia -->|Ok| ihandler["reload-policy / evict-tenant"]
    end
```

### 6.2 Hierarquia de chaves e segredos

**Escopo:** `rust/kernel/src/keys.rs`, `python/buildtovalue/security/keys.py`, crates btv-*.

```mermaid
flowchart TB
    env[".env / Secret k8s<br/>(injeção externa)"] --> hmac["BTV_HMAC_KEY"]
    env --> jwt["BTV_JWT_SECRET"]
    env --> apik["BTV_API_KEYS"]
    env --> intk["BTV_INTERNAL_SECRET"]
    env --> logvk["BTV_LOG_VERIFYING_KEY<br/>(pubkey Σ, out-of-band)"]
    env --> polpk["BTV_POLICY_PUBKEY_PATH<br/>(Ed25519 comitê de ética)"]

    hmac --> kmac["kernel KERNEL_MAC_KEY<br/>OnceLock+Zeroizing<br/>(scrub do environ)"]
    hmac --> eseal["btv-core: Verdict.hmac_seal"]
    hmac --> jver["btv-judicial: HmacVerifier"]
    hmac --> tek["TenantKeyDeriver<br/>HKDF-SHA256 → TEK por tenant"]
    tek --> verdid["LedgerEntry.verdict_id<br/>HMAC(TEK,...)"]
    jwt --> gwjwt["gateway BtvClaims / tenant"]
    jwt --> pyjwt["API: login/refresh (bcrypt users)"]
    logvk --> recv["ReceiptVerifier / LogClient pin"]
    polpk --> polload["policy_loader.verify_policy_yaml"]
    kmac --> skill["supply_guard.verify_skill<br/>(keyed-MAC constant-time)"]
```

**Notas:** chaves **fail-closed em produção** (`keys.rs` aborta se ausente); comparações sempre **constant-time** (`subtle`, `btv_types::crypto_utils::constant_time_eq`); `BTV_HMAC_KEY` é apagado do environ após init.

### 6.3 Isolamento multi-tenant

**Escopo:** `rust/kernel/src/ledger/tenant_router.rs`, `gateway/src/middleware/tenant_extractor.rs`.

```mermaid
flowchart LR
    jwt["Bearer JWT<br/>BtvClaims.tenant_id"] --> ext["TenantExtractorLayer<br/>valida (path-traversal guard)"]
    ext --> tid["TenantId"]
    tid --> router["TenantStorageRouter<br/>RwLock<HashMap>"]
    router --> l1[("ledger tenant A<br/>Arc<DurableLedger>")]
    router --> l2[("ledger tenant B")]
    tid --> tek["TenantKeyDeriver → TEK_A / TEK_B"]
    tek --> l1
    tek --> l2
    evict["DELETE /internal/v1/tenants/:id<br/>→ EvictionReport (5 componentes)"] --> router
```

### 6.4 Camadas criptográficas

```mermaid
flowchart TB
    subgraph hash["Integridade (hash)"]
        b3["BLAKE3<br/>evidence.hash · ledger chain · merkle"]
    end
    subgraph mac["Autenticidade (MAC)"]
        h256["HMAC-SHA256<br/>verdict_id · effect_log · seals"]
    end
    subgraph sig["Não-repúdio (assinatura)"]
        ed["Ed25519<br/>Σ LogSigner · políticas · mandatos · redação"]
    end
    subgraph proof["Prova de inclusão"]
        mk["Merkle (SHA-256)<br/>Σ tree + verify_merkle_inclusion"]
    end
    b3 --> h256 --> ed
    ed --> mk
```

**Nota:** duas famílias de Merkle coexistem — canônica `min(a,b)` em Σ/btv-types e ordenada por lado (`ProofSide`) em btv-judicial (`merkle_verify.rs`).

---

## 7 · Arquitetura de persistência

**Objetivo:** todos os armazenamentos e como se relacionam.

**Escopo:** `rust/kernel/src/ledger/`, `python/buildtovalue/{api/_db.py,api/ledger_reader.py,security/db.py}`, `ops/`.

```mermaid
flowchart TB
    subgraph rustled["Ledger imutável (Rust)"]
        wal[("WAL<br/>evidence snapshot fsync")]
        disk[("disco bincode<br/>LedgerEntry 384B encadeado")]
        eff[("EffectLog<br/>ring [64] em memória")]
        sess[("SessionAggregator<br/>ring [256] em memória")]
    end
    subgraph pyled["Ledger analítico (Python)"]
        jsonl[("data/ledger/decisions.jsonl<br/>append-only")]
    end
    subgraph sqlite["SQLite (WAL mode)"]
        trust[("trust / sessions")]
        appeals[("appeals")]
        threats[("threats")]
        users[("users (bcrypt)")]
    end
    subgraph sig["Σ"]
        merkle[("MerkleTree (InMemoryStore<br/>trocável por RocksDB/PG)")]
    end
    subgraph vol["Volumes / k8s"]
        led_data[("ledger_data (Compose)")]
        pvc_led[("PVC ledger 50Gi")]
        pvc_exp[("PVC explanations 100Gi")]
        pg[("Postgres + Redis (k8s Secret)")]
    end

    router["TenantStorageRouter"] --> disk
    disk --> wal
    disk --> eff & sess
    disk --- led_data
    disk --- pvc_led
    jsonl --- led_data
    LedgerReader["api.LedgerReader.query"] --> jsonl
    LedgerAnalytics["compliance.LedgerAnalytics"] --> jsonl
    appeals --> ContestabilityLoop
    disk --> verifychain["verify_chain_integrity → ChainStatus"]
```

**Notas:** há **dois ledgers** — o canônico criptográfico do kernel (WAL + bincode encadeado, por tenant) e um JSONL analítico no Python (consumido por `LedgerReader`/`LedgerAnalytics` para ROPA/Art.20/métricas). No Compose ambos compartilham o volume `ledger_data`. **Limitação conhecida:** sem rotação de ledger (cresce indefinidamente).

---

## 8 · Topologias de implantação

### 8.1 Quickstart (`ops/docker-compose.quickstart.yml`)

```mermaid
flowchart LR
    u["👤 :8501 dashboard"] --> dash["dashboard<br/>Dockerfile.streamlit-demo"]
    dash --> gw["gateway :8080<br/>Dockerfile.rust"]
    gw -->|:8000| gov["governance<br/>Dockerfile.python-quickstart"]
    gw -->|proxy| mock["upstream-mock :8082<br/>httpbin"]
    gw --- led[("ledger_data")]
    gov --- led
```

### 8.2 Produção Compose + observabilidade (`ops/docker-compose.yml`)

```mermaid
flowchart TB
    internet["🌐"] --> nginx["nginx :8443/:9443<br/>TLS"]
    nginx --> gw["gateway :8080 (+gRPC :9090)<br/>serve dashboard React"]
    nginx --> gov["governance :8000<br/>CUDA 12.4 · mem 6G/4cpu"]
    gw -->|:8000| gov
    gw --- led[("ledger_data")]
    gov --- led
    prom["prometheus :9090"] -->|scrape /metrics| gw
    graf["grafana :3000"] --> prom
    play["playground :8502"] --> gw
    dashl["dashboard-legacy :8501"] --> gw & gov
```

**Variantes:** `docker-compose.e2e.yml` (gateway pré-buildado `Dockerfile.rust-ci` + go-httpbin, adiciona `BTV_JWT_SECRET`); `docker-compose.gpu.yml` (reserva GPU NVIDIA na governança); `docker-compose.vps.yml` (único `nginx-prod` :80/:443 como ingress, redes externas + letsencrypt).

### 8.3 Kubernetes (`ops/k8s/`)

```mermaid
flowchart TB
    subgraph ns["ns: buildtovalue (PSS restricted)"]
        ing["Ingress nginx<br/>api.buildtovalue.com<br/>TLS cert-manager · 100rps"]
        svc["Service ClusterIP<br/>80→8000 · 9090 metrics<br/>sessionAffinity ClientIP"]
        dep["Deployment buildtovalue<br/>replicas 3 · RollingUpdate maxUnavailable 0<br/>initContainer validate-policies<br/>runAsNonRoot · podAntiAffinity"]
        depc["Deployment compliance<br/>replicas 3 · WAL PVC"]
        hpa["HPA 3–10<br/>CPU70% · Mem80% · p99 30ms"]
        pvc[("PVC ledger 50Gi<br/>PVC explanations 100Gi")]
        sec["Secret: DATABASE_URL(PG)<br/>REDIS_URL · SIGNING_KEY"]
        np["NetworkPolicy<br/>egress: DNS/PG/Redis/HTTPS"]
    end
    argocd["ArgoCD Application<br/>GitOps sync prune+selfHeal"] -.-> dep
    ing --> svc --> dep
    hpa --> dep
    dep --- pvc & sec
    np -.-> dep
```

### 8.4 Fly.io (`fly.toml`)

```mermaid
flowchart LR
    fly["app buildtovalue-gateway<br/>região gru · Dockerfile.rust<br/>internal_port 8080 · force_https<br/>512mb/1cpu · check GET /health"] -->|BTV_GOVERNANCE_URL<br/>https://governance.buildtovalue.io| ext["governança (externa)"]
```

---

## 9 · Pipeline de CI/CD

**Objetivo:** os portões de qualidade que protegem os invariantes arquiteturais.

**Escopo:** `.github/workflows/*.yml`.

```mermaid
flowchart TB
    push["push / pull_request"] --> gate

    subgraph gate["Portões (GitHub Actions)"]
        direction TB
        fs["fail_secure_ci<br/>merkle-consistency · bindings-build<br/>no-stubs · python-ffi · gate"]:::sec
        cp3["constitutional-phase3<br/>constitutional-boundaries · unit-tests<br/>gateway-unit · pipeline-with-sigma<br/>evidence-size · latency-benchmark"]:::sec
        crate["crate_release_audit<br/>workspace_integrity + dry_run<br/>(isolamento de crates)"]:::sec
        align["alignment_regression<br/>golden_tests"]:::test
        battery["btv_battery_v2<br/>Security Coverage"]:::test
        blind["policy-blind-test<br/>Rawls (ADR-042)"]:::test
        ci["ci (Grant Adapter)<br/>weeks 1-4 + full-pipeline"]:::test
        e2e["e2e<br/>Proxy HTTP transparente"]:::test
        lint["lint-guards<br/>bandit · cargo-audit<br/>trufflehog · coverage"]:::lint
        proto["proto<br/>breaking (contrato gRPC)"]:::lint
        docs["docs<br/>build MkDocs"]:::lint
    end

    gate --> merge{"todos verdes?"}
    merge -->|sim| ok["merge / deploy (ArgoCD)"]
    merge -->|não| block["bloqueia PR"]

    classDef sec fill:#c62828,color:#fff
    classDef test fill:#1565c0,color:#fff
    classDef lint fill:#6a1b9a,color:#fff
```

**Notas:** CI **codifica os invariantes de arquitetura** — `crate_release_audit` garante o isolamento de crates (J/Σ sem btv-core); `fail_secure_ci/no-stubs` proíbe stubs em caminhos de segurança; `constitutional-phase3/evidence-size` fixa 9632B da evidência; `latency-benchmark` protege o SLA; `trufflehog`/`bandit`/`cargo-audit` cobrem segredos e vulnerabilidades.

---

## 10 · Mapa de invariantes fail-secure

**Objetivo:** vista transversal do princípio que unifica o sistema — **o estado padrão é o bloqueio**.

```mermaid
flowchart TB
    inv["🔒 Invariante global:<br/>falha ⇒ negação"]

    inv --> k["Kernel<br/>TechnicalEvidence nasce hash=0 (inválida);<br/>3 portões emitem Finding crítico;<br/>#[must_use] → erro de build"]
    inv --> ffi["FFI<br/>PyO3-only, sem fallback;<br/>ImportError → BridgeNotAvailableError"]
    inv --> py["Governança Python<br/>exceção em qualquer etapa → BLOCK assinado;<br/>singleton 503 → fail-secure"]
    inv --> gw["Gateway<br/>proxy nega (451) por padrão;<br/>token ruim → 401 (MED-R05)"]
    inv --> exec["Executivo<br/>DecisionError sem variante parcial;<br/>sem recibo Σ ⇒ sem entrega"]
    inv --> keys["Chaves<br/>fail-closed em produção;<br/>comparação constant-time"]
    inv --> ci["CI<br/>no-stubs · evidence-size ·<br/>isolamento de crates"]
```

---

## 11 · Rastreabilidade arquivo → componente

| Componente (diagrama) | Origem no repositório |
|---|---|
| Gateway (rotas/middleware/estado/auditoria) | `rust/gateway/src/{routes,middleware,state.rs,audit}` |
| Kernel Gatekeeper + pipeline | `rust/kernel/src/{gatekeeper.rs,core,evidence,deobfuscator,interceptor}` |
| Ledger imutável | `rust/kernel/src/ledger/{durable_ledger,wal,effect_log,entry,tenant_router}.rs` |
| Tokens lineares / Executivo | `rust/btv-core/src/*`, `rust/btv-executive/src/*` |
| Σ Transparency Log | `rust/btv-sigma/src/{api,merkle,signer,store}.rs` |
| Judiciário / Governança / Redação | `rust/btv-{judicial,governance,redaction}/src/*` |
| Tipos wire compartilhados | `rust/btv-types/src/{lib,crypto_utils,merkle_verify}.rs` |
| FFI (PyO3 + C-ABI) | `rust/bindings/src/*`, `rust/kernel/src/ffi/*`, `python/buildtovalue/{ffi,governance/ffi_client.py}` |
| API FastAPI + routers | `python/buildtovalue/api/{app.py,_lifespan.py,routes/*}` |
| Ethical Context Engine + camadas | `python/buildtovalue/governance/{ethical_context_engine,ece_technical,ece_governance}.py` |
| Compliance (plugins + geradores) | `python/buildtovalue/compliance/*` |
| Intelligence (SLM/NER/threat) | `python/buildtovalue/intelligence/*` |
| Agentic (negociação A2A) | `python/buildtovalue/agentic/*` |
| Orquestradores core | `python/buildtovalue/core/{governance_gateway,tool_call_router}.py` |
| Segurança (chaves/DB) | `python/buildtovalue/security/{keys,db}.py`, `rust/kernel/src/keys.rs` |
| SDKs / MCP / integrações | `sdk/{javascript,python,mcp-server,integrations}/*` |
| Implantação | `ops/{docker-compose*.yml,Dockerfile.*,k8s,nginx,prometheus.yml}`, `fly.toml` |
| CI/CD | `.github/workflows/*.yml` |
| Contratos | `spec/{openapi.yaml,agent-pdp-v1.json}` |

---

> **Fidelidade.** Nenhum elemento deste documento foi inferido de material de marketing — todos derivam de leitura direta dos arquivos citados. Para o nível de classes/sequência detalhado, ver o [Documento UML](arquitetura-uml.md).

