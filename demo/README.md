# BuildToValue Trust OS — Demo Frontend

> Artefato provisório de demonstração. Não contém estado crítico. O estado da República Algorítmica reside estritamente em `ops/runtime/` e nos arquivos `.db`.

## Estrutura

```
demo/
├── proxy.py          ← Proxy Python (porta 8080) que injeta a API key
├── index.html        ← Landing page — seletor de personas
├── persona-eng.html  ← Engenheiro: latência p99, Rust FFI status
├── persona-ciso.html ← CISO: laboratório de ataques, ledger imutável
├── persona-dpo.html  ← DPO: compliance, FRIA, frameworks
├── persona-gov.html  ← Governança: contestability loop, SLA 24h
├── lab.html          ← Laboratório unificado (modo teatro)
├── css/btv.css       ← Design system dark
└── js/
    ├── api.js        ← Wrapper fetch() para /api/*
    └── lab-engine.js ← Cenários pré-definidos por persona
```

## Como rodar

```bash
# 1. API BTV deve estar rodando na porta 8000
make run &

# 2. Iniciar o proxy do demo
cd /opt/btv
python3 demo/proxy.py &

# 3. Acessar no browser
# http://<IP-DA-VPS>:8080
```

## Variáveis de ambiente

```bash
# Autenticação — API key (injetada em todos os requests pelo proxy)
export BTV_DEMO_KEY="sua-api-key"        # padrão: usa BTV_API_KEYS do .env

# Autenticação — JWT para operações de escrita (Appeals, Governança)
export BTV_DEMO_USER="admin"             # padrão: "admin"
export BTV_DEMO_PASSWORD="sua-senha"     # obrigatória para escrita; ausente = modo somente-leitura

# Infraestrutura
export BTV_API_BASE="http://localhost:8000"  # padrão
export BTV_DEMO_PORT="8080"                  # padrão
```

### Modo somente-leitura (fail-secure)

Se `BTV_DEMO_PASSWORD` não for configurada, o proxy bloqueia o endpoint `/demo-login`
com `HTTP 403` e payload `{"action": "BLOCK", "verdict": "DENY"}`. O frontend opera
em modo somente-leitura: personas de leitura (Engenheiro, CISO, DPO em GETs) funcionam
normalmente; a persona **Governança** (Appeals — escrita) exibe aviso de modo restrito.

Isso é **intencional e auditável** — não um erro silencioso.

## Personas e endpoints usados

| Persona | Foco | Endpoints |
|---|---|---|
| Engenheiro | Latência p99, Rust FFI | `/health`, `/v1/decide` |
| CISO | Ataques ao vivo, ledger | `/v1/decide`, `/v1/ledger/query` |
| DPO | Compliance, FRIA | `/v1/compliance/*`, `/v1/compliance/fria/generate` |
| Governança | Appeals, SLA 24h | `/v1/appeals`, `/v1/appeals/metrics` |
