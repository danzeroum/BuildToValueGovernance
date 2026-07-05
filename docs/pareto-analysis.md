# Análise de Pareto — Funcionalidade e Plano de Desenvolvimento

> Data: 2026-07-04 · Branch: `claude/pareto-analysis-dev-plan-yg5qb4`

## 1. A ferramenta é funcional?

**Sim — o núcleo é real, compila e passa nos testes.** A avaliação cobriu build,
suítes de teste, subida da API e comparação código × documentação.

| Componente | Estado | Evidência |
|---|---|---|
| Workspace Rust (12 crates) | ✅ Compila limpo | `cargo check --workspace` sem erros |
| Kernel (Gatekeeper) | ✅ Real | 21 módulos ligados no pipeline (`rust/kernel/src/gatekeeper.rs`), ~590 testes |
| Proxy transparente 451 | ✅ Real | `rust/gateway/src/routes/proxy.rs` — scan + policy + fail-secure + HTTP 451 |
| Ledger WAL + HMAC | ✅ Real | `rust/kernel/src/ledger/` — cadeia BLAKE3, HMAC-SHA256, usado em `/v1/decide` |
| API Python (FastAPI) | ✅ Sobe e responde | 49 endpoints reais; funciona sem o kernel Rust (fallback degradado) |
| Suíte Python | ✅ 1809 testes verdes | após correções desta análise (antes: 26 falhas de ambiente/isolamento) |
| Suíte Rust | ✅ Verde | após fallback de `BTV_HMAC_KEY` nos testes de integração |
| Docker quickstart | ✅ Coerente | 4 serviços, bundles de política existem |

**Onde estava o problema:** não no motor, mas na superfície de contato — o
onboarding documentado falhava no primeiro comando (`BTVClient` no pacote errado,
porta 3000 inexistente, endpoint `/v1/scan` prometido mas ausente) e as suítes
vermelhas passavam a impressão de projeto quebrado. Exatamente o perfil de
problema que a análise de Pareto favorece: pouco esforço, muito valor.

## 2. Diagrama de Pareto (valor ÷ esforço)

Itens ordenados por retorno. Esforço em pontos relativos (0,5 ≈ minutos;
10 ≈ semanas); valor em impacto de adoção/conformidade (1–10).

| # | Item | Esforço | Valor | Retorno | Valor acum. | Status |
|---|---|---:|---:|---:|---:|---|
| 1 | README: porta 8080 + payload corrigidos | 0,5 | 8 | 16× | 8,3% | ✅ feito |
| 2 | `cargo test` verde (`BTV_HMAC_KEY`) | 0,5 | 7 | 14× | 15,6% | ✅ feito |
| 3 | Docs: 21 módulos + arquitetura real | 0,5 | 5 | 10× | 20,8% | ✅ feito |
| 4 | README: instalação do SDK (`BTVClient`) | 1 | 9 | 9× | 30,2% | ✅ feito |
| 5 | Gateway: alias `/v1/scan` | 1 | 7 | 7× | 37,5% | ✅ feito |
| 6 | Makefile: dashboard/arena reais | 1 | 6 | 6× | 43,8% | ✅ feito |
| 7 | Suíte Python 1809 testes verde | 1,5 | 8 | 5,3× | 52,1% | ✅ feito |
| 8 | API Python: aliases `validate`/`sanitize` | 3 | 6 | 2× | 58,3% | Fase 2 |
| 9 | Namespace único p/ SDK e mcp-server | 6 | 8 | 1,3× | 66,7% | Fase 2 |
| 10 | Proxy: recibo no ledger a cada 451 | 6 | 8 | 1,3× | 75,0% | Fase 2 |
| 11 | TLS no quickstart | 4 | 4 | 1× | 79,2% | Fase 3 |
| 12 | Homóglifos Unicode (leetspeak) | 6 | 4 | 0,7× | 83,3% | Fase 3 |
| 13 | Rotação/retenção do ledger | 8 | 5 | 0,6× | 88,5% | Fase 3 |
| 14 | Publicação crates.io / PyPI | 10 | 6 | 0,6× | 94,8% | Fase 3 |
| 15 | Validação externa de benchmarks | 10 | 5 | 0,5× | 100% | Fase 3 |

**Leitura:** os 7 primeiros itens custam ~10% do esforço total mapeado e entregam
~52% do valor — todos implementados nesta branch. O marco de 80% do valor é
alcançado no item 11, com ~42% do esforço.

## 3. O que foi implementado nesta branch (Fase 1)

1. **README** — Path C instala `sdk/python/` (onde `BTVClient` existe de fato) e
   usa o método real `client.validate()`; Path B usa a porta real 8080 e payload
   aceito pelo gateway; contagem de módulos corrigida para 21; diagrama de
   arquitetura lista os endpoints que existem; licença dupla esclarecida.
2. **Gateway Rust** — novo alias `POST /v1/scan` → handler de `/v1/validate`
   (`rust/gateway/src/routes/mod.rs`), honrando o que o README promete.
3. **Testes Rust** — `btv-executive/tests/integration_pipeline.rs` define
   `BTV_HMAC_KEY` de teste quando ausente; `cargo test` verde sem setup manual.
4. **Testes Python** — 26 falhas → 0:
   - e2e de appeals autentica com JWT (exigência CRITICO-03 posterior ao teste);
   - `test_consensus_validator.py` usa `asyncio.run` (o loop compartilhado era
     fechado por testes anteriores na suíte completa);
   - teste de abliteration compara contra a constante canônica
     (`_DEFAULT_REFUSAL_THRESHOLD = 0.80`, v1.2.0) em vez do valor antigo 0.7.
5. **Makefile / pyproject** — `make dashboard` executa o Streamlit que existe
   (`python/buildtovalue/dashboard/app.py`); target `arena-demo` fantasma
   removido (o CLI `arena-demo-cli` permanece); novo extra
   `pip install -e "python/[dashboard]"`.

## 4. Plano de desenvolvimento

### Fase 2 — próximo sprint (1–2 semanas → ~75% do valor acumulado)

| Item | Descrição | Critério de aceite |
|---|---|---|
| Aliases na API Python | Expor `/v1/validate` e `/v1/sanitize` na API FastAPI (hoje só no gateway Rust), para os SDKs Python/JS funcionarem contra os dois backends | `BTVClient.validate()` e `sanitize()` verdes contra `localhost:8000` |
| Namespace do SDK | `python/buildtovalue` e `sdk/python/buildtovalue` disputam o mesmo import; o mcp-server importa dos dois e não instala. Renomear a distribuição do SDK (ex.: `buildtovalue-sdk`) e reexportar `AsyncBTVClient` no pacote da aplicação | `pip install` dos dois pacotes coexiste; mcp-server importa e sobe |
| Ledger no proxy | Bloqueios 451 do proxy não gravam no `DurableLedger` (só `/v1/decide` grava) — o "recibo imutável por bloqueio" do README. Reusar o caminho de persistência de `decide.rs` em `proxy.rs` | Todo 451 do proxy gera entrada verificável no ledger do tenant |

### Fase 3 — backlog priorizado

1. **TLS no quickstart** — Caddy/Traefik no compose (retira a limitação "sem TLS").
2. **Homóglifos Unicode** no LeetspeakDetector (FNR ~12%).
3. **Rotação/retenção do ledger** — hoje cresce indefinidamente.
4. **Publicação crates.io / PyPI** — já prevista para v3.0 no roadmap.
5. **Validação externa dos benchmarks** — FP ~15% medido em 70 amostras internas.

### Fora de escopo desta análise

Dívidas estruturais detectadas que merecem ADR próprio antes de execução:
duplicação `rust/kernel` × `rust/btv-core` (dois caminhos de decisão paralelos),
pasta `rust/_legacy`, e a divergência de formato entre `/v1/decide` do gateway
Rust e o da API Python.
