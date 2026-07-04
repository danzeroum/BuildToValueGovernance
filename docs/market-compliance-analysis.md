# Análise Profunda — Aceitação de Mercado e Validação da Camada de Compliance

> Data: 2026-07-04 · Complementa `docs/pareto-analysis.md`
> Método: dois auditores de código independentes (mercado e compliance) + pesquisa
> do cenário regulatório/competitivo de 2026. Todas as afirmações sobre o código
> têm referência `arquivo:linha`.

---

## Parte 1 — A ferramenta teria aceitação real no mercado de agentes/chamadas LLM do jeito que está?

### Veredito curto

**No mainstream (plataformas de agentes com chat/streaming em produção): não, ainda não.**
**Em um nicho específico (decisão automatizada batch, LGPD/Brasil): sim, como piloto.**

O timing e a arquitetura estão certos — o consenso do mercado em 2026 é que
guardrails pertencem ao gateway, não ao código da aplicação, e as obrigações de
alto risco do EU AI Act entram em vigor em 02/08/2026. Mas há uma lacuna material
entre o que o README/PRICING vendem e o que `proxy.rs` entrega.

### Bloqueadores HARD (impedem produção hoje)

| # | Bloqueador | Evidência |
|---|---|---|
| 1 | **Sem streaming SSE** — o proxy bufferiza a resposta inteira (`resp.bytes().await`) e devolve de uma vez. Qualquer cliente com `stream=True` (padrão em chat/agentes) quebra a UX. Moderação em streaming é O problema técnico da categoria (NeMo, SentGuard etc. competem nisso) | `rust/gateway/src/routes/proxy.rs:232-233` |
| 2 | **Timeout global de 20s** mata gerações longas | `rust/gateway/src/routes/mod.rs:117` |
| 3 | **Proxy não governa a RESPOSTA do LLM** — só escaneia o request; a resposta do upstream passa crua, sem scan/evidência. O pitch "toda chamada interceptada e auditada" só vale para a entrada | `proxy.rs:119,128` vs `proxy.rs:229-233` |
| 4 | **Só OpenAI funciona de fato** — o whitelist de headers não encaminha `x-api-key`/`anthropic-version` (Anthropic) nem assinaturas Bedrock, apesar do doc dizer "OpenAI/Anthropic/Bedrock" | `proxy.rs:39-46` vs `proxy.rs:3-4` |
| 5 | **Fail-secure vira SPOF**: governança Python indisponível → 451 para todo o tráfego | `proxy.rs:206-207` |
| 6 | **PRICING.md é aspiracional** — promete quota mensal/429/tiers, mas não existe metering, billing, licença ou Stripe no código; o único 429 é rate-limit por minuto in-memory (não distribuído, não persiste) | `PRICING.md:19-83`; `middleware/rate_limit.rs:60-104` |
| 7 | **Sem TLS nativo** (auto-declarado) | `README.md` limitações |

### Bloqueadores SOFT (confiança)

- **Benchmarks sem resultados**: `benchmarks/comparative/results/` contém só `.gitkeep`;
  a tabela do README dos benchmarks é "Expected Results" hardcoded; o adapter
  "Guardrails AI" prometido no título **não existe** (só btv, lakera, nemo, bedrock,
  prompt_security); datasets somam 50 amostras, não as 70 citadas.
- **Alpha 0.1.0a1, bus factor 1** (1 autor humano no git log), sem CHANGELOG técnico
  (o filosófico referencia um `CHANGELOG.md` inexistente), CI principal cobre só o
  grant adapter (`.github/workflows/ci.yml:22-44`), não o produto.
- Números de marketing sem fonte no repo (1,67μs, multa mediana $10,8M).

### Pontos fortes genuínos (defensáveis)

1. **Fail-secure por construção** (`TechnicalEvidence` hash-zero + `#[must_use]`) é
   um argumento honesto e diferenciado contra validadores bypassáveis.
2. **Middleware de gateway em nível de produção**: JWT real, multi-tenancy tipada
   com isolamento testado, rate limit moka por tenant, Prometheus/OTel
   (`middleware/auth.rs:126-144`, `tenant_extractor.rs:118-213`, `rate_limit.rs:60-104`).
3. **Integrações reais**: LangChain callback funcional, AutoGen, CrewAI, LlamaIndex,
   MCP server, SDKs Python/JS com testes — não são stubs.
4. **Maturidade documental atípica para o estágio**: 109 ADRs, runbooks, SECURITY.md.
5. **Posicionamento Brasil-first oportuno**: ANPD virou agência reguladora
   independente em 2026 com poderes reforçados, sandbox de IA em teste até dez/2026,
   Art. 20 LGPD sendo fiscalizado, PL 2338 na Câmara. CPF/CNPJ nativos + relatório
   Art. 20 derivado de ledger são diferencial real nesse mercado.

### Quem compraria hoje

Equipe de plataforma **OpenAI-only, fluxos não-streaming** (decisão de crédito,
triagem de currículos, pipelines batch), self-host, cujo comprador econômico é
DPO/CISO sob pressão LGPD/ANPD e quer **trilha de evidência imutável + contestação
Art. 20**. Para esse nicho, o produto atual sustenta um piloto.

### O que falta para o mercado principal (ordem de impacto)

1. Streaming SSE passthrough com scan incremental (chunk/sentence-level) — sem isso
   não há mercado de agentes.
2. Governança da resposta no proxy (hoje só request).
3. Multi-provider real (headers Anthropic/Bedrock — correção pequena, valor alto).
4. Modo de degradação configurável (fail-open com flag + alerta) para o SPOF.
5. Metering/quota real ou remoção do PRICING até existir.
6. Resultados de benchmark commitados + adapter Guardrails AI prometido.

---

## Parte 2 — A camada de compliance (ISO 42001 / EU AI Act) é real? É completa?

### Veredito curto

**Metade é real e de boa engenharia; metade é fachada que não sobreviveria a um
auditor — e a fachada é perigosa porque gera falsa segurança.**

Existem dois caminhos desconectados no código, com honestidades opostas:

| Caminho | Endpoints | Natureza |
|---|---|---|
| "Evaluator + ledger" | `/v1/compliance/evaluate`, `/classify-risk`, `/ropa/generate`, `/art20/report` | **Substancialmente real** |
| "Plugin vitrine" | `/v1/compliance/check`, `/frameworks`, `/report/{framework}` | **Carimbo de borracha** |

### O que é REAL

- **`classify-risk`** (`compliance/risk_classifier.py:148-248`): ordem correta
  Proibido→Alto→Limitado→Mínimo; Art. 5 com as capacidades proibidas reais
  (manipulação subliminar, social scoring, biometria em tempo real, emoção em
  trabalho/educação, policiamento preditivo); Anexo III mapeado por setor em
  `data/policies/sectors/_index.yaml:26-103`; obrigações citam artigos e
  penalidades corretos (35M€/7%). Limitação: classificação por setor é mais
  grossa que o Anexo III real (que qualifica usos, não setores).
- **Ledger imutável = Art. 12** (`governance/durable_ledger.py:44-49`): append-only,
  chain-hash BLAKE2b + HMAC-SHA256 por entrada, verificação de adulteração. A
  obrigação runtime mais bem atendida.
- **ROPA (GDPR Art. 30/LGPD Art. 37)** com proveniência real: agrega o ledger de
  decisões de verdade (contagens, PII detectados, janela temporal) e sela com hash
  (`compliance/ropa_generator.py:192-230`, `ledger_analytics.py:126-162`).
- **Relatório Art. 20 LGPD** derivado de decisões reais (`compliance/art20_report.py:132-179`).
  Ressalva: as declarações de viés são hard-coded (FPR 0.08/FNR 0.18 fixos).
- **ContestabilityLoop**: contestação funcional (SQLite WAL, SLA 24h, revisor humano,
  JWT no write). Mapeia para GDPR Art. 22 / LGPD Art. 20 / AI Act Art. 27(1)(i).

### O que é FACHADA

1. **Plugins EU AI Act / LGPD retornam COMPLIANT hard-coded.**
   `compliance/eu_ai_act_plugin.py:27,65,77` marca Art. 5, 9 e 15 como
   `COMPLIANT` incondicionalmente; `validate_requirements()` avalia um dict
   pré-fabricado — `GET /v1/compliance/report/EU_AI_ACT` retorna
   compliance_rate ≈ 1.0 **sempre**, sem avaliar nada. Idem LGPD
   (`lgpd_plugin.py:105`). *Este é o achado mais grave: um relatório de
   conformidade que não pode dar outro resultado.*
2. **Regras-chave silenciosamente quebradas** no evaluator YAML — falham para
   `skipped`, nunca para erro visível:
   - Art. 5 manipulação subliminar: `eu_ai_act.yaml:26` usa `.contains()` (método
     inexistente em lista Python) → AttributeError → skipped. **A proibição mais
     emblemática do AI Act nunca dispara.**
   - `iso_42001.yaml:85` (`not contains`) e `iso_42001.yaml:248` (`count()` fora da
     whitelist) → skipped.
   - `gdpr.yaml:239`: bug de indentação descarta ~4 artigos no load.
   - Metadados mentem: `eu_ai_act.yaml` declara `total_rules: 4` mas tem ~13.
3. **FRIA (Art. 27) é 90% template auto-descritivo**: as seções descrevem o produto
   BTV ("SLM Qwen 2.5 3B", "ContestabilityLoop 24h"), não o sistema de IA avaliado
   (`compliance/fria_generator.py:153-375`). Só 2 valores vêm de runtime, e um deles
   é `compliance_rate = 1 − block_rate` (`fria_generator.py:107`) — equação sem
   fundamento regulatório. Atenuante: o gerador declara `manual_required` e
   "X/10 auto-filled".
4. **Sobre-alegação de Art. 14**: contestação ex-post (redress) não é human
   oversight em tempo real (capacidade de intervir/parar durante a operação);
   `fria_generator.py:339` alega "Art. 14 compliant" via contestabilidade.

### O que é ALEGADO mas AUSENTE

- **Art. 73 (incident reporting a autoridades)**: inexistente. Só há webhooks
  Slack/PagerDuty internos, e `data/policies/webhooks.yaml` está inteiramente
  comentado.
- **Art. 72 (post-market monitoring)**: sem capacidade dedicada.

### ISO 42001 — o que um sistema runtime PODE cobrir (resposta direta)

ISO/IEC 42001 é um padrão de **sistema de gestão** (AIMS). As cláusulas 4–10
(contexto, liderança, planejamento, suporte, operação, avaliação, melhoria) são
processos organizacionais **que nenhum software runtime pode certificar** — no
máximo coletar evidência. O que runtime pode legitimamente cobrir é uma fração do
**Anexo A** (~38 controles): logging de eventos, transparência de decisão,
suporte a oversight, monitoramento operacional — talvez 8–10 controles com
evidência automatizada.

O que o BTV faz hoje: transforma 28 cláusulas em regras que checam **booleans
auto-declarados** pelo operador (`iso_42001.yaml:27,47` — "board existe?",
"contexto documentado?"). Isso é um checklist de auto-atestação, não verificação.
Cobre 3 de ~38 controles do Anexo A. E ISO 42001 nem aparece em
`GET /v1/compliance/frameworks` (só LGPD e EU_AI_ACT via plugins) — a cobertura
não é oferecida onde o usuário procuraria.

### Tabela-síntese: obrigação × o que runtime PODE fazer × o que o BTV faz

| Obrigação | Runtime pode (teto teórico) | BTV hoje | Gap |
|---|---|---|---|
| AI Act Art. 12 (logging) | Log imutável assinado e verificável | DurableLedger real | **Baixo** |
| Art. 14 (oversight) | HITL em tempo real, override, kill-switch | Redress ex-post (appeals) | **Médio-alto** (sobre-alegado) |
| Art. 15 (acurácia/robustez) | Gates, testes adversariais contínuos | Booleans auto-declarados + plugin carimbo | **Alto** |
| Art. 26/27 (deployer/FRIA) | Rascunho de FRIA derivado de risco+telemetria | classify-risk real; FRIA template | **Médio** |
| Art. 5 (proibições) | Detecção de capacidades proibidas | Classificador real; regra YAML quebrada | **Misto** |
| Art. 72 (pós-mercado) | Monitoramento contínuo + drift | Ausente | **Alto** |
| Art. 73 (incidentes) | Pipeline de notificação estruturada | Ausente (webhooks internos apenas) | **Muito alto** |
| GDPR Art. 30 / LGPD Art. 37 (ROPA) | ROPA de atividades reais | Real, do ledger | **Baixo-médio** |
| LGPD Art. 20 | Log + explicação + contestação | Real | **Baixo** |
| ISO 42001 cláusulas 4–10 | Nada além de coleta de evidência | Checklist de booleans | **Estrutural** |
| ISO 42001 Anexo A | ~8–10 controles com evidência automatizada | ~3 controles | **Alto** |

### É completa? Não. Sustentaria escrutínio de DPO/auditor?

**Parcialmente.** Os primitivos (classify-risk, ledger, ROPA, Art. 20, appeals)
sustentariam. O conjunto não: os endpoints-vitrine de conformidade retornam
sempre-conforme, regras emblemáticas nunca disparam sem aviso, tudo depende de
auto-atestação sem verificação independente, e Art. 72/73 não existem.

---

## Parte 3 — Ações recomendadas (novo Pareto, camada compliance/mercado)

Ordenadas por retorno (valor ÷ esforço):

1. **Corrigir as regras YAML quebradas + tornar `skipped` visível como erro**
   (esforço baixo, valor altíssimo — integridade do produto; hoje o Art. 5 nunca dispara).
2. **Encaminhar headers Anthropic (`x-api-key`, `anthropic-version`) no proxy**
   (3 linhas; destrava o segundo maior provider).
3. **Remover ou rotular os plugins carimbo** (`/check`, `/report`) como
   "demonstração" — hoje geram relatório sempre-conforme, o que é risco legal
   para o usuário e reputacional para o projeto. Honestidade é o diferencial
   declarado do BTV; este é o ponto onde ele se contradiz.
4. **Rebaixar a alegação ISO 42001 para "coleta de evidência para auditoria
   AIMS (fração do Anexo A)"** na documentação e na API.
5. **Streaming SSE passthrough** com scan incremental por sentença/chunk
   (esforço alto, mas é O bloqueador do mercado de agentes).
6. **Governança da resposta no proxy** (scan de output antes do repasse, com
   evidência no ledger).
7. **Pipeline Art. 73**: reaproveitar o webhook_dispatcher para notificação
   estruturada de incidente grave (template ANPD/autoridade UE) com evidência
   do ledger anexada.
8. **Medir bias declarations em runtime** (substituir FPR/FNR fixos do Art. 20
   report por métricas reais do ledger).

### Contexto de mercado que fundamenta a urgência

- Obrigações de alto risco do EU AI Act vigentes a partir de **02/08/2026**
  (Digital Omnibus pode adiar Anexo III para dez/2027, mas não está promulgado).
- ANPD tornou-se **agência reguladora independente em 2026** com poder de ordenar
  cessação de operações; sandbox de IA em testes até dez/2026; PL 2338 na Câmara.
- O consenso arquitetural do mercado ("guardrails no gateway") valida a tese do
  BTV, mas os concorrentes (Bifrost, Arthur, Databricks Unity AI Gateway,
  LiteLLM, NeMo, Bedrock/Azure Guardrails) já resolvem streaming e
  multi-provider — a janela de diferenciação do BTV é evidência criptográfica +
  contestabilidade + LGPD/Brasil, não largura de features.
