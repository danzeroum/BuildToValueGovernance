# ADR-0098: Propriedade do ledger canônico (Python `DurableLedger` vs `decisions.jsonl` do Rust)

**Status**: ✅ ACEITO — Opção C (ledgers disjuntos por design) — 31 de maio de 2026
**Data**: 31 de maio de 2026
**Autores**: IA Arquiteta
**Impacto**: `python/buildtovalue/api/_lifespan.py` (criação/ordem de
             `app.state.durable_ledger`); `python/buildtovalue/api/routes/agents.py`
             (`getattr` dormente, oracle-revocation); `python/buildtovalue/api/routes/ledger.py`
             + `ledger_reader.py` (fonte de `/v1/ledger/*`). Em (A) também o
             gateway Rust (`rust/gateway/src/routes/{validate,decide}.rs`).
**Pré-requisitos**: #182 (PR #188 — seam de injeção opcional no
             `CrossAgentCorrelator`), ADR-0093 (decomposição do lifespan),
             ADR-0024 (Ledger Query API), ADR-0083 (ledger por tenant no gateway).
**Issues**: #189 (este ADR), #193 (bug acoplado: guards do `agent_decide`).

---

## Contexto

O #189 pede um `DurableLedger` canônico persistente em `app.state`, partindo da
premissa de que isso faria o `CrossAgentCorrelator` e `/v1/ledger/*` lerem/escreverem
o **mesmo** ledger. O ground truth (comentário em #189) **refuta a premissa**:
existem **dois ledgers disjuntos**.

| | `DurableLedger` (Python) | `decisions.jsonl` (fonte de `/v1/ledger/*`) |
|---|---|---|
| Armazenamento | **Só em memória** — `self._entries=[]`, sem path, sem `save`/`load` | Arquivo append-only em disco |
| Escritor | `CrossAgentCorrelator`, oracle-revocation, subsistema `agentic/` | **Gateway Rust** (`validate.rs:338`, `decide.rs:1070` via `ledger.append_with_key`) — exclusivamente |
| Acesso Python | leitura/escrita in-process | **somente leitura** (`LedgerReader`, `LedgerAnalytics`) |
| Servido por | nada | `/v1/ledger/*`, `/v1/metrics`, relatórios LGPD/ROPA/Art20 |

Consequência: instanciar `app.state.durable_ledger` no lifespan, **sozinho, não
satisfaz o critério de aceite do #189** — `/v1/ledger/*` lê `decisions.jsonl`
(escrito pelo Rust), não o `DurableLedger`.

Fatos relevantes confirmados no código:

- `DurableLedger.__init__(self, hmac_key: bytes)` — sem path, sem máquina de
  persistência. Cadeia de hash + HMAC dão evidência de adulteração, mas tudo
  vive em RAM e morre com o processo.
- Precedente de HMAC-key no lifespan: `DelegationLedger(hmac_key_fn=get_hmac_key)`
  (`_lifespan.py:131–133`, rotação SIGHUP S-09). `DurableLedger` recebe *bytes
  estáticos*, não um callable → usar `get_hmac_key()` tira snapshot único no boot
  e **perde a paridade de rotação**.
- `_lifespan.py:121` já tem o seam do #182 (`getattr(application.state,
  "durable_ledger", None)`), e `agents.py:233` (oracle-revocation) já lê o mesmo
  `getattr` — ambos dormentes.

## Pergunta central

> **Qual ledger é canônico, e o Python pode escrever no ledger de propriedade do Rust?**

Tudo o mais no checklist do #189 (fonte da HMAC-key, ordem de init, ativar os
`getattr`) só passa a ser bem-definido **depois** desta decisão, porque ela
determina o tamanho do trabalho.

## Opções

### (A) Unificar no ledger do Rust
`CrossAgentCorrelator`/escritas Python passam a gravar em `decisions.jsonl`.

- **Consequências**: escrita cross-language num ledger append-only HMAC de
  propriedade do Rust; o Python tem que casar o formato de linha + o esquema HMAC
  do `decide.rs` (`append_with_key`) e respeitar o layout por tenant (ADR-0083).
  Contenção de escrita entre processos Rust e Python. Discutivelmente viola
  "Rust é o system-of-record do ledger de decisões".
- **Tamanho**: projeto de unificação cross-language. Toca Rust + Python +
  contrato de formato + segurança de chave compartilhada. **Não** é um fix de
  lifespan.

### (B) Expor o `DurableLedger` em memória via `/v1/ledger/*`
Uma sub-rota nova (ou ramo no router) serve as entradas do `app.state.durable_ledger`.

- **Consequências**: pequeno em código, mas **não-durável** — perde tudo no
  restart, contradizendo o título "persistente" do #189. Cria duas fontes para
  `/v1/ledger/*` (arquivo Rust + memória Python) com semânticas diferentes.
- **Tamanho**: pequeno, porém entrega uma garantia mais fraca do que o issue pede.

### (C) Re-escopar — `decisions.jsonl` (Rust) é canônico; `DurableLedger` é trilho in-process *(recomendada)*
Declara explicitamente:

- `decisions.jsonl` (Rust) = **ledger canônico persistido** de decisões; Python lê,
  não escreve.
- `DurableLedger` (Python) = **trilho de auditoria in-process** do subsistema
  agentic / correlator, tamper-evident por hash-chain+HMAC, com escopo de vida
  do processo — não um substituto do system-of-record.

E então:

- `_lifespan.py`: cria `application.state.durable_ledger = DurableLedger(get_hmac_key())`
  **antes** do bloco C6 (linha 115), para o seam do #182 (linha 121) capturá-lo —
  dando ao `CrossAgentCorrelator` (e à oracle-revocation em `agents.py:233`) um
  **ledger compartilhado por processo**, em vez de instâncias privadas soltas.
- Documenta na fronteira que `/v1/ledger/*` continua servindo `decisions.jsonl`
  (Rust), e o trilho in-process **não** é exposto ali (ou é exposto numa rota
  explicitamente rotulada como volátil, se houver demanda).
- **Reescreve o critério de aceite do #189**: de "correlator e `/v1/ledger/*` no
  mesmo ledger" para "o correlator escreve num ledger in-process compartilhado e
  verificável (`verify()`), e a fronteira Rust/Python está documentada".

- **Consequências**: respeita a separação Rust/Python já estabelecida; o trabalho
  real **colapsa para fiar os `getattr` dormentes + documentação** — mesmo padrão
  de escopo estreitado que funcionou no #182. Custo: a garantia "durável entre
  restarts" para o trilho agentic fica adiada (e explicitamente fora de escopo)
  até existir demanda real de persistência cross-restart desse subsistema.

## Decisão

**HOMOLOGADO: Opção C.** Os ledgers são **logicamente disjuntos por design**,
preservando a barreira fail-secure entre o Kernel (Rust/Merkle, system-of-record
persistido) e a camada de estado operacional (Python). A rastreabilidade
cross-ledger é garantida por **Ligação de Evidência Débil** — hashes de
referência cruzada — e **não** por unificação física ou via de escrita única. O
`DurableLedger` (Python) é o source-of-truth da camada Python; o Kernel Rust
permanece validador de integridade externo. O critério de aceite do #189 é
reescrito sob esta base (ver checklist abaixo).

Justificativa em duas linhas:

1. Respeita a separação Rust/Python já estabelecida — Rust é o system-of-record
   do ledger de decisões; o Python o lê (`LedgerReader`/`LedgerAnalytics`).
2. O trabalho real colapsa para fiar os `getattr` dormentes (#182 já preparou o
   seam) + documentar a fronteira — escopo estreitado, sem unificação
   cross-language nem persistência nova.

(A) fica registrado como projeto separado, a ser aberto **apenas** se a auditoria
exigir que sinais do correlator entrem no ledger persistido de decisões — caso em
que o canal correto é o pipeline de decisão do Rust, não uma escrita Python no
arquivo do Rust.

> **Nota de segurança (sob C)**: as notas de segurança do #189 reduzem-se a:
> chave via `get_hmac_key()` (snapshot no boot; rotação SIGHUP **não** propaga ao
> trilho in-process — aceitável por não ser system-of-record). A Ligação de
> Evidência Débil (hash de referência cruzada) não cria caminho de escrita Python
> no ledger Rust, preservando a barreira fail-secure.

## Decisões em aberto (dependentes da ratificação de C)

- [ ] **HMAC-key**: `get_hmac_key()` (snapshot) — ou adicionar `hmac_key_fn` ao
      `DurableLedger` para paridade de rotação com o `DelegationLedger`? (Sob C, o
      snapshot é defensável; documentar o trade-off.)
- [ ] **Ordem de init** em `_lifespan.py`: inserir a criação antes da linha 115
      (bloco C6).
- [ ] **Ativar os `getattr` dormentes**: `_lifespan.py:121` e `agents.py:233`
      passam a receber a instância real; remover/atualizar os comentários
      "not yet created".
- [ ] **Guards do `agent_decide` (#193)**: decidir se consomem o mesmo
      `app.state.durable_ledger` (resolve o controle morto de liveness/skill) ou
      ficam fora do escopo deste ADR.
- [ ] **Teste de integração**: um registro de degradação do correlator é
      recuperável via `verify()`/`entries()` do ledger compartilhado, dentro do
      ciclo de vida do processo.

## Referências

- #189 — issue de origem (premissa refutada no comentário de ground truth).
- #193 — bug acoplado: `agent_decide.py` passa `Path` em `DurableLedger(hmac_key: bytes)`.
- #182 / PR #188 — seam de injeção no `CrossAgentCorrelator`.
- ADR-0024 — Ledger Query API (`/v1/ledger/*`). ADR-0083 — ledger por tenant (Rust).
- ADR-0051 — `DurableLedger` (hash-chain + HMAC, in-process).
