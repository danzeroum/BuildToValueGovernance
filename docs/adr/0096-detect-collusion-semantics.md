# ADR-0096: Semântica de `detect_collusion` (C6 — coordenação multi-agente)

**Status**: ✅ ACEITO (documenta comportamento já implementado)
**Data**: 30 de maio de 2026
**Autores**: IA Arquiteta
**Impacto**: `python/buildtovalue/governance/cross_agent_correlator.py`
             (`detect_collusion`); `python/buildtovalue/api/routes/agents.py`
             (endpoint `POST /v1/a2a/scan`).
**Pré-requisitos**: nenhum — o comportamento já está em `main` (commits
             `b6ba66e`, `8413a72`); este ADR formaliza o contrato, sem mudança
             de código.

---

## Contexto

A issue #181 identificou um *type mismatch* latente em `POST /v1/a2a/scan`:
`detect_collusion` declara `Dict[str, List[str]]` mas era chamado com
`Dict[str, str]` (`payload[:64]`). A rota inline original não estava sob
`mypy --strict`, então o mismatch passou despercebido até a extração do Router 4.

A issue exigiu explicitamente uma **decisão semântica** antes de qualquer
correção, sob o invariante de que a detecção de conluio (controle de segurança
**C6**) **não pode ser enfraquecida**. A correção foi implementada em `b6ba66e`
(+ Bug 2 em `8413a72`); este ADR documenta a semântica resultante como contrato
explícito — distinguindo o que o contrato **garante** do que é **comportamento
emergente** ainda não especificado.

## Decisão

### 1. Contrato de `detect_collusion`

```python
def detect_collusion(self, agent_actions: Dict[str, List[str]]) -> Optional[str]
```

- **Entrada**: mapa `agent_id -> lista de strings de ação`. Cada string pode ser
  um nome de ação exato **ou** um blob de payload (ex.: conteúdo de mensagem A2A).
- **Saída**: a `reason` (string) do **primeiro** padrão de conluio que casar, ou
  `None` se nenhum casar. **Nunca** um `dict` ou booleano (regressão do #181
  Bug 2, em que o endpoint testava `isinstance(collusion, dict)` e por isso
  reportava `False` permanentemente).

### 2. Semântica de correspondência (homologada)

- **Substring-explícito**: um *role* `{"action": K}` casa com um agente quando o
  keyword `K` aparece como **substring** de qualquer string da lista daquele
  agente — `any(K in action for action in actions)`. Nomes de ação exatos
  continuam casando como caso especial (`K == action`).
- **`AND` dentro de um padrão**: um padrão só dispara quando **todos** os seus
  roles forem satisfeitos, cada um por um agente **distinto** (um agente não
  preenche dois roles).
- **`OR` entre padrões**: basta **um** padrão casar; retorna a `reason` dele.
- **Simétrico / sem direção**: a detecção independe de qual agente preenche qual
  role e da ordem das ações. `{A:[x], B:[y]}` e `{A:[y], B:[x]}` são equivalentes.
- **Fonte dos padrões**: `collusion_patterns` do YAML de política
  (`agents: [{action: ...}], reason: ...`). Sem padrões configurados,
  `detect_collusion` sempre retorna `None`.

### 3. Preservação de C6 (invariante não-negociável)

A mudança de `role_action in actions` (operando sobre o valor) para
`any(role_action in action for action in actions)` (sobre os elementos da lista),
combinada com a chamada passando `[payload[:64]]`, é um **superset comportamental**:

| Caminho | Matcher antigo | Matcher novo | Resultado |
|---|---|---|---|
| Produção real (valor `str`) | substring na string | `[str]` + `any(... in ...)` | **idêntico** |
| Lista real (prometida pela assinatura, nunca usada) | match **exato** de elemento | substring por elemento | **mais forte** (⊇) |

Logo, C6 é **preservado** no caminho de produção e **fortalecido** no caminho que
a assinatura prometia. Coberto por testes de regressão positivos e negativos
(`tests/unit/governance/test_cross_agent_correlator.py::TestCollusionDetection`,
`tests/integration/test_a2a_scan.py`) e por um liveness guard (ADR do #185,
`test_control_activation.py`) que prova que o controle é capaz de disparar.

## Comportamento emergente — NÃO garantido pelo contrato

Os pontos a seguir são consequências da implementação atual, **não** garantias.
Alterá-los é mudança de contrato e exige novo ADR:

- **Substring sem fronteira de palavra**: `K="read"` casa dentro de
  `"already"`/`"spread"`. É deliberado para capturar keywords embutidas em
  payloads livres, ao custo de possíveis falsos-positivos. Word-boundary **não**
  é garantido.
- **Sem normalização**: a correspondência é *case-sensitive* e não normaliza
  espaços, unicode ou encoding. `"Read_Secrets"` não casa `"read_secrets"`.
- **Primeiro-match, não todos**: retorna a `reason` do primeiro padrão; não
  enumera múltiplos conluios simultâneos.
- **Apenas ações declaradas**: opera sobre as strings fornecidas pelo caller.
  **Não** modela identidade (pubkeys/endereços), intenção, nem *drift* ético, e
  não inspeciona metadados de oráculos. Conluio aqui é **co-ocorrência de
  keywords de ação**, não inferência de propósito.
- **Independência do ledger (#182)**: `detect_collusion` não escreve no
  `DurableLedger` nem usa o `AlignmentDegradationTracker`. A injeção de ledger do
  #182 toca apenas o tracker de degradação; o caminho de conluio é ortogonal.

## Consequências

- O #181 está **resolvido**: type mismatch corrigido, assinatura honesta,
  `# type: ignore[dict-item]` removido, regressão coberta, `mypy --strict` limpo.
- Expansões futuras de casos A2A (ex.: word-boundary, conluio por intenção,
  enumeração de múltiplos padrões) partem deste contrato e exigem ADR próprio,
  pois cruzam a fronteira do que hoje é emergente.
- O invariante C6 (não enfraquecer a detecção de conluio) fica registrado como
  critério de aceite para qualquer mudança nesta superfície.
