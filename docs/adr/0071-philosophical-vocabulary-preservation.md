# ADR-071 — Preservação do Vocabulário Filosófico (Rawls / Levinas / Jonas / Gilligan)

**Status:** ACCEPTED
**Data:** 2026-05-20
**Autor:** AI Squad (Arquiteta Opus)
**Versão BTV alvo:** v1.6.x
**Relacionados:** ADR-038 (Ethical Context Engine v4 — 4 estágios nomeados), ADR-067 (Contestability — `VALID_GROUNDS`)

---

## Contexto

Foi levantada a proposta de **renomear** os identificadores filosóficos do
sistema (`rawls`, `levinas`, `jonas`, `gilligan`) para nomes funcionais
genéricos, sob o argumento de que os nomes próprios prejudicam a
descobribilidade para quem não conhece os autores.

Uma auditoria do repositório foi conduzida para dimensionar o impacto.

### Achado da auditoria

O vocabulário aparece em **283 ocorrências distribuídas por 47 arquivos**
(excluindo `archive/`), atravessando camadas críticas do sistema:

| Camada | Artefato | Natureza do impacto |
|---|---|---|
| Contrato de API | `spec/openapi.yaml` | Contrato público — *breaking change* para todos os consumers |
| Gateway (Rust) | `rust/gateway/src/routes/decide.rs` | Struct `ExplainDecision` com campos `rawls_rationale`, `levinas_rationale`, `jonas_rationale`, `gilligan_rationale` — requer recompilação |
| SDK Python | `sdk/python/buildtovalue/models.py` | Modelo Pydantic `ExplainDecision` — quebra serialização JSON |
| SDK JavaScript | `sdk/javascript/src/types.ts` | Tipo `AppealGrounds` (`rawls_equity`, `levinas_protection`, …) |
| Observabilidade | `python/.../metrics.py` | Label Prometheus `stage=rawls\|levinas\|jonas\|gilligan` — quebra dashboards Grafana existentes |
| Políticas | `data/policies/**/*.yaml` | 20+ arquivos de política com chaves nomeadas |
| Governança | `python/buildtovalue/governance/contestability_loop.py` | `VALID_GROUNDS` — vocabulário controlado formal |
| Decisões de arquitetura | ADR-038, ADR-067 | Estágios nomeados e `VALID_GROUNDS` já formalizados e aprovados |

Renomear não é uma operação de "buscar e substituir": é a quebra simultânea
de um contrato público de API, de dois SDKs, de dashboards de produção e de
duas ADRs já aceitas.

---

## Decisão

**Os identificadores filosóficos serão preservados.** Não haverá renomeação
unilateral de `rawls` / `levinas` / `jonas` / `gilligan` nas camadas de
código, API, políticas ou observabilidade.

A descobribilidade será resolvida por **documentação**, não por renomeação:
expondo melhor os *aliases* descritivos que já existem no repositório.

---

## Justificativa

### 1. Renomear quebraria o contrato semântico dos `AppealGrounds`

O conjunto `rawls_equity`, `levinas_protection`, `gilligan_mercy`,
`jonas_responsibility` é um **vocabulário controlado e formal**
(`VALID_GROUNDS`, definido como `frozenset` imutável em ADR-067) — usado
tanto na API REST quanto em ADRs aprovadas. Alterá-lo exigiria uma nova
versão de API (`/v2/`) com período de *deprecation*, não uma edição de texto.

### 2. Os nomes filosóficos carregam semântica que o nome funcional perde

Os nomes não são decorativos — eles nomeiam um teste específico:

- `rawls_equity` não é "por que a política foi aplicada"; é a garantia de
  que a decisão passaria pelo **Véu de Ignorância** (seria a mesma sem saber
  quem é o afetado).
- `levinas_protection` não é "impacto no usuário"; é o princípio de
  responsabilidade pelo **Outro vulnerável**.
- `jonas_responsibility` é o **imperativo da responsabilidade** sobre
  consequências futuras e irreversíveis.
- `gilligan_mercy` é a **ética do cuidado**: aplicação contextual da regra,
  com espaço para misericórdia/educação em vez de bloqueio rígido.

Nomes funcionais genéricos apagam essa distinção — que é precisamente o
diferencial acadêmico do BTV frente a *guardrails* genéricos.

### 3. A documentação já resolve o problema corretamente

`docs/compliance.md` já estabelece a separação correta: os nomes filosóficos
são os **identificadores de código**; as descrições em português são a
**documentação**.

```json
"rawls_rationale":    "Por que a política foi aplicada",
"levinas_rationale":  "Impacto no usuário",
"jonas_rationale":    "Risco de longo prazo",
"gilligan_rationale": "Por que (ou por que não) misericórdia foi aplicada"
```

Esta separação é correta **por design** e deve ser mantida.

---

## Tabela de Mapeamento — Identificador → Significado → Princípio Regulatório

Esta tabela é o artefato de descobribilidade canônico. Deve ser replicada no
Glossário do manual HTML.

| Identificador (`VALID_GROUNDS`) | Estágio | Significado funcional | Princípio regulatório operacionalizado |
|---|---|---|---|
| `rawls_equity` | Rawls — Equidade procedimental | A decisão passaria pelo Véu de Ignorância: seria idêntica sem saber quem é o afetado | LGPD Art. 6, IX (não discriminação); EU AI Act Art. 10 (exame de vieses em governança de dados) |
| `levinas_protection` | Levinas — Cuidado com o Outro | A decisão protege a parte vulnerável da interação | LGPD Art. 14 (tratamento de vulneráveis); EU AI Act Art. 9 (grupos vulneráveis na gestão de risco) |
| `jonas_responsibility` | Jonas — Responsabilidade de longo prazo | A decisão considera consequências futuras e potencialmente irreversíveis | EU AI Act Art. 9 (riscos razoavelmente previsíveis); princípio da precaução |
| `gilligan_mercy` | Gilligan — Ética do cuidado | Aplicação contextual da regra; possibilidade de educar/mitigar em vez de bloquear | LGPD Art. 20 (revisão de decisão automatizada); EU AI Act Art. 14 (supervisão humana) |

Os demais membros de `VALID_GROUNDS` (`technical_error`, `scope_mismatch`,
`false_positive`) são fundamentos de contestação não-filosóficos e não são
afetados por esta decisão.

---

## Ação de baixo custo e alto valor (em vez de renomear)

1. **Glossário no manual HTML** — adicionar a tabela de mapeamento acima ao
   Glossário do manual, ligando nome filosófico → significado funcional →
   artigo regulatório.
2. **Campo `summary` na API** — garantir que a resposta de
   `explain_decision()` consolide os quatro `*_rationale` em linguagem
   acessível, de modo que um consumer não precise conhecer os autores para
   entender a decisão.
3. **Esta ADR** — torna a decisão de preservar o vocabulário **rastreável e
   contestável**, em vez de implícita.

---

## Consequências

### Positivas

- Zero *breaking changes*: API pública, SDKs, políticas e dashboards
  permanecem estáveis.
- A identidade acadêmica diferencial do BTV é preservada.
- A decisão passa a ser explícita e auditável — pode ser revisitada via nova
  ADR caso uma migração `/v2/` planejada seja conduzida no futuro.

### Negativas / custo aceito

- A barreira de descobribilidade para quem desconhece os autores não é
  eliminada — é **mitigada** via documentação (Glossário + `summary`).
- Uma futura renomeação, se desejada, continuará sendo um projeto de
  versionamento de API, não uma edição trivial.

### Escopo explicitamente fora desta decisão

Esta ADR **não** proíbe uma futura renomeação. Caso o projeto decida migrar
para nomes funcionais, isso deverá ser objeto de uma nova ADR que trate de:
versionamento `/v2/` da API, período de *deprecation*, migração de
dashboards e atualização coordenada dos SDKs.

---

## Status de Implementação

- [x] Auditoria de impacto concluída (283 ocorrências / 47 arquivos)
- [x] Decisão de preservação formalizada (esta ADR)
- [ ] Tabela de mapeamento adicionada ao Glossário do manual HTML
- [ ] Verificação de que o campo `summary` da API consolida os 4 `*_rationale`
