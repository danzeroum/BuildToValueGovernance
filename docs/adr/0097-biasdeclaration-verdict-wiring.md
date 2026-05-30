# ADR-0097: Fiação da `BiasDeclaration` calibrada até o `VerdictRecord`

**Status**: ✅ ACEITO — Q1 + Q2(Opção A) implementadas
**Data**: 30 de maio de 2026
**Autores**: IA Arquiteta
**Impacto**: `rust/btv-executive/src/gatekeeper_bridge.rs` (`ScanResult`,
             conversão `ev.bias` → tipo de wire); `rust/btv-core/src/verdict.rs`
             (`Verdict::new`, `to_record`); call sites de `Verdict::new`
             (1 produção + testes/benches). **Possivelmente** o wire format em
             `rust/btv-types/src/lib.rs` — ver Decisão.
**Pré-requisitos**: ADR-0060 (construtor obrigatório de `BiasDeclaration`),
             ADR-0063 (wire format `TechnicalEvidence` de 9596 bytes).

---

## Contexto

ADR-0060 tornou `bias_declaration` um campo **obrigatório** do `VerdictRecord`
(`btv_types::BiasDeclaration`, não `Option`). A garantia de **tipo** existe: é
impossível serializar um veredito sem o campo. Mas o **valor** real nunca chega
ao registro.

### O gap (rastreado ponta a ponta)

Os ~15 validators do kernel declaram bias calibrado por módulo, e o gatekeeper
**já agrega** o pior caso:

```
kernel/gatekeeper.rs:307   evidence.bias = BiasDeclaration::aggregate(worst-case)   ✅ calculado
        │
        ▼
gatekeeper_bridge.rs:84    let ev = ...scan_for_evidence()      ← ev.bias EXISTE aqui
        │
        ▼
gatekeeper_bridge.rs:125   ScanResult { findings, ... }         ❌ ev.bias é DESCARTADO
        │                  (struct ScanResult, linhas 16-26: não tem campo bias)
        ▼
executive.rs:121           Verdict::new(evidence, compliance, decision, explanation)
        │                  ← bias nunca é passado
        ▼
verdict.rs:74              bias_declaration: bootstrap_unvalidated()   ← placeholder hardcoded
```

O elo morto está em **`gatekeeper_bridge.rs:125`**: `ScanResult` não possui campo
`bias`, então o valor agregado é silenciosamente perdido. Em produção, **todo
veredito declara bias `UNVALIDATED`** independentemente do que os validators
mediram — o `bootstrap_unvalidated()` injeta a string `"UNVALIDATED"` que dispara
alertas de auditoria no Dashboard e nunca deveria sobreviver a um PoC externo.

Não há divergência de comportamento em relação aos ADRs — o bootstrap é um estado
de transição **declarado** nos comentários (`verdict.rs:63`, `lib.rs:234`). É um
gap de fiação, não de contrato.

### Impedância de tipos descoberta durante o ground truth

A fiação **não é** propagar um valor: existem **dois tipos `BiasDeclaration`
distintos e não convertíveis por cópia**.

| Campo | `kernel::core::types::BiasDeclaration` (origem, `ev.bias`) | `btv_types::BiasDeclaration` (destino, `VerdictRecord`) |
|---|---|---|
| `false_positive_rate: f32` | ✅ | ✅ |
| `false_negative_rate: f32` | ✅ | ✅ |
| `calibration_date: u32` | ✅ | — (ausente) |
| `test_dataset_size: u32` | ✅ | — (ausente) |
| `affected_groups: [u8;128]` | ✅ (grupos **afetados** pelo viés) | — |
| — | | `validated_groups: Vec<String>` (grupos **validados**) |
| `known_limitations: [u8;256]` (texto livre) | ✅ | — |
| — | | `known_disparities: Vec<KnownDisparity>` (estruturado) |
| — | | `measurement_tool_version: String` |

Apenas `fpr`/`fnr` mapeiam de forma limpa. Não há `impl From` existente, e o
crate `kernel` nem depende de `btv_types`.

**Risco semântico crítico**: `affected_groups` (kernel) e `validated_groups`
(btv_types) são **conceitos opostos** — grupos *impactados negativamente* vs.
grupos para os quais o modelo foi *explicitamente validado*. Copiar um no outro
fabricaria dado de fairness e enganaria a auditoria/LGPD Art. 20. **Esta inversão
é proibida sob qualquer decisão deste ADR.**

---

## Decisão

Este ADR decide **duas** questões.

### Q1 — Onde a `BiasDeclaration` entra no `Verdict` (resolvida)

**O valor entra via `Verdict::new` (sole-constructor, Paper 1 Def. 4.1).**

`Verdict::new` ganha um parâmetro de bias, armazenado como campo privado;
`to_record()` lê `self.bias` em vez de chamar `bootstrap_unvalidated()`. Os call
sites de `Verdict::new` passam o argumento; o compilador garante que **nenhum
`Verdict` pode ser criado sem bias real**.

Rejeitada a alternativa "threadar por fora" (`to_record_with_bias(bias)`): o
`hmac_tag` do `VerdictRecord` sela `evidence_hash ‖ decision ‖ explanation` mas
**não** o bias. Se o bias não entra no `Verdict`, ele jamais integra a cadeia de
construção do veredito — fica anexado a posteriori no call site, sem garantia de
tipo. A garantia "signed-at-construction" exige passar pelo construtor.

**Blast-radius**: exatamente **1** call site de produção constrói o
`VerdictRecord` (`verdict.rs::to_record`), via 1 call site de produção de
`Verdict::new` (`executive.rs:121`). Os demais (`hmac_verify.rs`,
`judicial/integration.rs`, `unit_sole_entry_point.rs`, `judicial.rs`) são
teste/bench e só precisam passar o novo argumento.

### Q2 — Como converter `kernel::BiasDeclaration` → tipo de wire (EM ABERTO)

Esta é a decisão central que requer revisão humana antes de qualquer código.

#### Opção A — Mapa conservador (recomendada)

Converter apenas o que é semanticamente seguro:

- `false_positive_rate`, `false_negative_rate` ← valores **reais** agregados do kernel
- `measurement_tool_version` ← `"kernel-aggregate-v<N>"` (proveniência explícita)
- `validated_groups` ← `["aggregated-worst-case — see per-module docs"]`
  (declara honestamente a origem; **não** copia `affected_groups`)
- `known_disparities` ← `[]`

`calibration_date` e `test_dataset_size` do kernel **não têm destino** em
`btv_types::BiasDeclaration` e são omitidos (ou preservados apenas na variante
`Fixed` via hash, se desejável num passo futuro).

- **Wire format**: `BiasDeclarationFixed` permanece intacto — o assert de
  9596 bytes (`btv-types/src/lib.rs:382`) **não é tocado**.
- **Consequência**: a string `"aggregated-worst-case"` aparecerá em auditoria,
  dashboards e potencialmente respostas LGPD Art. 20. Isto é **comportamento
  intencional e documentado**, não um placeholder — substitui o `UNVALIDATED`
  enganoso por uma declaração honesta de que fpr/fnr são calibrados mas a
  validação por grupo é responsabilidade dos módulos individuais.
- **Ganho imediato**: fpr/fnr reais passam a integrar todo veredito; o sinal
  `UNVALIDATED` deixa de poluir produção.

#### Opção B — Mapa lossless (estender `btv_types::BiasDeclaration`)

Adicionar `calibration_date`, `test_dataset_size` e um campo de grupos afetados a
`btv_types::BiasDeclaration` para que a conversão não perca informação.

- **Wire format**: muda `BiasDeclarationFixed` → **quebra o assert de 9596 bytes**
  (`btv-types/src/lib.rs:382`). Isso é uma **emenda ao wire format constitucional**
  (ADR-0063), não uma mudança de implementação.
- **Consequência**: exige processo de emenda constitucional próprio (Paper 6) e
  re-validação de toda a fronteira FFI de 9596 bytes. Blast-radius grande.

#### Recomendação e decisão

**Opção A (conservador) — aceita e implementada.** Ela fecha o elo morto,
entrega fpr/fnr calibrados em produção e elimina o `UNVALIDATED` enganoso **sem**
tocar o wire format constitucional. A Opção B pode ser um ADR futuro se a
auditoria exigir calibration_date/dataset_size no registro persistido — mas essa
é uma emenda constitucional que não deve ser acoplada a um fix de fiação.

---

## Invariantes

1. **A conversão NUNCA copia `affected_groups` (kernel) para `validated_groups`
   (btv_types).** São conceitos opostos; a inversão é proibida e deve ser coberta
   por teste.
2. O bias entra no `Verdict` **via `Verdict::new`** — nunca anexado a posteriori.
3. Sob a Opção A, o assert `size_of::<TechnicalEvidence>() == 9596` permanece
   verdadeiro e não é alterado.

## Consequências

- **Positivas**: produção passa a declarar fpr/fnr reais; `UNVALIDATED` some do
  caminho feliz; garantia signed-at-construction reforçada pelo compilador.
- **Negativas (Opção A)**: `validated_groups` carrega uma string de proveniência,
  não grupos reais — auditoria precisa saber que validação por grupo continua nos
  docs por módulo até medição dedicada existir.
- **Trabalho futuro**: medição real de `validated_groups`/`known_disparities`
  por jurisdição; eventual Opção B se o registro persistido precisar de
  calibration_date.

## Status de implementação

Implementado (Opção A). Mudanças:

- `btv-core/src/verdict.rs`: `Verdict` ganha campo privado `bias`; `Verdict::new`
  recebe `bias: BiasDeclaration` (5º parâmetro); `to_record()` e
  `to_technical_evidence()` leem `self.bias` em vez de `bootstrap_unvalidated()`.
- `btv-executive/src/gatekeeper_bridge.rs`: `ScanResult` ganha campo `bias`;
  novo `map_kernel_bias()` aplica o mapa conservador (fpr/fnr reais; proveniência
  explícita em `validated_groups`; nunca copia `affected_groups`).
- `btv-executive/src/executive.rs`: passa `scan.bias` para `Verdict::new`.
- Testes: `unit_gatekeeper_bridge.rs` cobre (a) bias não-bootstrap e (b) o
  invariante de proveniência. O golden trybuild `verdict_struct_literal.stderr`
  foi regenerado e agora também ancora `bias` como campo privado.

Wire format inalterado: `size_of::<TechnicalEvidence>() == 9596` continua válido.
