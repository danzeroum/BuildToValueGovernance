# ADR-043: Unified Verdict Identity — REPORT como 4º Veredicto + verdict_id Determinístico

**Status:** Aceito  
**Data:** 2026-03-08  
**Autores:** AI Squad (Arquiteta)  
**Supera:** placeholder vazio (0 bytes)  
**Relacionados:** ADR-004 (Immutable Ledger), ADR-017 (Contestability), ADR-039 (TrustScore v2), ADR-042 (Policy-as-Code v2)

---

## Contexto

O `EthicalVerdict` atual possui 5 variantes: `Pending/Allow/Educate/Redact/Block`. O `Action` enum possui `Allow/Log/Block/Redact`. Há assimetria deliberada: `Educate` existe em `ActionType` (ledger) mas não em `Action` (gatekeeper). Essa assimetria indica que os dois enums têm semânticas distintas — `Action` é o que o kernel *executa*, `EthicalVerdict` é o que o Python Governance *declara*.

O problema identificado: não existe veredicto para o caso em que a decisão é **registrar e encaminhar para revisão humana sem bloquear nem permitir silenciosamente**. `Educate` e `Redact` são transformações do conteúdo. `Block` é terminal. `Allow` é permissivo. Nenhum deles cobre o caso de *flagging auditável sem ação imediata* — necessário para compliance (LGPD Art. 37, logs de tratamento) e para o fluxo de contestabilidade (ADR-017).

Adicionalmente, veredictos no ledger são identificados apenas por `entry_id: u64` sequencial. Isso torna impossível verificar a integridade de um veredicto específico fora do contexto do ledger completo — violando o princípio de evidência forense isolável.

---

## Decisão

### 1. `REPORT` como 4º veredicto ético

Adicionar `Report = 5` ao enum `EthicalVerdict`:

```rust
pub enum EthicalVerdict {
    Pending  = 0,
    Allow    = 1,
    Educate  = 2,
    Redact   = 3,
    Block    = 4,
    Report   = 5,   // ← novo: flagging auditável sem ação terminal
}
```

**Semântica de `Report`:**
- O request é processado normalmente (não bloqueado).
- Um finding auditável é gerado e persistido no ledger com `ethical_verdict = Report`.
- O evento é encaminhado ao fluxo de contestabilidade (ADR-017) com SLA 24h.
- Usado quando: risco detectado mas abaixo do threshold de bloqueio; situação requer revisão humana; compliance exige registro sem interrupção de serviço.

**`Report` NÃO substitui `Educate` nem `Redact`:**
- `Educate`: transforma o output para o usuário (adiciona contexto).
- `Redact`: remove conteúdo do output.
- `Report`: não altera output; apenas registra e encaminha.

### 2. `verdict_id` determinístico via HMAC-SHA256

Cada veredicto recebe identidade criptográfica derivada de seus componentes:

```
verdict_id = HMAC-SHA256(
    key       = ledger_signing_key,
    message   = evidence_hash ‖ action_u8 ‖ trail_id [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/14874737/e1f2a343-8c00-4fd3-85fb-77b26729c227/sinteseDeDefesaAataques.txt)
)
```

- `evidence_hash`: BLAKE3 hash dos 9596 bytes do `TechnicalEvidence` (ADR-005).
- `action_u8`: valor `#[repr(u8)]` do `EthicalVerdict` (1 byte).
- `trail_id`: `entry_id: u64` do `LedgerEntry` (8 bytes, little-endian).
- `ledger_signing_key`: chave HMAC do operador, configurável via Policy (ADR-042).

**Propriedades:**
- Determinístico: mesmos inputs → mesmo `verdict_id`.
- Verificável fora do ledger: qualquer auditor com a chave pode recomputar.
- Não forjável sem `ledger_signing_key`.
- Contestável: `verdict_id` é o identificador primário no fluxo de appeal (ADR-017 §3).

### 3. Arquivos afetados

| Arquivo | Mudança |
|---|---|
| `rust/kernel/src/core/types.rs` | `EthicalVerdict::Report = 5` |
| `rust/kernel/src/ledger/entry.rs` | Campo `verdict_id: [u8; 32]` em `LedgerEntry` + HMAC-SHA256 |
| `rust/kernel/src/ledger/entry.rs` | `ActionType::Report = 5` (sincronizar com `EthicalVerdict`) |
| `python/buildtovalue/governance/` | Emissão de `Report` pelo Python Governance quando threshold parcial |
| `data/policies/*.yaml` | Campo `report_threshold: f32` nas políticas (ADR-042) |

---

## Alternativas Consideradas

| Alternativa | Descartada por |
|---|---|
| Usar `Log` (Action) como equivalente de Report | `Log` é ação de kernel, não veredicto ético — semânticas incompatíveis |
| UUID v4 aleatório como `verdict_id` | Não verificável deterministicamente; impossível recomputar para auditoria |
| SHA-256 simples (sem HMAC) | Sem autenticação de origem; forjável por terceiros com acesso ao ledger |
| Reutilizar `entry_id` como identidade | Sequencial, não criptográfico; não isola o veredicto do contexto do ledger |
| `Educate` para casos de flagging | Altera output do usuário — semântica errada para casos de compliance silencioso |

---

## Consequências

**Positivas:**
- Veredictos são isoladamente verificáveis — auditoria forense sem reconstruir ledger completo.
- `Report` preenche lacuna de compliance LGPD Art. 37 (registro de operações de tratamento).
- Contestabilidade (ADR-017) ganha identificador estável para appeals.
- Determinismo do `verdict_id` permite deduplicação de veredictos idênticos.

**Negativas / Riscos:**
- `LedgerEntry` cresce 32 bytes (384 → 416 bytes) — requer atualização de `static_assertions` e ADR-044.
- `ActionType` precisa de `Report = 5` para manter sincronismo com `EthicalVerdict`.
- Políticas YAML existentes sem `report_threshold` devem ter default seguro (`1.0` = nunca reportar sem configuração explícita).
- `ledger_signing_key` ausente em ambiente de teste — `verdict_id` deve usar chave zero `[0u8; 32]` apenas em `#[cfg(test)]`.

---

## Implementação

| Fase | Status | Release |
|---|---|---|
| Definição de `EthicalVerdict::Report` | 🔲 Pendente | v1.6.0 |
| `verdict_id` em `LedgerEntry` + HMAC | 🔲 Pendente | v1.6.0 |
| Python Governance emite `Report` | 🔲 Pendente | v1.6.0 |
| Policy YAML `report_threshold` | 🔲 Pendente | v1.6.0 |

---

## Fundamento Filosófico

Rawls: decisões que afetam indivíduos devem ser identificáveis e contestáveis — um veredicto sem identidade criptográfica é uma decisão sem responsável verificável. `verdict_id` é a assinatura da República Algorítmica em cada ato de governança.
ADREOF


