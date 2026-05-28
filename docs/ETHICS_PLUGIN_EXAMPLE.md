# Ethics Plugin Example — Implementing `EthicsValidator`

> Exemplo mínimo de como estender o BTV com um motor ético customizado.
> Para o contrato completo, ver `rust/kernel/src/ethics_plugin.rs` e ADR-0082 §5.

## Quando usar

Implemente `EthicsValidator` quando precisar adicionar uma regra ética
ou regulatória ao pipeline de decisões. Motores futuros como Rawls (DIR),
Jonas (PSI), Levinas (alteridade) e Gilligan (cuidado/SLA) seguem
exatamente este padrão.

## Exemplo: `BlockAfterHoursValidator`

Bloqueia decisões automatizadas fora do horário comercial (08:00–18:00,
fuso UTC). Caso de uso: política de uma fintech que exige supervisão
humana para empréstimos noturnos.

```rust
// crates/my-tenant-plugins/src/after_hours.rs

use buildtovalue_kernel::ethics_plugin::{
    EthicsValidator, EthicsDecision, EthicsPluginError,
};
use buildtovalue_kernel::evidence::TechnicalEvidence;
use buildtovalue_kernel::core::types::BiasDeclaration;
use chrono::{Timelike, Utc};

pub struct BlockAfterHoursValidator;

impl EthicsValidator for BlockAfterHoursValidator {
    fn validate(
        &self,
        _evidence: &TechnicalEvidence,
    ) -> Result<EthicsDecision, EthicsPluginError> {
        let hour = Utc::now().hour();
        if (8..18).contains(&hour) {
            Ok(EthicsDecision::Allow)
        } else {
            Ok(EthicsDecision::Block {
                reason: "after_hours_decision",
                adr_ref: "tenant-policy-after-hours",
            })
        }
    }

    fn explain(&self) -> BiasDeclaration {
        // BiasDeclaration documenta o critério antes da execução —
        // garante explicabilidade mesmo se outro plugin bloquear primeiro.
        BiasDeclaration::default() // substitua por uma declaração assinada real
    }

    fn plugin_id(&self) -> &'static str {
        "block-after-hours"
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }
}
```

## Registro no gateway (`main.rs`)

```rust
use buildtovalue_kernel::ethics_plugin::EthicsPluginRegistry;
use my_tenant_plugins::after_hours::BlockAfterHoursValidator;

fn build_registry() -> EthicsPluginRegistry {
    EthicsPluginRegistry::new(vec![
        Box::new(BlockAfterHoursValidator),
        // adicionar outros plugins aqui — a ordem é a ordem de execução
    ])
}

fn main() {
    let registry = build_registry();
    // injetar `registry` no estado do axum / handler do Gatekeeper
}
```

## Invariantes que seu plugin DEVE respeitar

1. **Síncrono** — nada de `async fn` ou `Box<dyn Future>`. O trait é
   síncrono por design (zero heap no hot path; ver ADR-0082 §5).
2. **Sem `panic!`** — retorne `Err(EthicsPluginError)` em qualquer falha.
   O `EthicsPluginRegistry` converte erros em `BLOCK` automaticamente
   (fail-secure).
3. **`explain()` honesto** — declare o critério **antes** da execução.
   Vai aparecer no laudo mesmo se um plugin anterior bloquear (LGPD Art. 20).
4. **`plugin_id` único** — sufixe com a versão se houver coexistência
   (`rawls-v1`, `rawls-v2`).
5. **`&'static str` onde possível** — strings dinâmicas obrigam alocação.

## Como o Registry executa seu plugin

Ver `EthicsPluginRegistry::run_all` em `rust/kernel/src/ethics_plugin.rs`:

1. Chama `explain()` em **todos** os plugins → preenche `declarations`.
2. Itera `validate()` na ordem registrada.
3. Primeiro `Block` ou `Err` interrompe (short-circuit fail-secure).
4. Plugins não executados ficam em `skipped_plugins` no resultado.

## Testes recomendados

Mínimo (espelhando os testes do próprio crate):

- `allow_case` — entrada esperada produz `EthicsDecision::Allow`.
- `block_case` — entrada esperada produz `Block` com `reason` e `adr_ref` corretos.
- `error_propagates_as_block` — quando seu plugin retorna `Err`, o
  Registry traduz para `Block { reason: "plugin_execution_failed" }`.

## Referências

- `rust/kernel/src/ethics_plugin.rs` — contrato canônico
- ADR-0010 — BiasDeclaration Mandate
- ADR-0082 — API Evolution & Deprecation Policy (§5 Filosofia do Registry)
- `docs/API_ETHICS_GUIDE.md` — contrato HTTP completo
