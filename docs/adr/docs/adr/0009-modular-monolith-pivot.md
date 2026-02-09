# ADR-009: Modular Monolith Architecture (Reconciled)

**Status**: ✅ APROVADO (revisão 2)
**Data Original**: 08 de fevereiro de 2026
**Data Revisão**: 09 de fevereiro de 2026
**Autores**: Daniel Camargo, Staff Engineer
**Impacto**: TODOS os crates e módulos Python

## Contexto

A v2.2 ("Golden Record") definiu dois hemisférios físicos (rust/ + python/)
com identidade PyPI `buildtovalue` e crate `buildtovalue-kernel`. 
A proposta v3.0 original tentou criar 7 crates novos (`btv-common`, 
`btv-kernel`, `btv-governance`, `btv-slm`, `btv-notary`, `btv-ledger`, 
`btv-gateway`) com namespace `btv-*`, quebrando identidade, fragmentando
o workspace, e ignorando código real existente (~3000 linhas Rust, 
~2000 linhas Python funcionando).

Três problemas da proposta original:
1. **Namespace break**: `btv-*` perde identidade PyPI `buildtovalue`
2. **Over-engineering**: 7 crates para equipe solo = overhead de CI/CD
3. **Rewrite risk**: Meses de código descartado sem necessidade

## Decisão (Revisada)

**Monolito Modular Incremental**: manter a estrutura física v2.2 como base,
reorganizando internamente para absorver os benefícios do monolito modular.

### O que MUDA (v2.2 → v3.0):

| Aspecto | v2.2 | v3.0 Reconciliado |
|---------|------|-------------------|
| Web framework | FastAPI only | FastAPI (v1.5-v1.8) → Axum (v1.9+) |
| Axum crate | Não existe | `rust/gateway/` (ÚNICO crate novo) |
| Node.js BFF | Não existe | Confirmado: NUNCA existirá |
| gRPC | Não existe | Confirmado: NUNCA existirá |
| Módulos lógicos | Subdiretórios em kernel/ | Mesmos subdiretórios (sem mudança) |
| Workspace members | kernel, bindings, cli | kernel, bindings, cli, gateway (v1.9+) |
| Package names | `buildtovalue-kernel` | Preservado (sem mudança) |
| Python namespace | `buildtovalue.*` | Preservado (sem mudança) |

### O que NÃO MUDA:
- `rust/kernel/` continua como crate único (módulos internos, não crates separados)
- `rust/bindings/` continua como ponte PyO3/Maturin
- `python/buildtovalue/` continua como namespace hierárquico
- `data/policies/` continua como shared state
- `Cargo.toml` raiz continua como workspace root
- Identidade PyPI e crates.io preservada

### Workspace Evolution Timeline:
```toml
# v1.5-v1.8 (atual):
members = ["rust/kernel", "rust/bindings", "rust/cli"]

# v1.9+ (quando Axum for implementado):
members = ["rust/kernel", "rust/bindings", "rust/cli", "rust/gateway"]
```

## Alternativas Consideradas

| Alternativa | Rejeitada porque |
|-------------|-----------------|
| 7 crates separados (btv-*) | Overhead de CI/CD, namespace break, rewrite risk |
| Manter FastAPI forever | Axum unifica stack Tokio, elimina superfície Python no serving |
| Migração big-bang | Viola Anti-Burnout Protocol; risco de regressão |

## Fundamento Filosófico

- **Jonas (Proporcionalidade)**: Mudança incremental é proporcional ao 
  estágio do projeto. Rewrite completo com equipe solo é irresponsável.
- **Rawls (Equidade)**: Estrutura simples democratiza contribuições. 
  7 crates com dependências cruzadas exclui contribuidores ocasionais.

## Consequências

- **Positivas**: Zero rewrite, identidade preservada, CI/CD simples,
  contribuidores existentes não perdem contexto.
- **Negativas**: Kernel cresce em LOC (mitigação: módulos internos 
  bem separados, ≤ 200 linhas por arquivo).
- **Riscos**: Gateway Axum pode ter conflito de deps com PyO3 
  (mitigação: crate separado, conditional compilation).

## Conformidade
- NIST SP 800-53 (CM-3: Configuration Change Control)
- ISO 42001 (6.1.2: Risk Assessment — mudança incremental reduz risco)