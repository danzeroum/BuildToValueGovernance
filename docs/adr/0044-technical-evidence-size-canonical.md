# ADR-0044 — TechnicalEvidence: Tamanho Canônico 9596 bytes

**Status**: Accepted  
**Date**: 2026-03-05  
**Amends**: ADR-0005  
**Authors**: BuildToValue AI Squad  

## Contexto

ADR-0005 (§3) documentou o tamanho fixo do `TechnicalEvidence` como **9600 bytes**.  
A implementação atual do Rust kernel (v2.1) produz **9596 bytes** em runtime:

```rust
// rust/kernel/src/evidence.rs
const_assert_eq!(std::mem::size_of::<TechnicalEvidence>(), 9596);
```

A discrepância de 4 bytes gerou inconsistência entre documentos:

| Documento | Valor | Estado |
|---|---|---|
| `docs/adr/0005-evidence-protocol-v2-fixed-size.md` | 9600 | ❌ Incorreto |
| `docs/ARCHITECTURE_ATLAS.md` | 9596 | ✅ Correto |
| `docs/PROJECT_CONTEXT.md` | 9596 | ✅ Correto |
| Space Instructions (BuildToValue v3.0) | 9596 | ✅ Correto |

## Decisão

**9596 bytes é o valor canônico e imutável** para `TechnicalEvidence` v2.1.

ADR-0005 §3 fica emendado: substituir "9600 bytes" por "9596 bytes" em toda documentação.

A invariante verificável (golden suite PROP-035):

```python
TECHNICAL_EVIDENCE_SIZE_BYTES: int = 9596  # ADR-0044
assert TECHNICAL_EVIDENCE_SIZE_BYTES == 9596
```

Qualquer mudança de layout do `TechnicalEvidence` que altere esse valor constitui
breaking change e requer:
1. Novo ADR supersedendo este
2. Incremento de versão do Forensic Evidence Protocol
3. Atualização dos golden tests (PROP-035)
4. Novo benchmark de tamanho fixo

## Consequências

### Positivas
- Documentação alinhada com implementação real
- Golden suite (PROP-035) asserta `size == 9596` sem ambiguidade
- Elimina divergência entre ADR-0005, Atlas e Context

### Negativas
- Nenhuma: é correção documental exclusivamente, sem mudança de código

## Referências
- ADR-0005: Evidence Protocol v2 Fixed Size
- PROP-035: Alignment Regression CI
- `rust/kernel/src/evidence.rs`: implementação de referência
