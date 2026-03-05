# ADR-0044 — TechnicalEvidence: Tamanho Canônico 9632 bytes

**Status**: Accepted  
**Date**: 2026-03-05  
**Amends**: ADR-0005  
**Authors**: BuildToValue AI Squad  

## Contexto

ADR-0005 (§3) documentou o tamanho fixo do `TechnicalEvidence` como **9600 bytes**.
Documentos intermediários circularam com 9596 bytes.
A implementação real do Rust kernel (v2.1) produz **9632 bytes** em runtime:

```rust
// rust/kernel/src/evidence/technical.rs
const_assert_eq!(std::mem::size_of::<TechnicalEvidence>(), 9632);
// _reserved_metadata: [u8; 7072] — layout que produz 9632
```

Layout do `TechnicalEvidence` (campos confirmados no código real):

| Campo | Tamanho (bytes) |
|---|---|
| Header / metadata | 64 |
| Hash (BLAKE3) | 32 |
| BiasDeclaration | 512 |
| Context evidence | 1872 |
| Flags / version | 16 |
| `_reserved_metadata` | 7072 |
| HMAC-SHA256 | 32 |
| Padding / alinhamento | 32 |
| **Total** | **9632** |

Histórico de valores circulantes:

| Documento | Valor | Estado |
|---|---|---|
| ADR-0005 (original) | 9600 | ❌ Incorreto |
| Documentos intermediários | 9596 | ❌ Incorreto |
| `core/types.rs` (`EVIDENCE_SIZE`) | 9632 | ✅ Correto |
| `technical.rs` (`const_assert_eq!`) | 9632 | ✅ Correto |

## Decisão

**9632 bytes é o valor canônico e imutável** para `TechnicalEvidence` v2.1.

ADR-0005 §3 fica emendado: substituir qualquer valor anterior por **9632 bytes**.

A invariante verificável (golden suite PROP-035):

```python
TECHNICAL_EVIDENCE_SIZE_BYTES: int = 9632  # ADR-0044
assert TECHNICAL_EVIDENCE_SIZE_BYTES == 9632
```

Qualquer mudança de layout do `TechnicalEvidence` que altere esse valor constitui
breaking change e requer:
1. Novo ADR supersedendo este
2. Incremento de versão do Forensic Evidence Protocol
3. Atualização dos golden tests (PROP-035)
4. Re-verificação dos checklists PROP-029, PROP-031 e PROP-038

## Consequências

### Positivas
- Documentação alinhada com implementação real (`EVIDENCE_SIZE` em `core/types.rs`)
- Golden suite asserta `size == 9632` sem ambiguidade
- Elimina divergência histórica: ADR-0005 (9600) → docs intermediários (9596) → código (9632)

### Negativas
- Nenhuma: é correção documental exclusivamente, sem mudança de código

## Referências

- ADR-0005: Evidence Protocol v2 Fixed Size
- PROP-035: Alignment Regression CI
- `rust/kernel/src/evidence/technical.rs`: `const_assert_eq!` de referência
- `rust/kernel/src/core/types.rs`: `EVIDENCE_SIZE = 9632`
