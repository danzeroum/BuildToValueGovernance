# ADR-002: Evidence Protocol v1.0

**Status**: ⛔ OBSOLETO — Substituído por ADR-005  
**Data**: Novembro 2025  
**Motivo da Descontinuação**: Heap allocations no hot path causavam latência imprevisível

## Decisão (Histórica)

```rust
// v1.0 — DESCONTINUADO
pub struct TechnicalEvidence {
    findings: Vec<Finding>,  // ❌ Tamanho variável, heap allocation
}
```

## Problemas Detectados

- p50: 12ms, p99: 180ms (variação 15×)
- 5–50 heap allocations por request
- Memory leaks após 10k requests em stress test
- Impossibilidade de zero-copy FFI

## Lição Aprendida

Estruturas de dados no hot path de um sistema de governança em tempo real não podem ter tamanho variável. A previsibilidade é um requisito de segurança, não apenas de performance.

**Substituído por**: ADR-005 (Evidence Protocol v2.1, 9.4KB fixo)

---
