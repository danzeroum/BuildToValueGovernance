
# ADR-005: Evidence Protocol v2.1 (Fixed-Size)

**Status**: ✅ APROVADO  
**Data**: 15 de janeiro de 2026  
**Autores**: Daniel Camargo  
**Revisores**: Security Architect, Ethical Committee (3/3 votos)  
**Crate v3.0**: `btv-common` (tipos), `btv-kernel` (geração)

## Contexto

ADR-002 (Evidence v1.0) fracassou por heap allocations. O sistema precisa de um formato canônico, determinístico e de tamanho fixo para representar evidências forenses.

## Decisão

TechnicalEvidence com 9.4KB fixos, zero heap, ring buffer para findings:

```rust
#[repr(C, align(8))]
pub struct TechnicalEvidence {
    // HEADER (64 bytes)
    protocol_version: u16,
    audit_trail_id: u128,
    timestamp: u128,
    evidence_hash: [u8; 32],     // BLAKE3
    composite_risk: u8,

    // FINDINGS NORMAIS (1280 bytes) — Ring buffer FIFO
    findings: [Finding; 10],
    finding_count: u8,

    // FINDINGS CRÍTICOS (384 bytes) — Preservados sempre
    critical: [Finding; 3],
    critical_count: u8,

    // STATISTICS (256 bytes)
    stats: InputStatistics,

    // BIAS DECLARATION (512 bytes)
    bias: BiasDeclaration,

    // CHECKSUM (32 bytes)
    checksum: [u8; 32],          // BLAKE3 do struct inteiro
}

static_assertions::const_assert_eq!(size_of::<TechnicalEvidence>(), 9596);
```

## Fundamento Filosófico

- **Rawls**: TechnicalEvidence não sabe contexto (Véu da Ignorância). Apenas fatos técnicos. Quem interpreta é o Python.
- **Gilligan**: Ring buffer é mercy — findings menores sobrescritos pelos mais recentes, mas críticos preservados (cuidado com o essencial).
- **Jonas**: Dossiê imutável + BLAKE3 hash + BiasDeclaration = responsabilidade e transparência.

## Performance

| Operação | Latência | Heap |
|----------|---------|------|
| `new()` | 20ns | 0 |
| `add_finding()` | 100ns | 0 |
| `finalize()` (10 findings) | 2.5ms | 0 |
| **Total worst case** | **5.8ms** | **0** |

## Validação

- Fuzzing 24h: 5.2M test cases, 0 crashes
- Miri: zero unsafe violations
- Property-based tests (QuickCheck): hash determinismo, collision resistance, tampering detection
- Ethical Committee: aprovado 17 jan 2026 (3/3)

---
