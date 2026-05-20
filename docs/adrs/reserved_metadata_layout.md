[Docs](../README.md) › **Reserved Metadata Layout**

![Interno](https://img.shields.io/badge/Trilha-Contribuidor%20%2F%20Interno-6e7681)

<!-- audience: internal -->

---

# Reserved Metadata Layout — TechnicalEvidence._reserved_metadata[7072]

**Status:** DEFINIDO | **Data:** 2026-03-04 | **Referência:** ADR-005, ADR-033

## Layout Canônico

| Offset    | Bytes | Proprietário       | Descrição                          |
|-----------|-------|--------------------|------------------------------------|
| [0..8]    | 8     | ADR-033            | `pattern_epoch: u64` (LE)          |
| [8..40]   | 32    | PROP-031 (v1.5.1)  | `skill_hash: [u8; 32]` (BLAKE3)    |
| [40..44]  | 4     | PROP-030 (v1.6+)   | `recovery_evidence_tag: [u8; 4]`   |
| [44..45]  | 1     | PROP-038 (v1.7+)   | `policy_drift_detected: u8` (0/1)  |
| [45..7072]| 7027  | RESERVADO          | Futuras extensões                  |

## Invariante

Nenhuma proposta pode usar offsets fora deste mapa sem atualizar este documento
e o CI deve validar que `sizeof(TechnicalEvidence) == EVIDENCE_SIZE (9632)`.

## Referências

- ADR-033: PatternRegistry epoch em [0..8]
- PROP-031: skill_hash BLAKE3 em [8..40]
- PROP-030: recovery tag em [40..44]
- PROP-038: drift flag em [44..45]

---

### Próximos passos / Relacionados

- [Project Context](../PROJECT_CONTEXT.md)
- [Índice de ADRs (este arquivo NÃO faz parte dele)](../adr/0000-adr-index.md)

---

<sub>[↑ Hub](../README.md) · [Trilha Engenheiro](../for-engineers.md) · [Trilha DPO/CISO](../for-dpo-ciso.md) · [Links de Referência](../reference-links.md)</sub>
