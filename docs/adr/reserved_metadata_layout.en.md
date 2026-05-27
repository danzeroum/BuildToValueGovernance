[BuildToValue](../../README.md) › [Documentation](../README.md) › **Reserved Metadata Layout**

![Internal](https://img.shields.io/badge/Track-Contributor%20%2F%20Internal-6e7681)

<!-- audience: internal -->

---

# Reserved Metadata Layout — TechnicalEvidence._reserved_metadata[7072]

**Status:** DEFINED | **Date:** 2026-03-04 | **Reference:** ADR-005, ADR-033

## Canonical layout

| Offset    | Bytes | Owner              | Description                        |
|-----------|-------|--------------------|------------------------------------|
| [0..8]    | 8     | ADR-033            | `pattern_epoch: u64` (LE)          |
| [8..40]   | 32    | PROP-031 (v1.5.1)  | `skill_hash: [u8; 32]` (BLAKE3)    |
| [40..44]  | 4     | PROP-030 (v1.6+)   | `recovery_evidence_tag: [u8; 4]`   |
| [44..45]  | 1     | PROP-038 (v1.7+)   | `policy_drift_detected: u8` (0/1)  |
| [45..7072]| 7027  | RESERVED           | Future extensions                  |

## Invariant

No proposal may use offsets outside this map without updating this document,
and CI must validate that `sizeof(TechnicalEvidence) == EVIDENCE_SIZE (9632)`.

## References

- ADR-033: PatternRegistry epoch at [0..8]
- PROP-031: BLAKE3 skill_hash at [8..40]
- PROP-030: recovery tag at [40..44]
- PROP-038: drift flag at [44..45]

---

### Next steps / Related

- [Project Context](../PROJECT_CONTEXT.md)
- [ADR Index (this file is NOT part of it)](../adr/0000-adr-index.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
