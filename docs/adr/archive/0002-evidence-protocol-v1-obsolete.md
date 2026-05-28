# ADR-0002: Evidence Protocol v1 (OBSOLETO)

| Campo | Valor |
|-------|-------|
| **Status** | Obsoleto — Supersedido por ADR-0005 |
| **Supersedido por** | [0005-evidence-protocol-v2-fixed-size.md](../0005-evidence-protocol-v2-fixed-size.md) |
| **Arquivado em** | 2026-05-27 |
| **Motivo** | TechnicalEvidence v1 não possuía tamanho fixo canônico. A variação de payload quebrava a verificação BLAKE3 em ambientes de alta concorrência. Substituído pelo invariante de 9596 bytes fixos definido no ADR-0005. |

---

> ⚠️ Este documento está arquivado e não deve ser referenciado em implementações novas.
> Consulte `0005-evidence-protocol-v2-fixed-size.md` e `0063-technical-evidence-size-invariant.md`.
