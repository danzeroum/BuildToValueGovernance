# ADR-013: Deobfuscation Chaining Strategy

**Status:** 🔒 Planejado (v1.6)
**Crate:** `btv-kernel` (deobfuscator module)

## Decisão
O Kernel implementa um loop de deobfuscação com `max_depth = 3`.
1. Tenta decodificar (Base64 -> Hex -> Leet).
2. Se após 3 tentativas o texto continuar ofuscado/ilegível, marca como `CRITICAL_RISK` (Tentativa de Evasão Ativa).