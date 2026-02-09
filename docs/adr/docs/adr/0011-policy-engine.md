# ADR-011: Policy Engine Design (YAML to Runtime)

**Status:** 🔒 Planejado (v1.6)
**Crate:** `btv-kernel` (policy module)

## Decisão
Implementar um motor que compila regras YAML (`data/policies/`) em estruturas Rust otimizadas (phf - Perfect Hash Functions) em tempo de compilação ou inicialização, garantindo lookup O(1) para regras de bloqueio (Hard Blocks).