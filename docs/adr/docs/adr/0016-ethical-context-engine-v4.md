# ADR-016: Ethical Context Engine v4.0

**Status:** 🔒 Planejado (v1.8)
**Crate:** `btv-governance` (Python)

## Decisão
Formalizar o pipeline de decisão ética em Python:
1. **Rawls (Equidade):** Blind test do input.
2. **Levinas (Cuidado):** Verifica vulnerabilidade do usuário.
3. **Jonas (Proporcionalidade):** Custo da ação vs Risco.
4. **Gilligan (Misericórdia):** Aplica o ADR-003 se incerteza for alta.

Obrigatório uso de `explain_decision()` retornando rationale legível.