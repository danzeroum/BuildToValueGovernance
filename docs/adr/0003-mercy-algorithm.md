# ADR-003: Mercy Algorithm (Gilliganian Ethics)

**Status**: ✅ APROVADO  
**Data**: Dezembro 2025  
**Autores**: Daniel Camargo, Ethical Committee  
**Crate v3.0**: `btv-governance` (via PyO3 → Python `MercyCalculator`)

## Contexto

Sistemas binários (allow/block) são injustos. Um médico pesquisando efeitos colaterais de medicamentos não deveria ser tratado como um atacante exfiltrando dados de pacientes, mesmo que ambos disparem a mesma regra de detecção de CPF.

## Decisão

Implementar abrandamento contextual baseado na Ética do Cuidado (Gilligan, 1982):

```python
mercy_score = (
    0.30 * (1.0 - entropy_normalized) +   # Baixa incerteza → + mercy
    0.30 * trust_score +                    # Alto trust → + mercy
    0.20 * justifiability +                 # Contexto justificável
    0.10 * (1.0 - severity_normalized) +    # Baixa severidade
    0.10 * consistency                      # Histórico consistente
)

# Abrandamento: se mercy > 0.5 e ação original é BLOCK → EDUCATE
if mercy_score > 0.5 and original_action == Action.BLOCK:
    final_action = Action.EDUCATE
```

## Fundamento Filosófico

- **Gilligan**: Contexto > Regra. Relações e circunstâncias importam mais que aplicação cega de normas.
- **Levinas**: Dever de cuidado — educar antes de punir. L1 (EDUCATE) antes de L4 (BLOCK).

## Métricas Operacionais

- Mercy aplicada em ~18% dos casos (target: 15–20%)
- Taxa de contestação pós-mercy: 4% (vs 18% sem mercy)
- False positive rate com mercy: 2.1% (vs 22% em v1.0 sem mercy)

## Riscos

| Risco | Mitigação |
|-------|-----------|
| Mercy excessiva permite ameaças reais | Threshold 0.5 calibrado via blind tests; jamais aplica em `severity == Critical` |
| Gaming via trust score artificial | Anti-spam detection; rate limiting no trust calculator |
| Mercy inconsistente entre perfis | Blind Policy Testing (Rawls) — ≥95% pass rate |

---
