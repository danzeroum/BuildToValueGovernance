[BuildToValue](../README.md) › [Documentação](./README.md) › **Handoff Templates**

![Interno](https://img.shields.io/badge/Trilha-Contribuidor%20%2F%20Interno-6e7681)

<!-- audience: internal -->

---

# BuildToValue — Handoff Templates v1.0

## Template A: Arquiteta → Dev Rust

---
handoff_type: architecture
from_role: architect
to_role: dev_rust
version: 1.0
date: YYYY-MM-DD
feature: [nome do feature]
target_version: [v1.5.0 | v1.6.0 | ...]
project_context_version: 3.0.1
---

### ADR
[ADR completo com fundamento filosófico]

### Traits a Implementar
```rust
[traits com assinaturas completas]
```

### BiasDeclaration Esperado
```rust
[template preenchido com ranges esperados]
```

### Arquivos a Criar/Modificar
| Arquivo | Ação | Descrição |
|---------|------|-----------|
| `rust/kernel/src/[path]` | CRIAR | [descrição] |

### Testes Obrigatórios
1. [cenário happy path]
2. [cenário error path 1]
3. [cenário error path 2]
4. [cenário edge case]

### Constraints
- [constraint específico deste feature]

---

## Template B: Arquiteta → Dev Python

---
handoff_type: architecture
from_role: architect
to_role: dev_python
version: 1.0
date: YYYY-MM-DD
feature: [nome do feature]
target_version: [v1.5.0 | v1.6.0 | ...]
project_context_version: 3.0.1
---

### ADR
[ADR com fundamento filosófico]

### Interface Python Esperada
```python
class [ClassName]:
    def [método](self, [params]: [types]) -> [ReturnType]:
        """[docstring com explain_decision obrigatório]"""
        ...
```

### Contrato com Rust (FFI)
```
Input do Rust: TechnicalEvidence (desserializado via Protobuf)
Output para Execution: EthicalVerdict (assinado HMAC-SHA256)
```

### Cenários de Mercy (Gilligan)
| Condição | Trust | Uncertainty | Critical | Ação Esperada |
|----------|-------|-------------|----------|---------------|
| [cenário 1] | > 0.6 | > 0.7 | 0 | EDUCATE (mercy) |
| [cenário 2] | < 0.3 | qualquer | > 0 | BLOCK (sem mercy) |

### Testes Obrigatórios
1. [cenário happy path]
2. [cenário mercy aplicada]
3. [cenário mercy negada]
4. [cenário fail-secure]

---

## Template C: Dev → Reviewer (Review Request)

---
handoff_type: review_request
from_role: dev_rust | dev_python
to_role: reviewer
version: 1.0
date: YYYY-MM-DD
feature: [nome do feature]
adr_reference: ADR-XXX
project_context_version: 3.0.1
---

### Resumo
[O que foi implementado, 2-3 frases]

### Arquivos Modificados
| Arquivo | Linhas | Tipo |
|---------|--------|------|
| `[path]` | +XXX/-YYY | NOVO / MODIFICADO |

### ADR Original (para comparação)
[Link ou conteúdo do ADR]

### Código
[código completo organizado por arquivo]

### Testes
[testes completos]

### Self-Review (já verificado pelo Dev)
[checklist preenchido]

### Pontos de Atenção
[áreas que o Dev sabe que precisam de mais olho]

---

## Template D: Reviewer → Dev (Review Feedback)

---
handoff_type: review_feedback
from_role: reviewer
to_role: dev_rust | dev_python
version: 1.0
date: YYYY-MM-DD
feature: [nome do feature]
iteration: [1 | 2 | 3] (máximo 3)
verdict: APPROVE | REQUEST_CHANGES | REJECT
---

### Veredito: [APPROVE | REQUEST_CHANGES | REJECT]
Issues: X Critical, Y Major, Z Minor

### Issues a Corrigir
[lista detalhada com código sugerido]

### O Que Está Bem Feito
[feedback positivo]

### Recomendações para PROJECT_CONTEXT.md
[anti-padrões a adicionar, se aplicável]

---

## Regra de Iteração
- Máximo 3 rounds Dev ↔ Reviewer
- Se após 3 rounds ainda há CRITICAL → voltar para Arquiteta
- Reviewer DEVE incluir "O Que Está Bem Feito" em toda review

---

### Próximos passos / Relacionados

- [Project Context](./PROJECT_CONTEXT.md)
- [Release Gates](./RELEASE_GATES.md)
- [Índice de ADRs](./adr/0000-adr-index.md)

---

<sub>[↑ Hub](./README.md) · [Trilha Engenheiro](./for-engineers.md) · [Trilha DPO/CISO](./for-dpo-ciso.md) · [Links de Referência](./reference-links.md)</sub>
