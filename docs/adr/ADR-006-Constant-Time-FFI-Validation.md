# ADR-006: Constant-Time FFI Validation

**Status**: APPROVED  
**Date**: 2026-02-05  
**Deciders**: Staff Engineer, Lead Architect, Ethical Committee  
**Gate**: G1 (FFI Safety Review)

## Context

A análise de segurança identificou uma vulnerabilidade de **timing attack** na função 
`FFIBuffer::validate()` (v2.2). O código original realizava early returns diferenciados:

```rust
// ❌ VULNERÁVEL (v2.2)
if !constant_time_eq(&self.checksum, computed.as_bytes()) {
    return Err(FFIError::IntegrityViolation);  // Retorno rápido (~Xms)
}

if age > MAX_DATA_AGE_SECS {
    return Err(FFIError::StaleData { ... });  // Retorno tardio (~X+Yms)
}
```

**Ataque**: Um adversário pode forjar pacotes com checksums inválidos e medir o tempo 
de resposta. Se o erro retornar rapidamente, o checksum estava errado. Se demorar mais, 
o checksum estava correto (mas o timestamp estava stale). Isso **vaza informação sobre 
a validade do HMAC/Hash**.

## Decision

Implementar validação **constant-time** que:

1. **Sempre executa todas as validações** (não short-circuit)
2. Combina resultados via **bitwise AND** (não `&&` lógico)
3. Retorna **erro genérico** (não revela qual validação falhou)

```rust
// ✅ SEGURO (v2.3)
pub fn validate(&self) -> FFIResult<()> {
    let checksum_valid = self.validate_checksum_ct();  // Sempre executa
    let freshness_valid = self.validate_freshness_ct();  // Sempre executa
    
    let all_valid = checksum_valid & freshness_valid;  // Bitwise AND
    
    if all_valid {
        Ok(())
    } else {
        Err(FFIError::IntegrityViolation)  // Generic error
    }
}
```

## Consequences

### Positivo
- ✅ **Timing leak eliminado**: Ambos os casos retornam em ~(X+Y)ms sempre
- ✅ **Test coverage**: `test_timing_constant_validation` valida variância < 5%
- ✅ **Zero custo adicional**: Bitwise AND é tão rápido quanto `&&`

### Negativo
- ⚠️ **Erro menos específico**: Não distingue entre checksum vs. timestamp (aceitável)
- ⚠️ **Latência fixa**: Sempre executa ambas validações (trade-off segurança vs. speed)

### Mitigação de Riscos
- **Hardware virtualizado**: Se variância > 5% em CI, ajustar threshold para 10%
- **Debugging**: Logs detalhados (nível DEBUG) ainda revelam causa do erro

## Compliance

- **NIST SP 800-57**: Key management (constant-time comparison)
- **OWASP ASVS 6.2.1**: Timing attack resistance
- **ISO 42001**: AI system security requirements

## Approval

- [x] Staff Engineer: Implementação correta (bitwise AND)
- [x] Lead Architect: Integração com FFIBuffer aprovada
- [x] Ethical Committee: Trade-off segurança/usabilidade aceitável

**Signature**: `ADR-006-APPROVED-2026-02-05`
```
