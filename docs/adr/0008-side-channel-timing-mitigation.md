
# ADR-008: Side-Channel & Timing Attack Mitigation

**Status**: ✅ APROVADO  
**Data**: Janeiro 2026  
**Crate v3.0**: `btv-kernel`

## Contexto

Timing attacks podem vazar informações sobre blacklists, CPFs válidos e padrões de detecção. Um adversário medindo tempo de resposta pode inferir se um CPF está em uma blacklist (resposta lenta = blacklist lookup executado).

## Decisão

4 camadas de proteção:

1. **Constant-time validators**: Todas as validações executam ambos os branches (sem early return baseado em dados sensíveis). Bitwise AND em vez de `&&` lógico.

2. **ORAM blacklist lookup**: Access patterns uniformes — sempre acessa N entries, independente de resultado.

3. **Position randomization**: Findings no ring buffer não revelam posição exata da detecção no input.

4. **Finding count bucketing**: Oculta contagem exata (buckets: 0–1, 2–5, 6–10, 11+).

```rust
// Constant-time validation (ADR-006 do repositório: Constant-Time FFI)
pub fn validate(&self) -> FFIResult<()> {
    let checksum_valid = self.validate_checksum_ct();   // Sempre executa
    let freshness_valid = self.validate_freshness_ct();  // Sempre executa
    let all_valid = checksum_valid & freshness_valid;    // Bitwise AND
    if all_valid { Ok(()) }
    else { Err(FFIError::IntegrityViolation) }           // Erro genérico
}
```

## Performance

| Operação | Baseline | Hardened | Overhead |
|----------|----------|----------|----------|
| CPF Validation | 15µs | 52µs | 3.5× |
| Blacklist Lookup | 5µs | 48µs | 9.6× |
| End-to-End | 8.2ms | 12.5ms | 1.5× |

T-test p-value: 0.67 (> 0.05 — sem leakage detectável). CV: 3–5%.

## Fundamento Filosófico

- **Rawls**: Proteção equânime — todos os usuários recebem mesma proteção contra timing attacks.
- **Jonas**: Overhead de 1.5× é proporcional ao risco. Sistema não deve facilitar ataques por negligência.
- **Levinas**: Protege privacidade mesmo contra adversários avançados.

## Conformidade

- NIST SP 800-57 (constant-time comparison)
- OWASP ASVS 6.2.1 (timing attack resistance)

---
