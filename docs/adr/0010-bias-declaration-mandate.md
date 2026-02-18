# ADR-010: TechnicalEvidence v2.1 Refactor & BiasDeclaration Mandate

**Status**: 🆕 PROPOSTO
**Data**: 09 de fevereiro de 2026
**Autores**: IA Arquiteta (validado por Staff Engineer)
**Impacto**: rust/kernel/src/evidence/, rust/kernel/src/gatekeeper.rs,
             rust/kernel/src/validators/ (todos), rust/bindings/src/

## Contexto

O TechnicalEvidence v2.1 existe e funciona (9596 bytes, BLAKE3, ring buffer).
Porém, três gaps foram identificados na auditoria para v1.5.0:

1. **BiasDeclaration está definido na struct mas não preenchido pelos validators**.
   Cada validator retorna `BiasDeclaration::default()` (zeros). Isso viola o
   princípio de Transparência Radical (Jonas) — é como assinar um documento 
   em branco.

2. **O trait Validator não exige bias_declaration()** como método obrigatório.
   Implementações podem omitir sem erro de compilação.

3. **Gatekeeper não agrega BiasDeclaration** dos módulos executados no 
   evidence.bias final. O campo existe mas é sempre default.

## Decisão

### 1. Tornar bias_declaration() parte do trait Validator
```rust
// rust/kernel/src/validators/mod.rs
pub trait Validator: Send + Sync {
    /// Executa validação e retorna findings
    fn validate(&self, input: &str) -> Vec<Finding>;
    
    /// Identifica o módulo (para bitmask executed_modules)
    fn module_id(&self) -> ValidatorModule;
    
    /// NOVO (OBRIGATÓRIO): Declara limitações conhecidas
    fn bias_declaration(&self) -> BiasDeclaration;
}
```

### 2. Cada validator DEVE preencher BiasDeclaration com valores reais
```rust
// Exemplo: CpfValidator
fn bias_declaration(&self) -> BiasDeclaration {
    BiasDeclaration {
        false_positive_rate: 0,      // 0% — mod 11 é determinístico
        false_negative_rate: 5,      // ~2% — CPFs ofuscados escapam
        calibration_date: 20260209,  // YYYYMMDD (< 90 dias de validade)
        known_limitations: pad_128(
            "Obfuscated CPFs (spaced, encoded, leetspeak) may evade regex. \
             Does not detect CPFs in images or audio."
        ),
    }
}
```

### 3. Gatekeeper agrega BiasDeclaration no finalize()
```rust
// rust/kernel/src/gatekeeper.rs — dentro de scan_for_evidence()
// Após executar todos os módulos:
evidence.bias = self.aggregate_bias_declarations();

// Lógica de agregação:
fn aggregate_bias_declarations(&self) -> BiasDeclaration {
    BiasDeclaration {
        // Pior caso entre todos os módulos executados
        false_positive_rate: max(cpf.fpr, cnpj.fpr, email.fpr, ...),
        false_negative_rate: max(cpf.fnr, cnpj.fnr, email.fnr, ...),
        // Data de calibração mais antiga (mais desatualizada)
        calibration_date: min(cpf.date, cnpj.date, email.date, ...),
        // Limitação mais crítica
        known_limitations: pad_128("Aggregated: see individual modules"),
    }
}
```

### 4. Teste de integridade: BiasDeclaration nunca é default após scan
```rust
#[test]
fn test_bias_declaration_never_default_after_scan() {
    let mut gk = Gatekeeper::new();
    let evidence = gk.scan_for_evidence("test input", 0x1234);
    // BiasDeclaration DEVE ter sido preenchido
    assert_ne!(evidence.bias.calibration_date, 0,
        "BiasDeclaration.calibration_date must be set after scan");
}
```

## BiasDeclaration por Módulo (Valores Iniciais)

| Módulo | FPR (0-255) | FNR (0-255) | Limitação Principal |
|--------|-------------|-------------|---------------------|
| CPF | 0 (0%) | 5 (~2%) | Ofuscados escapam regex |
| CNPJ | 0 (0%) | 5 (~2%) | Ofuscados escapam regex |
| Email | 3 (~1%) | 10 (~4%) | Endereços incomuns (TLDs novos) |
| CreditCard | 2 (~0.8%) | 8 (~3%) | Números parciais não detectados |
| Phone | 5 (~2%) | 15 (~6%) | Formatos internacionais variados |
| Entropy | 13 (~5%) | 20 (~8%) | Textos curtos têm alta variância |
| ZScore | 10 (~4%) | 18 (~7%) | Baseline assume distribuição normal |
| CharRatio | 8 (~3%) | 15 (~6%) | Idiomas CJK alteram ratios |
| Base64 | 3 (~1%) | 25 (~10%) | Strings curtas ambíguas |
| Hex | 2 (~0.8%) | 20 (~8%) | UUIDs sem 0x prefix |
| Leetspeak | 15 (~6%) | 30 (~12%) | Variantes regionais não cobertas |

## Alternativas Consideradas

| Alternativa | Rejeitada porque |
|-------------|-----------------|
| BiasDeclaration opcional | Viola Jonas (Responsabilidade); permite omissão silenciosa |
| BiasDeclaration via config YAML | Desacopla declaração do código; difícil manter atualizado |
| Valores calculados runtime | Requer dataset de calibração; overhead no hot path |

## Fundamento Filosófico

- **Jonas (Responsabilidade Proporcional)**: Cada módulo DEVE declarar suas
  limitações. Omitir é irresponsável — equivale a um médico que não informa
  efeitos colaterais.
- **Rawls (Transparência)**: O usuário (e o auditor) têm direito de saber
  as taxas de erro. BiasDeclaration é o "rótulo nutricional" do sistema.
- **Levinas (Cuidado)**: FNR alto em um módulo (ex: leetspeak 12%) significa
  que devemos EDUCAR o usuário sobre a limitação, não fingir perfeição.

## Consequências

- **Positivas**: Transparência radical; auditoria automática de calibração
  (flag se calibration_date > 90 dias); base para relatórios AJL.
- **Negativas**: +1 método por validator; ~15 min trabalho por módulo.
- **Riscos**: Valores FPR/FNR iniciais são estimativas educadas, não
  medidos empiricamente (mitigação: flag `estimated` vs `measured` no v1.6).

## Testes Obrigatórios para o Dev
1. `test_bias_declaration_never_default_after_scan` — aggregate funciona
2. `test_each_validator_has_nonzero_calibration_date` — nenhum esquecido
3. `test_calibration_date_within_90_days` — não expirado
4. `test_aggregate_takes_worst_case` — max(FPR), max(FNR), min(date)
5. `test_evidence_size_unchanged` — ainda 9596 bytes após mudança

## Conformidade
- ISO 42001 (7.4: Communication — declaração de limitações)
- EU AI Act (Art. 13: Transparency — informar limitações)
- NIST AI RMF (MAP 2.3: Document known limitations)

## Constraints para Dev Rust
- NÃO alterar o layout de TechnicalEvidence (BiasDeclaration já existe)
- NÃO alterar o tamanho de BiasDeclaration (já está em 9596 bytes)
- A função `pad_128(str)` deve truncar + null-pad em [u8; 128]
- Calibration date formato YYYYMMDD como u32
- FPR/FNR em escala 0-255 (0=0%, 255=100%, resolução ~0.4%)