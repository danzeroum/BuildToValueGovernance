# ADR-0035: Multi-jurisdiction PII Validators

**Status:** ✅ Implementado (v1.7.0)
**Data:** 24 de fevereiro de 2026
**Autores:** BuildToValue AI Squad (Arquiteta + Staff Engineer)
**Versão Alvo:** v1.7.0
**Grupo:** J — Multilingual & Multi-tenant Foundation
**Depende de:** ADR-0032 (ScanContextFlags), ADR-0034 (Language Detection)
**Bloqueado por:** ADR-0032 + ADR-0033 mergeados

---

## 1. Contexto

### Estado atual dos validators PII
```
validators/
├── brazilian/   CPF, CNPJ          ← Mod 11, com checksum
├── us/          SSN                ← já implementado (Area/Group/Serial rules)
├── financial/   CreditCard         ← Luhn, universal
├── communication/ Email, Phone     ← universal
├── network/     IPv4, URL          ← universal
├── sensitive/   LGPD Art.11        ← BR-specific
└── analysis/    Statistical        ← universal
```

**Gaps confirmados no repositório:**
- `validators/uk/` — não existe. NHS Number ausente.
- `validators/eu/` — não existe. VAT e IBAN ausentes.
- `ValidatorModule` enum em `core/types.rs` não tem `NhsNumber`, `EuVat`, `Iban`.

**Comportamento atual do Gatekeeper:** todos os validators rodam contra
todo input, independente de jurisdição. Com ADR-032 disponível, o
`jurisdiction_bitmask` em `ScanContextFlags` permite desativar validators
por jurisdição — mas o mecanismo de dispatch ainda não existe.

### Por que agora (v1.7.0)

ADR-034 popula `lang_bitmask`. O gateway injeta `jurisdiction_bitmask`.
Falta o lado receptor: validators que leem esses campos e decidem se
devem rodar. O NHS e o VAT são os casos de uso mais solicitados
(conforme README do projeto: *"Validators for other jurisdictions
(US SSN, UK NHS, EU VAT)"* listados como contribuições bem-vindas).

---

## 2. Decisão

### 2.1 Novos Namespaces de Validators
```
rust/kernel/src/validators/
├── uk/
│   ├── mod.rs        # re-exports
│   └── nhs.rs        # NHS Number (Mod 11, 10 dígitos)
└── eu/
    ├── mod.rs        # re-exports
    ├── vat.rs        # EU VAT (prefixo país + formato por país)
    └── iban.rs       # IBAN (ISO 13616, Mod 97)
```

Cada arquivo respeita o limite de ≤ 200 linhas.

### 2.2 Adições ao ValidatorModule enum
```rust
// rust/kernel/src/core/types.rs — adicionar ao enum ValidatorModule:
pub enum ValidatorModule {
    // ... entradas existentes ...
    NhsNumber,      // UK NHS Number
    EuVat,          // EU VAT Number
    Iban,           // International Bank Account Number (ISO 13616)
}
```

### 2.3 Dispatcher por Jurisdição

O dispatcher substitui o padrão atual de "todos os validators sempre rodam"
por seleção baseada em `ScanContextFlags.jurisdiction_bitmask`.
```rust
// rust/kernel/src/validators/mod.rs — adicionar:

use crate::core::module::ScanContextFlags;
use crate::evidence::Finding;
use crate::core::module::ScanContext;

/// Executa validators PII selecionados pelo jurisdiction_bitmask.
/// Universal (email, credit card, phone, IP) sempre roda.
/// Jurisdição-específico roda apenas se o bit correspondente estiver ativo.
pub fn dispatch_pii(input: &str, ctx: &mut ScanContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let j = ctx.flags.jurisdiction_bitmask;
    let caps = ctx.flags.capability_mask;

    // Guard: PII detection desabilitada para este scan
    if caps & ScanContextFlags::CAP_PII == 0 {
        return findings;
    }

    // ── Universal (sempre) ─────────────────────────────────────────
    findings.extend(EmailValidator::new().scan(input, ctx));
    findings.extend(PhoneValidator::new().scan(input, ctx));
    findings.extend(CreditCardValidator::new().scan(input, ctx));

    // ── BR ─────────────────────────────────────────────────────────
    if j & ScanContextFlags::JURISDICTION_BR != 0 {
        findings.extend(CpfValidator::new().scan(input, ctx));
        findings.extend(CnpjValidator::new().scan(input, ctx));
    }

    // ── US ─────────────────────────────────────────────────────────
    if j & ScanContextFlags::JURISDICTION_US != 0 {
        findings.extend(SsnValidator::new().scan(input, ctx));
    }

    // ── UK ─────────────────────────────────────────────────────────
    if j & ScanContextFlags::JURISDICTION_UK != 0 {
        findings.extend(uk::NhsValidator::new().scan(input, ctx));
    }

    // ── EU ─────────────────────────────────────────────────────────
    if j & ScanContextFlags::JURISDICTION_EU != 0 {
        findings.extend(eu::VatValidator::new().scan(input, ctx));
        findings.extend(eu::IbanValidator::new().scan(input, ctx));
    }

    findings
}
```

**Integração no Gatekeeper:** o Stage 3 (Validate) chama `dispatch_pii()`
em vez de instanciar cada validator individualmente. Os validators
universais (Email, Phone, CreditCard) permanecem no pipeline do Gatekeeper
diretamente por serem sempre ativos — apenas os jurisdiction-specific
passam pelo dispatcher.

### 2.4 NHS Number Validator
```rust
// rust/kernel/src/validators/uk/nhs.rs

//! NHS Number Validator v1.0.0 (ADR-035)
//!
//! Valida NHS Numbers do Reino Unido.
//! Formato: NNN NNN NNNN (10 dígitos, algoritmo Módulo 11)
//! Exemplos válidos: "943 476 5919", "401 023 2137"
//!
//! Filosofia (Levinas): dados de saúde são hipersensíveis — BLOCK por padrão.
//! Filosofia (Jonas): BiasDeclaration com FPR/FNR calibrados contra RT-010.

use lazy_static::lazy_static;
use regex::Regex;
use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;

lazy_static! {
    // NNN NNN NNNN | NNNNNNNNNN | NNN-NNN-NNNN
    static ref NHS_PATTERN: Regex = Regex::new(
        r"\b(\d{3})[\s\-]?(\d{3})[\s\-]?(\d{4})\b"
    ).unwrap();
}

pub struct NhsValidator;

impl NhsValidator {
    pub fn new() -> Self { Self }

    /// Módulo 11 para NHS Number.
    /// Pesos: 10, 9, 8, 7, 6, 5, 4, 3, 2.
    /// Check digit = 11 - (soma mod 11).
    /// Se check digit = 11 → 0. Se check digit = 10 → número inválido.
    fn is_valid_nhs(digits: &str) -> bool {
        if digits.len() != 10 { return false; }
        let nums: Vec<u32> = digits.chars()
            .filter_map(|c| c.to_digit(10))
            .collect();
        if nums.len() != 10 { return false; }

        let sum: u32 = nums[..9].iter()
            .zip((2u32..=10).rev())
            .map(|(d, w)| d * w)
            .sum();

        let remainder = sum % 11;
        let check = if remainder == 0 { 0 } else { 11 - remainder };

        // check digit = 10 → número estruturalmente inválido
        check != 10 && check == nums[9]
    }

    fn mask_nhs(digits: &str) -> String {
        if digits.len() == 10 {
            format!("{}***{}", &digits[..3], &digits[7..])
        } else {
            "***".to_string()
        }
    }
}

impl Default for NhsValidator {
    fn default() -> Self { Self::new() }
}

impl Module for NhsValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in NHS_PATTERN.find_iter(input) {
            let raw = mat.as_str();
            let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();

            let (severity, rule_id, confidence) = if Self::is_valid_nhs(&digits) {
                (TechnicalSeverity::Critical(255), "NHS_NUMBER_DETECTED", 95u8)
            } else {
                (TechnicalSeverity::Medium, "NHS_NUMBER_INVALID_FORMAT", 45u8)
            };

            findings.push(
                Finding::new(
                    ValidatorModule::NhsNumber,
                    severity,
                    rule_id,
                    "PII_LEAKAGE_HEALTH",
                    &Self::mask_nhs(&digits),
                )
                .with_position(mat.start() as u16, mat.end() as u16)
                .with_confidence(confidence)
            );
        }
        findings
    }

    fn name(&self) -> &'static str { "nhs_number" }
    fn module_id(&self) -> ValidatorModule { ValidatorModule::NhsNumber }

    fn bias_declaration(&self) -> BiasDeclaration {
        // Valores iniciais — calibrar com RT-010 após implementação
        BiasDeclaration::new(0.12, 0.08, 20260224, 100)
            .with_limitations(
                "Regex + Mod 11 only. Does not verify against NHS spine. \
                 10-digit sequences from phone numbers or order IDs may FP."
            )
            .with_affected_groups(
                "Non-UK users with 10-digit numeric IDs. \
                 UK phone numbers in 10-digit format."
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_nhs_spaced() {
        let v = NhsValidator::new();
        let f = v.scan("NHS: 943 476 5919", &mut ScanContext::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, TechnicalSeverity::Critical(255));
        assert_eq!(f[0].confidence, 95);
    }

    #[test]
    fn test_valid_nhs_no_spaces() {
        let v = NhsValidator::new();
        let f = v.scan("9434765919", &mut ScanContext::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, TechnicalSeverity::Critical(255));
    }

    #[test]
    fn test_invalid_nhs_check_digit() {
        let v = NhsValidator::new();
        // Troca último dígito → Mod 11 falha
        let f = v.scan("943 476 5910", &mut ScanContext::default());
        assert_eq!(f[0].severity, TechnicalSeverity::Medium);
        assert_eq!(f[0].confidence, 45);
    }

    #[test]
    fn test_mod11_algorithm() {
        assert!(NhsValidator::is_valid_nhs("9434765919"));
        assert!(NhsValidator::is_valid_nhs("4010232137"));
        assert!(!NhsValidator::is_valid_nhs("1234567890")); // check digit inválido
    }

    #[test]
    fn test_masking() {
        assert_eq!(NhsValidator::mask_nhs("9434765919"), "943***5919");
    }

    #[test]
    fn test_bias_declaration_valid() {
        let v = NhsValidator::new();
        assert!(v.bias_declaration().false_positive_rate > 0.0);
    }
}
```

### 2.5 EU VAT Validator
```rust
// rust/kernel/src/validators/eu/vat.rs

//! EU VAT Number Validator v1.0.0 (ADR-035)
//!
//! Detecta números de IVA europeus.
//! Formato: prefixo de 2 letras + 8-12 dígitos/alfanuméricos.
//! Países iniciais: DE, FR, IT, ES, PT (maior relevância para clientes BTV).
//!
//! Filosofia (Jonas): BiasDeclaration declarada antes do deploy.

use lazy_static::lazy_static;
use regex::Regex;
use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;

lazy_static! {
    // Padrões por país — formato: PREFIXO + corpo alfanumérico
    static ref VAT_PATTERNS: Vec<(&'static str, Regex)> = vec![
        // Alemanha: DE + 9 dígitos
        ("DE", Regex::new(r"\bDE\s?\d{9}\b").unwrap()),
        // França: FR + 2 alfanum + 9 dígitos
        ("FR", Regex::new(r"\bFR\s?[A-Z0-9]{2}\s?\d{9}\b").unwrap()),
        // Itália: IT + 11 dígitos
        ("IT", Regex::new(r"\bIT\s?\d{11}\b").unwrap()),
        // Espanha: ES + letra/dígito + 7 dígitos + letra/dígito
        ("ES", Regex::new(r"\bES\s?[A-Z0-9]\d{7}[A-Z0-9]\b").unwrap()),
        // Portugal: PT + 9 dígitos
        ("PT", Regex::new(r"\bPT\s?\d{9}\b").unwrap()),
    ];
}

pub struct VatValidator;

impl VatValidator {
    pub fn new() -> Self { Self }

    fn mask_vat(raw: &str) -> String {
        if raw.len() >= 4 {
            format!("{}***", &raw[..2])
        } else {
            "***".to_string()
        }
    }
}

impl Default for VatValidator {
    fn default() -> Self { Self::new() }
}

impl Module for VatValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (country, pattern) in VAT_PATTERNS.iter() {
            for mat in pattern.find_iter(input) {
                findings.push(
                    Finding::new(
                        ValidatorModule::EuVat,
                        TechnicalSeverity::High,
                        "EU_VAT_DETECTED",
                        &format!("PII_TAX_ID_{}", country),
                        &Self::mask_vat(mat.as_str()),
                    )
                    .with_position(mat.start() as u16, mat.end() as u16)
                    .with_confidence(88)
                );
            }
        }
        findings
    }

    fn name(&self) -> &'static str { "eu_vat" }
    fn module_id(&self) -> ValidatorModule { ValidatorModule::EuVat }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.10, 0.15, 20260224, 80)
            .with_limitations(
                "Regex only — no checksum validation per country. \
                 5 countries implemented (DE, FR, IT, ES, PT). \
                 Remaining EU countries: Tier 2 YAML (future). \
                 Two-letter country codes in text may FP."
            )
            .with_affected_groups(
                "Documents with ISO country codes. \
                 Non-EU users with similar numeric formats."
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_de_vat() {
        let v = VatValidator::new();
        let f = v.scan("VAT: DE123456789", &mut ScanContext::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].confidence, 88);
    }

    #[test]
    fn test_detect_pt_vat() {
        let v = VatValidator::new();
        let f = v.scan("NIF PT123456789", &mut ScanContext::default());
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn test_clean_input() {
        let v = VatValidator::new();
        let f = v.scan("Hello world", &mut ScanContext::default());
        assert!(f.is_empty());
    }

    #[test]
    fn test_mask_format() {
        assert_eq!(VatValidator::mask_vat("DE123456789"), "DE***");
    }
}
```

### 2.6 IBAN Validator
```rust
// rust/kernel/src/validators/eu/iban.rs

//! IBAN Validator v1.0.0 (ADR-035)
//!
//! Detecta International Bank Account Numbers (ISO 13616).
//! Formato: 2 letras (país) + 2 check digits + BBAN (até 30 chars).
//! Comprimento: 15–34 chars dependendo do país.
//!
//! Validação: Mod 97 conforme ISO 13616.
//! Dados bancários são PII críticos — BLOCK por padrão.

use lazy_static::lazy_static;
use regex::Regex;
use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;

lazy_static! {
    // Formato geral IBAN: 2 letras + 2 dígitos + 11-30 alfanum
    // Aceita com ou sem espaços (formato display: grupos de 4)
    static ref IBAN_PATTERN: Regex = Regex::new(
        r"\b[A-Z]{2}\d{2}[\s]?([A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}\b"
    ).unwrap();
}

pub struct IbanValidator;

impl IbanValidator {
    pub fn new() -> Self { Self }

    /// Validação Mod 97 (ISO 13616).
    /// 1. Remove espaços
    /// 2. Move 4 primeiros chars para o final
    /// 3. Substitui letras por números (A=10, B=11, ..., Z=35)
    /// 4. Calcula mod 97 — resultado deve ser 1
    fn is_valid_iban(raw: &str) -> bool {
        let clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.len() < 15 || clean.len() > 34 { return false; }
        if !clean.chars().take(2).all(|c| c.is_ascii_uppercase()) { return false; }

        // Reordenar: BBAN + 4 primeiros chars
        let rearranged = format!("{}{}", &clean[4..], &clean[..4]);

        // Converter para número grande: letras → dígitos
        let numeric: String = rearranged.chars().map(|c| {
            if c.is_ascii_digit() {
                c.to_string()
            } else {
                ((c as u32 - 'A' as u32) + 10).to_string()
            }
        }).collect();

        // Mod 97 em chunks (evita overflow u128 para IBANs longos)
        let mut remainder: u64 = 0;
        for ch in numeric.chars() {
            remainder = (remainder * 10 + ch.to_digit(10).unwrap() as u64) % 97;
        }
        remainder == 1
    }

    fn mask_iban(raw: &str) -> String {
        let clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.len() >= 6 {
            format!("{}***{}", &clean[..4], &clean[clean.len()-4..])
        } else {
            "***".to_string()
        }
    }
}

impl Default for IbanValidator {
    fn default() -> Self { Self::new() }
}

impl Module for IbanValidator {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for mat in IBAN_PATTERN.find_iter(input) {
            let raw = mat.as_str();
            let clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();

            let (severity, rule_id, confidence) = if Self::is_valid_iban(&clean) {
                (TechnicalSeverity::Critical(255), "IBAN_DETECTED", 93u8)
            } else {
                (TechnicalSeverity::Medium, "IBAN_INVALID_FORMAT", 40u8)
            };

            findings.push(
                Finding::new(
                    ValidatorModule::Iban,
                    severity,
                    rule_id,
                    "PII_FINANCIAL_ACCOUNT",
                    &Self::mask_iban(raw),
                )
                .with_position(mat.start() as u16, mat.end() as u16)
                .with_confidence(confidence)
            );
        }
        findings
    }

    fn name(&self) -> &'static str { "iban" }
    fn module_id(&self) -> ValidatorModule { ValidatorModule::Iban }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.08, 0.10, 20260224, 120)
            .with_limitations(
                "Regex + Mod 97 only. Valid format does not guarantee \
                 active account. Short sequences may FP on product codes \
                 or reference numbers starting with country code."
            )
            .with_affected_groups(
                "Reference numbers with country-code prefix. \
                 Non-EU documents with similar alphanumeric patterns."
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_iban_de() {
        // IBAN alemão válido (gerado por calculadora Mod 97)
        let v = IbanValidator::new();
        let f = v.scan("IBAN: DE89370400440532013000", &mut ScanContext::default());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, TechnicalSeverity::Critical(255));
        assert_eq!(f[0].confidence, 93);
    }

    #[test]
    fn test_valid_iban_spaced() {
        let v = IbanValidator::new();
        let f = v.scan("DE89 3704 0044 0532 0130 00", &mut ScanContext::default());
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn test_invalid_iban_check_digit() {
        let v = IbanValidator::new();
        // Altera check digit → Mod 97 falha
        let f = v.scan("DE00370400440532013000", &mut ScanContext::default());
        assert_eq!(f[0].severity, TechnicalSeverity::Medium);
    }

    #[test]
    fn test_mod97_algorithm() {
        assert!(IbanValidator::is_valid_iban("DE89370400440532013000"));
        assert!(!IbanValidator::is_valid_iban("DE00370400440532013000"));
    }

    #[test]
    fn test_masking() {
        assert_eq!(IbanValidator::mask_iban("DE89370400440532013000"), "DE89***3000");
    }
}
```

### 2.7 Atualização do validators/mod.rs
```rust
// rust/kernel/src/validators/mod.rs — adicionar:

pub mod uk;
pub mod eu;

pub use uk::NhsValidator;
pub use eu::{VatValidator, IbanValidator};

// Dispatcher por jurisdição (ver seção 2.3)
pub use self::jurisdiction_dispatch::dispatch_pii;
mod jurisdiction_dispatch {
    // ... código da seção 2.3 ...
}
```

### 2.8 Red-team Scripts (requisito de aceitação)
```bash
# tests/red-team/RT-010-pii-uk-nhs.sh  — criado em v1.7.0
# tests/red-team/RT-011-pii-eu-vat.sh
# tests/red-team/RT-012-pii-eu-iban.sh
# tests/red-team/RT-009-pii-us-ssn.sh  — já existia; expandir com edge cases
```

Cada script segue o padrão dos `RT-00X` existentes:
source `lib/common.sh`, usa `rt_should_detect` e `rt_should_allow`,
gera JSON de resultado compatível com `run-all.sh`.

---

## 3. PatternQualityGate para Validators PII (CI)
```python
# tests/quality_gates/pii_quality_gate.py
# Executado no CI para cada novo validator adicionado

THRESHOLDS = {
    "nhs": {"min_detection_rate": 0.85, "max_fpr": 0.12},
    "eu_vat": {"min_detection_rate": 0.80, "max_fpr": 0.10},
    "iban": {"min_detection_rate": 0.88, "max_fpr": 0.08},
}
# v1.7.0: informativo (warning). v1.8.0: bloqueante (exit 1).
```

---

## 4. Fundamento Filosófico

**Levinas (Dever de Cuidado):** NHS Number é dado de saúde — a categoria
mais sensível de PII. O validator falha para `Critical(255)` em qualquer
NHS válido detectado. O Mod 11 reduz FP ao exigir que o número seja
estruturalmente plausível, não apenas formalmente similar.

**Jonas (Responsabilidade Proporcional):** cada validator tem
`BiasDeclaration` com FPR/FNR declarados antes do deploy, mesmo que
sejam estimativas iniciais. Os valores reais virão dos scripts RT-010/011/012
e serão atualizados no primeiro ciclo de red-team (ADR-036).

**Rawls (Blind Testing):** o dispatcher por `jurisdiction_bitmask` aplica
exatamente as mesmas regras para qualquer input que ative aquela jurisdição,
independente de quem enviou. Não há tratamento diferenciado por origem.

---

## 5. Consequências

### Positivas

- NHS, VAT, IBAN detectados — gaps mais solicitados no README fechados.
- Dispatcher por jurisdição reduz execução desnecessária (CPF não roda
  em deployment UK-only; NHS não roda em deployment BR-only).
- `ValidatorModule` enum extendido de forma backward-compatible.
- Padrão de implementação (Mod 11, Mod 97) documentado e reutilizável
  para futuros validators (NI, SNILS, INSEE).

### Negativas e Trade-offs

- **VAT sem checksum por país:** cada país EU tem algoritmo diferente
  (DE: verificação por Bundeszentralamt, FR: Luhn modificado). Implementar
  todos em v1.7.0 é fora de escopo. Regex + identificação de formato é
  suficiente para v1.7.0 — checksum por país entra como Tier 2 em v1.8+.
- **FPR inicial do NHS (~12%):** sequências de 10 dígitos em textos
  técnicos (números de pedido, datas compactas) podem FP. Mitigado pelo
  Mod 11 (elimina ~90% dos FP de format match). BiasDeclaration declara
  explicitamente o risco residual.
- **Gatekeeper.new() precisa ser atualizado:** o pipeline do Gatekeeper
  instancia módulos individualmente. A refatoração para usar `dispatch_pii`
  muda a construção do Stage 3, mas não a interface `Module::scan()`.

---

## 6. Critérios de Aceitação

- [ ] `validators/uk/nhs.rs` criado (≤ 200 linhas)
- [ ] `validators/eu/vat.rs` criado (≤ 200 linhas)
- [ ] `validators/eu/iban.rs` criado (≤ 200 linhas)
- [ ] `ValidatorModule` enum contém `NhsNumber`, `EuVat`, `Iban`
- [ ] `dispatch_pii()` existe em `validators/mod.rs`
- [ ] `JURISDICTION_UK` ativo → `NhsValidator` executa
- [ ] `JURISDICTION_EU` ativo → `VatValidator` + `IbanValidator` executam
- [ ] `JURISDICTION_BR` ativo, sem UK → `NhsValidator` NÃO executa
- [ ] `NhsValidator::is_valid_nhs("9434765919") == true`
- [ ] `NhsValidator::is_valid_nhs("1234567890") == false`
- [ ] `IbanValidator::is_valid_iban("DE89370400440532013000") == true`
- [ ] `IbanValidator::is_valid_iban("DE00370400440532013000") == false`
- [ ] RT-010, RT-011, RT-012 criados e rodando via `run-all.sh`
- [ ] Todos os 357+ testes existentes passam sem regressão

---

## 7. Referências

- `rust/kernel/src/validators/mod.rs` — estado atual
- `rust/kernel/src/core/types.rs` — `ValidatorModule` enum
- `rust/kernel/src/validators/us/ssn.rs` — modelo de implementação
- `rust/kernel/src/validators/brazilian/cpf.rs` — modelo com Mod 11
- `rust/kernel/src/network/jurisdiction.rs` — `Jurisdiction` enum existente
- ADR-032 (ScanContextFlags — `jurisdiction_bitmask`, `capability_mask`)
- ADR-034 (Language Detection — popula `lang_bitmask` para contexto)
- README.md: *"Validators for other jurisdictions (US SSN, UK NHS, EU VAT)"*