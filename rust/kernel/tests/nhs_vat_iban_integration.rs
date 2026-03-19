//! Testes de integração — NHS/VAT/IBAN no pipeline Gatekeeper (ADR-035)
//!
//! Verifica que os validadores UK/EU são acionados via JURISDICTION_ALL
//! (default no Gatekeeper) e que isolamento jurisdicional funciona corretamente.

use buildtovalue_kernel::Gatekeeper;
use buildtovalue_kernel::core::types::ValidatorModule;

fn has_finding_from(input: &str, module: ValidatorModule) -> bool {
    let mut gk = Gatekeeper::new();
    let evidence = gk.scan_for_evidence(input, 0xAD_035);
    evidence.get_all_findings().iter().any(|f| f.module == module)
}

/// NHS Number válido (checksum módulo 11 = 0) deve ser detectado
#[test]
fn test_nhs_number_detected_in_default_jurisdiction() {
    // NHS: 943 476 5919 — número de teste com checksum válido
    assert!(
        has_finding_from("Patient NHS number: 943 476 5919 needs urgent review", ValidatorModule::NhsNumber),
        "NHS number deve ser detectado com JURISDICTION_ALL (default)"
    );
}

/// IBAN válido (ISO 13616, módulo 97) deve ser detectado
#[test]
fn test_iban_detected_in_default_jurisdiction() {
    // GB29 NWBK 6016 1331 9268 19 — IBAN britânico de teste
    assert!(
        has_finding_from("Please transfer to GB29NWBK60161331926819 by end of day", ValidatorModule::Iban),
        "IBAN deve ser detectado com JURISDICTION_ALL (default)"
    );
}

/// EU VAT number deve ser detectado
#[test]
fn test_eu_vat_detected_in_default_jurisdiction() {
    // DE123456789 — VAT alemão formato padrão
    assert!(
        has_finding_from("Invoice for DE123456789 client, VAT registered", ValidatorModule::EuVat),
        "EU VAT number deve ser detectado com JURISDICTION_ALL (default)"
    );
}

/// CPF brasileiro também deve ser detectado (JURISDICTION_BR incluso em ALL)
#[test]
fn test_cpf_still_detected_alongside_eu_validators() {
    let mut gk = Gatekeeper::new();
    let input = "CPF 123.456.789-09 and IBAN GB29NWBK60161331926819";
    let evidence = gk.scan_for_evidence(input, 0xAD_035B);
    let findings = evidence.get_all_findings();

    let has_cpf  = findings.iter().any(|f| f.module == ValidatorModule::CPF);
    let has_iban = findings.iter().any(|f| f.module == ValidatorModule::Iban);

    assert!(has_cpf,  "CPF deve ser detectado mesmo com JURISDICTION_ALL");
    assert!(has_iban, "IBAN deve ser detectado mesmo com JURISDICTION_ALL");
}
