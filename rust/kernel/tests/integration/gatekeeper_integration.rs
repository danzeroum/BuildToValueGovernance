//! Testes de integração do Gatekeeper com a nova arquitetura de módulos.

use buildtovalue_kernel::Gatekeeper;
use buildtovalue_kernel::core::types::ValidatorModule;

#[test]
fn test_scan_order_preserved() {
    let mut gk = Gatekeeper::new();
    let input = "CPF 123.456.789-09 and Base64 SGVsbG8=";
    let evidence = gk.scan_for_evidence(input, 0x1234);

    let findings = evidence.get_all_findings();

    // O primeiro finding deve ser do CPF (primeiro módulo)
    assert!(!findings.is_empty());
    assert_eq!(findings[0].module, ValidatorModule::CPF);

    // O último finding (se houver base64) deve ser do deobfuscator
    // (pode haver vários, então procuramos o último com módulo Deobfuscator)
    let last_deob = findings.iter().rev().find(|f| f.module == ValidatorModule::Deobfuscator);
    assert!(last_deob.is_some());
}