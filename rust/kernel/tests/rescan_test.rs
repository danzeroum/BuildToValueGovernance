use buildtovalue_kernel::deobfuscator::chain::DeobfuscatorChain;
use buildtovalue_kernel::gatekeeper::Gatekeeper;

#[test]
fn test_base64_cpf_decoded_and_detected() {
    let chain = DeobfuscatorChain::new();
    let result = chain.deobfuscate("MTIzLjQ1Ni43ODktMDk=");
    println!("Layers: {:?}", result.layers);
    println!("Final: {}", result.final_text);
    assert!(!result.layers.is_empty(), "Should decode at least 1 layer");
    assert_eq!(result.final_text, "123.456.789-09");

    // Now scan the decoded text
    let mut gk = Gatekeeper::new();
    let evidence = gk.scan_for_evidence(&result.final_text, 0x9999);
    println!("Findings: {}", evidence.finding_count);
    println!("Critical: {}", evidence.critical_count);
    assert!(evidence.finding_count > 0, "Should detect CPF in decoded text");
    assert!(evidence.critical_count > 0, "CPF should be critical");
}

#[test]
fn test_full_rescan_pipeline() {
    let mut gk = Gatekeeper::new();
    // Base64-encoded CPF
    let evidence = gk.scan_for_evidence("MTIzLjQ1Ni43ODktMDk=", 0x1234);
    println!("Total findings: {}", evidence.finding_count);
    println!("Critical: {}", evidence.critical_count);
    // Should find both: base64 detection + CPF after decode
    assert!(evidence.critical_count > 0, 
        "Should detect CPF after base64 decode, got {} findings {} critical",
        evidence.finding_count, evidence.critical_count);
}
