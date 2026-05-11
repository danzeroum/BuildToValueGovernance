//! Testes ADR-032: ScanContextFlags
//! Valida invariantes de tamanho, bitmask ops e não-regressão do pipeline.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use buildtovalue_kernel::core::module::{ScanContext, ScanContextFlags};
use buildtovalue_kernel::core::types::InputStatistics;
use buildtovalue_kernel::Gatekeeper;

#[test]
fn test_scan_context_flags_size_64_bytes() {
    assert_eq!(
        core::mem::size_of::<ScanContextFlags>(),
        64,
        "ScanContextFlags deve ter exatamente 64 bytes (ADR-032)"
    );
}

#[test]
fn test_scan_context_total_size() {
    assert_eq!(
        core::mem::size_of::<ScanContext>(),
        core::mem::size_of::<InputStatistics>() + 64
    );
}

#[test]
fn test_default_is_single_tenant_all_caps() {
    let ctx = ScanContext::default();
    assert!(ctx.flags.is_default_tenant());
    assert!(ctx.flags.is_language_undetermined());
    assert!(ctx.flags.has_capability(ScanContextFlags::CAP_PII));
    assert!(ctx.flags.has_capability(ScanContextFlags::CAP_INJECTION));
    assert!(ctx.flags.has_capability(ScanContextFlags::CAP_DEOBFUSC));
    assert!(ctx.flags.has_capability(ScanContextFlags::CAP_OUTPUT));
}

#[test]
fn test_lang_bitmask_operations() {
    let mut flags = ScanContextFlags::default();
    assert!(flags.is_language_undetermined());

    flags.lang_bitmask |= ScanContextFlags::LANG_PT;
    flags.lang_bitmask |= ScanContextFlags::LANG_EN;

    assert!(flags.has_lang(ScanContextFlags::LANG_PT));
    assert!(flags.has_lang(ScanContextFlags::LANG_EN));
    assert!(!flags.has_lang(ScanContextFlags::LANG_RU));
    assert!(!flags.is_language_undetermined());
}

#[test]
fn test_jurisdiction_bitmask_operations() {
    let mut flags = ScanContextFlags::default();
    flags.jurisdiction_bitmask |= ScanContextFlags::JURISDICTION_BR;

    assert!(flags.has_jurisdiction(ScanContextFlags::JURISDICTION_BR));
    assert!(!flags.has_jurisdiction(ScanContextFlags::JURISDICTION_UK));
    assert!(!flags.has_jurisdiction(ScanContextFlags::JURISDICTION_EU));
}

#[test]
fn test_capability_mask_disable() {
    let mut flags = ScanContextFlags {
        capability_mask: ScanContextFlags::CAP_ALL,
        ..Default::default()
    };
    // Desabilitar PII para este scan
    flags.capability_mask &= !ScanContextFlags::CAP_PII;

    assert!(!flags.has_capability(ScanContextFlags::CAP_PII));
    assert!(flags.has_capability(ScanContextFlags::CAP_INJECTION));
}

#[test]
fn test_lang_confidence_fixed_point() {
    let mut flags = ScanContextFlags::default();
    flags.lang_scores[0] = 65535; // 100%
    flags.lang_scores[1] = 32767; // ~50%
    flags.lang_scores[2] = 0;     // 0%

    assert!((flags.lang_confidence(0) - 1.0).abs() < 0.0001);
    assert!((flags.lang_confidence(1) - 0.5).abs() < 0.01);
    assert_eq!(flags.lang_confidence(2), 0.0);
    assert_eq!(flags.lang_confidence(99), 0.0); // out of bounds — não panic
}

#[test]
fn test_pipeline_unaffected_by_adr032() {
    // Garante que os 13 módulos existentes não regridem após ADR-032.
    let mut gk = Gatekeeper::new();
    let evidence = gk.scan_for_evidence("CPF: 123.456.789-09", 0x1234);
    assert!(evidence.critical_count > 0, "CPF deve gerar finding crítico");
    assert!(evidence.bias.false_positive_rate > 0.0, "BiasDeclaration agregada deve estar presente");
    assert!(evidence.validate_hash(), "Hash BLAKE3 deve ser válido após finalize()");
}

#[test]
fn test_reserved_metadata_epoch_and_tenant_written() {
    let mut gk = Gatekeeper::new();
    let evidence = gk.scan_for_evidence("hello world", 0xABCD);

    // epoch = 0 (PatternRegistry inativo até ADR-033): bytes 0-7 = zeros
    let epoch = u64::from_le_bytes(evidence._reserved_metadata[0..8].try_into().unwrap());
    assert!(epoch >= 1, "epoch deve ser >= 1 após REGISTRY inicializar");
    // tenant_key = zeros (single-tenant default): bytes 8-24 = zeros
    assert_eq!(&evidence._reserved_metadata[8..24], &[0u8; 16]);
}
