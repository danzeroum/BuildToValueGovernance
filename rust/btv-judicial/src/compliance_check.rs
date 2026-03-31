//! Verifica metadata de compliance no VerdictRecord.
//!
//! Placeholder: valida que `legislative_version` é compatível
//! com o MandateToken em vigor (Fase 6 implementará verificação completa).

/// Resultado da verificação de compliance.
#[derive(Debug, Clone)]
pub struct ComplianceCheck {
    pub version_valid: bool,
    pub details: String,
}

/// Verifica que o `legislative_version` do verdict é compatível
/// com o mínimo aceito pelo auditor.
pub fn check_legislative_version(
    verdict: &btv_types::VerdictRecord,
    min_version: u64,
) -> ComplianceCheck {
    let valid = verdict.legislative_version >= min_version;
    ComplianceCheck {
        version_valid: valid,
        details: if valid {
            format!("Version {} >= minimum {}", verdict.legislative_version, min_version)
        } else {
            format!(
                "Version {} below minimum {} (stale MandateToken)",
                verdict.legislative_version, min_version
            )
        },
    }
}
