//! Relatório de auditoria assinado pelo Judiciário.
//!
//! Paper 5, §4.2: "J assina o relatório de auditoria com sua própria chave Ed25519."
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Signature};
use rand::RngCore;

/// Detalhe de uma falha de verificação.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FailureDetail {
    pub verdict_hash: [u8; 32],
    pub log_index:    u64,
    pub reason:       String,
}

/// Relatório de auditoria assinado pelo Judiciário.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditReport {
    pub report_id:         String,
    pub timestamp:         String,
    pub payloads_verified: usize,
    pub payloads_passed:   usize,
    pub payloads_failed:   usize,
    pub failures:          Vec<FailureDetail>,
    pub auditor_id:        String,
    pub log_root:          [u8; 32],
    pub tree_size:         u64,
    #[serde(with = "btv_types::serde_bytes_64_pub")]
    pub signature:         [u8; 64],
    pub auditor_pubkey:    [u8; 32],
}

/// Auditor judicial — mantém chave Ed25519 independente de L e E.
pub struct JudicialAuditor {
    signing_key: SigningKey,
    pub auditor_id: String,
}

impl JudicialAuditor {
    /// Gera um novo par de chaves usando OS CSPRNG.
    /// Em produção: carregar de HSM/TPM.
    pub fn new(auditor_id: String) -> Self {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self { signing_key: SigningKey::from_bytes(&secret), auditor_id }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Assina o relatório, preenchendo `signature` e `auditor_pubkey`.
    pub fn sign_report(&self, report: &mut AuditReport) {
        let msg = canonical_bytes(report);
        let sig: Signature = self.signing_key.sign(&msg);
        report.signature    = sig.to_bytes();
        report.auditor_pubkey = *self.signing_key.verifying_key().as_bytes();
    }

    /// Verifica um relatório assinado por qualquer auditor judicial.
    pub fn verify_report(report: &AuditReport) -> bool {
        let msg = canonical_bytes(report);
        let Ok(pk) = VerifyingKey::from_bytes(&report.auditor_pubkey) else { return false; };
        let sig = Signature::from_bytes(&report.signature);
        pk.verify(&msg, &sig).is_ok()
    }
}

/// Serialização canônica dos campos estruéveis do relatório (exceto signature e pubkey).
fn canonical_bytes(r: &AuditReport) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        r.report_id, r.timestamp,
        r.payloads_verified, r.payloads_passed, r.payloads_failed,
        r.failures.len(), r.auditor_id,
        hex::encode(r.log_root), r.tree_size,
    ).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_report() -> AuditReport {
        AuditReport {
            report_id: "audit-test".into(),
            timestamp: "2026-03-30T00:00:00Z".into(),
            payloads_verified: 10,
            payloads_passed:   9,
            payloads_failed:   1,
            failures:          vec![],
            auditor_id:        "test-auditor".into(),
            log_root:          [0u8; 32],
            tree_size:         10,
            signature:         [0u8; 64],
            auditor_pubkey:    [0u8; 32],
        }
    }

    #[test]
    fn sign_and_verify_report() {
        let auditor = JudicialAuditor::new("test".into());
        let mut report = make_report();
        auditor.sign_report(&mut report);
        assert!(JudicialAuditor::verify_report(&report));
    }

    #[test]
    fn tampered_report_fails_verification() {
        let auditor = JudicialAuditor::new("test".into());
        let mut report = make_report();
        auditor.sign_report(&mut report);
        report.payloads_failed = 99; // tamper
        assert!(!JudicialAuditor::verify_report(&report));
    }
}
