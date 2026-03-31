//! Monitor judicial — ponto de entrada único para auditoria.
//!
//! Restrições constitucionais:
//! - Importa `btv-types` APENAS
//! - Consulta `btv-sigma` DIRETAMENTE (nunca através do Executivo)
//! - Assina relatórios com chave Ed25519 INDEPENDENTE de L e E
use chrono::Utc;
use crate::{
    HmacVerifier, ReceiptVerifier, LedgerQuery,
    payload_verify::verify_payload,
    audit_report::{AuditReport, JudicialAuditor, FailureDetail},
    hmac_verify::JudicialError,
};

/// Resultado de verificação de um payload.
#[derive(Debug, Clone)]
pub struct VerifiedPayload {
    pub verdict_hash: [u8; 32],
    pub log_index:    u64,
    pub decision:     btv_types::Decision,
    pub valid:        bool,
    pub details:      String,
}

/// O Monitor Judicial — ponto de entrada único para auditoria.
pub struct Monitor {
    hmac_verifier:    HmacVerifier,
    receipt_verifier: ReceiptVerifier,
    ledger:           LedgerQuery,
    auditor:          JudicialAuditor,
}

impl Monitor {
    pub fn new(
        hmac_verifier:    HmacVerifier,
        receipt_verifier: ReceiptVerifier,
        ledger:           LedgerQuery,
        auditor:          JudicialAuditor,
    ) -> Self {
        Self { hmac_verifier, receipt_verifier, ledger, auditor }
    }

    /// Verifica um único DeliveryPayload contra o Transparency Log.
    ///
    /// Flow:
    /// 1. Busca Merkle proof em btv-sigma (diretamente)
    /// 2. Busca root atual em btv-sigma
    /// 3. Verifica HMAC + Ed25519 + Merkle + root consistency
    pub async fn verify(
        &self,
        payload: &btv_types::DeliveryPayload,
    ) -> Result<VerifiedPayload, JudicialError> {
        let log_index = payload.receipt.log_index;
        let proof  = self.ledger.get_proof(log_index).await?;
        let root   = self.ledger.current_root().await?;

        let v = verify_payload(
            payload,
            &self.hmac_verifier,
            &self.receipt_verifier,
            &proof,
            &root,
        );

        Ok(VerifiedPayload {
            verdict_hash: v.verdict_hash,
            log_index,
            decision: payload.verdict.decision,
            valid:    v.overall_valid,
            details:  v.details,
        })
    }

    /// Auditoria em lote: verifica um slice de payloads e retorna AuditReport assinado.
    pub async fn audit_batch(
        &self,
        payloads: &[btv_types::DeliveryPayload],
    ) -> AuditReport {
        let mut passed   = 0usize;
        let mut failed   = 0usize;
        let mut failures = Vec::new();

        for payload in payloads {
            match self.verify(payload).await {
                Ok(v) if v.valid => passed += 1,
                Ok(v) => {
                    failed += 1;
                    if failures.len() < 100 {
                        failures.push(FailureDetail {
                            verdict_hash: v.verdict_hash,
                            log_index:    v.log_index,
                            reason:       v.details,
                        });
                    }
                }
                Err(e) => {
                    failed += 1;
                    if failures.len() < 100 {
                        failures.push(FailureDetail {
                            verdict_hash: [0; 32],
                            log_index:    payload.receipt.log_index,
                            reason:       e.to_string(),
                        });
                    }
                }
            }
        }

        let root = self.ledger.current_root().await.unwrap_or([0; 32]);

        let mut report = AuditReport {
            report_id:         format!("audit-{}", Utc::now().timestamp_millis()),
            timestamp:         Utc::now().to_rfc3339(),
            payloads_verified: payloads.len(),
            payloads_passed:   passed,
            payloads_failed:   failed,
            failures,
            auditor_id:        self.auditor.auditor_id.clone(),
            log_root:          root,
            tree_size:         0,
            signature:         [0; 64],
            auditor_pubkey:    [0; 32],
        };

        self.auditor.sign_report(&mut report);
        report
    }
}
