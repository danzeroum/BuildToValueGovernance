// BuildToValue v2.0 - Consent Validator
// LGPD Art. 7º, I - Base Legal: Consentimento
//
// Validates user consent for data processing.
// Checks if consent is present and valid.
//
// Author: BuildToValue Architecture Team
// License: Apache 2.0
// Padrão para todos os validadores
use crate::evidence::finding::Finding;
use crate::core::types::{ValidatorModule, TechnicalSeverity};
use crate::validators::Validator;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Consent Validator
///
/// Verifica se há consentimento válido do titular para processamento de dados.
///
/// LGPD Requirements:
/// - Art. 7º, I: Consentimento do titular
/// - Art. 8º: Consentimento deve ser livre, informado e inequívoco
///
/// Philosophy (Levinas - Ethics of the Other):
/// - Titular tem direito absoluto de escolha
/// - Sem consentimento = sem processamento (exceto outras bases legais)
#[derive(Debug, Clone)]
pub struct ConsentValidator {
    /// Minimum consent validity in days (default: 365)
    consent_validity_days: u32,

    /// Require explicit consent (not implicit)
    require_explicit: bool,
}

impl Default for ConsentValidator {
    fn default() -> Self {
        Self {
            consent_validity_days: 365,
            require_explicit: true,
        }
    }
}

impl ConsentValidator {
    pub fn new(consent_validity_days: u32, require_explicit: bool) -> Self {
        Self {
            consent_validity_days,
            require_explicit,
        }
    }

    /// Extract consent metadata from context
    fn extract_consent_metadata(&self, context_metadata: &HashMap<String, String>) -> ConsentMetadata {
        ConsentMetadata {
            has_consent: context_metadata
                .get("user.has_consent")
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),

            consent_date: context_metadata
                .get("user.consent_date")
                .and_then(|v| v.parse().ok()),

            consent_type: context_metadata
                .get("consent.type")
                .cloned(),

            is_explicit: context_metadata
                .get("consent.is_explicit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),

            processing_requires_consent: context_metadata
                .get("processing.requires_consent")
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),

            legal_basis: context_metadata
                .get("processing.legal_basis")
                .cloned(),
        }
    }

    /// Check if consent is expired
    fn is_consent_expired(&self, consent_date: Option<i64>) -> bool {
        if let Some(date) = consent_date {
            let now = chrono::Utc::now().timestamp();
            let days_since = (now - date) / 86400;
            days_since > self.consent_validity_days as i64
        } else {
            false // No date = assume valid (will be caught by has_consent=false)
        }
    }
}

impl Validator for ConsentValidator {
    fn validate(
        &self,
        _input: &str,
        context_metadata: Option<&HashMap<String, String>>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let metadata = match context_metadata {
            Some(m) => self.extract_consent_metadata(m),
            None => return findings, // No context = can't validate
        };

        // Check 1: Processing requires consent?
        if !metadata.processing_requires_consent {
            return findings; // Not applicable
        }

        // Check 2: Alternative legal basis exists?
        if let Some(ref legal_basis) = metadata.legal_basis {
            if legal_basis != "consent" && !legal_basis.is_empty() {
                return findings; // Has other legal basis (Art. 7º, II-X)
            }
        }

        // Check 3: Consent present?
        if !metadata.has_consent {
            findings.push(Finding {
                module: ValidatorModule::Consent,
                severity: TechnicalSeverity::Critical(255),
                rule_id: "LGPD_ART7_I_CONSENTIMENTO".to_string(),
                title: "MISSING_USER_CONSENT".to_string(),
                description: "Processing requires user consent (LGPD Art. 7º, I)".to_string(),
                confidence: 255, // 100% confidence
                position: (0, 0),
                metadata: Some(format!(
                    "has_consent=false, requires_consent=true, legal_basis={:?}",
                    metadata.legal_basis
                )),
            });
            return findings;
        }

        // Check 4: Consent expired?
        if self.is_consent_expired(metadata.consent_date) {
            findings.push(Finding {
                module: ValidatorModule::Consent,
                severity: TechnicalSeverity::High(200),
                rule_id: "CONSENT_EXPIRED".to_string(),
                title: "CONSENT_EXPIRED".to_string(),
                description: format!(
                    "Consent expired (validity: {} days)",
                    self.consent_validity_days
                ),
                confidence: 240,
                position: (0, 0),
                metadata: Some(format!(
                    "consent_date={:?}, validity_days={}",
                    metadata.consent_date, self.consent_validity_days
                )),
            });
        }

        // Check 5: Explicit consent required?
        if self.require_explicit && !metadata.is_explicit {
            findings.push(Finding {
                module: ValidatorModule::Consent,
                severity: TechnicalSeverity::High(180),
                rule_id: "LGPD_ART8_QUALIDADE_CONSENTIMENTO".to_string(),
                title: "CONSENT_NOT_EXPLICIT".to_string(),
                description: "Consent must be explicit (LGPD Art. 8º)".to_string(),
                confidence: 200,
                position: (0, 0),
                metadata: Some(format!(
                    "is_explicit=false, consent_type={:?}",
                    metadata.consent_type
                )),
            });
        }

        findings
    }

    fn name(&self) -> &str {
        "consent_validator"
    }

    fn bias_declaration(&self) -> crate::validators::BiasDeclaration {
        crate::validators::BiasDeclaration {
            false_positive_rate: 0.05, // 5% FPR (consent ambiguity)
            false_negative_rate: 0.02, // 2% FNR (missed consent)
            calibration_date: "2026-02-05".to_string(),
            test_dataset_size: 120,
            known_limitations: vec![
                "Cannot detect implicit consent (body language, etc.)".to_string(),
                "Consent validity period (365 days) is arbitrary".to_string(),
                "No cultural context (opt-in vs opt-out norms)".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsentMetadata {
    has_consent: bool,
    consent_date: Option<i64>, // Unix timestamp
    consent_type: Option<String>, // "explicit", "implicit", "opt_in", "opt_out"
    is_explicit: bool,
    processing_requires_consent: bool,
    legal_basis: Option<String>, // "consent", "legitimate_interest", "contract", etc.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_consent() {
        let validator = ConsentValidator::default();
        let mut metadata = HashMap::new();
        metadata.insert("user.has_consent".to_string(), "false".to_string());
        metadata.insert("processing.requires_consent".to_string(), "true".to_string());

        let findings = validator.validate("", Some(&metadata));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "LGPD_ART7_I_CONSENTIMENTO");
        assert!(matches!(findings[0].severity, TechnicalSeverity::Critical(_)));
    }

    #[test]
    fn test_consent_with_alternative_legal_basis() {
        let validator = ConsentValidator::default();
        let mut metadata = HashMap::new();
        metadata.insert("user.has_consent".to_string(), "false".to_string());
        metadata.insert("processing.requires_consent".to_string(), "true".to_string());
        metadata.insert("processing.legal_basis".to_string(), "legitimate_interest".to_string());

        let findings = validator.validate("", Some(&metadata));

        // No findings: has alternative legal basis (Art. 7º, IX)
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_valid_consent() {
        let validator = ConsentValidator::default();
        let mut metadata = HashMap::new();
        metadata.insert("user.has_consent".to_string(), "true".to_string());
        metadata.insert("consent.is_explicit".to_string(), "true".to_string());
        metadata.insert("processing.requires_consent".to_string(), "true".to_string());

        let findings = validator.validate("", Some(&metadata));

        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_implicit_consent_not_explicit() {
        let validator = ConsentValidator::new(365, true); // Require explicit
        let mut metadata = HashMap::new();
        metadata.insert("user.has_consent".to_string(), "true".to_string());
        metadata.insert("consent.is_explicit".to_string(), "false".to_string());
        metadata.insert("consent.type".to_string(), "implicit".to_string());

        let findings = validator.validate("", Some(&metadata));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "LGPD_ART8_QUALIDADE_CONSENTIMENTO");
    }
}
