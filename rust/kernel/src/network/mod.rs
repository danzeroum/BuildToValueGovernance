//! Network Module v1.7.0 (ADR-014)
pub mod ip_classifier;
pub mod jurisdiction;

pub use ip_classifier::{IpClassifier, IpClassification, IpRisk, IpCategory};
pub use jurisdiction::{
    JurisdictionMapper, JurisdictionResult, Jurisdiction, ComplianceFramework,
};