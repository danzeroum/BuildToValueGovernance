//! Validator Registry
//!
//! Orquestra todos os validators disponíveis.

pub mod cpf;
pub mod patterns;

use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION RESULT
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub validator_name: String,
    pub is_violation: bool,
    pub message: String,
    pub category: String,
    pub location: String,
    pub evidence: String,
    pub severity: f32,
    pub confidence: f32,
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATOR REGISTRY
// ═══════════════════════════════════════════════════════════════════════════

pub struct ValidatorRegistry {
    validators: HashMap<String, Box<dyn Validator>>,
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            validators: HashMap::new(),
        };

        // Registra validators
        registry.register("cpf", Box::new(cpf::CpfValidator));
        registry.register("email", Box::new(patterns::EmailValidator));
        registry.register("url", Box::new(patterns::UrlValidator));

        registry
    }

    pub fn register(&mut self, name: &str, validator: Box<dyn Validator>) {
        self.validators.insert(name.to_string(), validator);
    }

    pub fn validate_all(&self, input: &str) -> Vec<ValidationResult> {
        let mut results = Vec::new();

        for (name, validator) in &self.validators {
            if let Some(result) = validator.validate(input, name) {
                results.push(result);
            }
        }

        results
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATOR TRAIT
// ═══════════════════════════════════════════════════════════════════════════

pub trait Validator: Send + Sync {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult>;
}

//! Validator Registry
//!
//! Orquestra todos os validators disponíveis.

pub mod brazilian_ids;
pub mod credit_card;
pub mod network;
pub mod statistics;
pub mod patterns;

use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION RESULT
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub validator_name: String,
    pub is_violation: bool,
    pub message: String,
    pub category: String,
    pub location: String,
    pub evidence: String,
    pub severity: f32,
    pub confidence: f32,
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATOR REGISTRY v2.0
// ═══════════════════════════════════════════════════════════════════════════

pub struct ValidatorRegistry {
    validators: HashMap<String, Box<dyn Validator>>,
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            validators: HashMap::new(),
        };

        // Brazilian IDs
        registry.register("cpf", Box::new(brazilian_ids::CpfValidator));
        registry.register("cnpj", Box::new(brazilian_ids::CnpjValidator));

        // Financial
        registry.register("credit_card", Box::new(credit_card::CreditCardValidator));

        // Network
        registry.register("ipv4", Box::new(network::Ipv4Validator));
        registry.register("url", Box::new(network::UrlValidator));
        registry.register("domain", Box::new(network::DomainValidator));

        // Statistics
        registry.register("entropy", Box::new(statistics::EntropyValidator::default()));
        registry.register("zscore", Box::new(statistics::ZScoreValidator::default()));
        registry.register("pattern", Box::new(statistics::PatternValidator));

        // Basic patterns
        registry.register("email", Box::new(patterns::EmailValidator));

        registry
    }

    pub fn register(&mut self, name: &str, validator: Box<dyn Validator>) {
        self.validators.insert(name.to_string(), validator);
    }

    pub fn validate_all(&self, input: &str) -> Vec<ValidationResult> {
        let mut results = Vec::new();

        for (name, validator) in &self.validators {
            if let Some(result) = validator.validate(input, name) {
                results.push(result);
            }
        }

        results
    }

    pub fn count(&self) -> usize {
        self.validators.len()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATOR TRAIT
// ═══════════════════════════════════════════════════════════════════════════

pub trait Validator: Send + Sync {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult>;
}
