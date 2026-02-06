//! Policy Engine v1.0
//!
//! Policy-as-Code implementation:
//! - YAML policies (versionadas em Git)
//! - Runtime enforcement
//! - Action levels: ALLOW, LOG, EDUCATE, REDACT, BLOCK
//! - Blind testing support (Rawls)
//!
//! Gate: Week 3 - Day 15

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};

// ═══════════════════════════════════════════════════════════════════════════
// POLICY TYPES
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    /// Versão do policy set
    pub version: String,

    /// Metadata
    pub metadata: PolicyMetadata,

    /// Policies
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
    pub author: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// ID único da policy
    pub id: String,

    /// Nome descritivo
    pub name: String,

    /// Descrição
    pub description: String,

    /// Habilitado
    pub enabled: bool,

    /// Prioridade (maior = mais importante)
    pub priority: u32,

    /// Condições (quando aplicar)
    pub conditions: PolicyConditions,

    /// Ação a tomar
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConditions {
    /// Validators que devem detectar (qualquer)
    #[serde(default)]
    pub validators: Vec<String>,

    /// Categorias (qualquer)
    #[serde(default)]
    pub categories: Vec<String>,

    /// Severidade mínima (0.0-1.0)
    #[serde(default)]
    pub min_severity: f32,

    /// Confiança mínima (0.0-1.0)
    #[serde(default)]
    pub min_confidence: f32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyAction {
    /// Permitir (apenas log)
    Allow,

    /// Log para auditoria
    Log,

    /// Educar usuário (warning)
    Educate,

    /// Redact (mascara dados)
    Redact,

    /// Bloquear completamente
    Block,
}

impl PolicyAction {
    /// Retorna severidade da ação (0-4)
    pub fn severity_level(&self) -> u8 {
        match self {
            PolicyAction::Allow => 0,
            PolicyAction::Log => 1,
            PolicyAction::Educate => 2,
            PolicyAction::Redact => 3,
            PolicyAction::Block => 4,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// POLICY ENGINE
// ═══════════════════════════════════════════════════════════════════════════

pub struct PolicyEngine {
    /// Policy set carregado
    policy_set: PolicySet,

    /// Cache de policies por validator
    validator_index: HashMap<String, Vec<usize>>,

    /// Métricas
    metrics: PolicyMetrics,
}

#[derive(Debug, Default)]
pub struct PolicyMetrics {
    pub evaluations_total: u64,
    pub matches_total: u64,
    pub actions_by_level: [u64; 5], // ALLOW, LOG, EDUCATE, REDACT, BLOCK
}

impl PolicyEngine {
    /// Cria engine a partir de YAML file
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let yaml_str = fs::read_to_string(path)
            .context("Failed to read policy file")?;

        Self::from_yaml_str(&yaml_str)
    }

    /// Cria engine a partir de YAML string
    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        let policy_set: PolicySet = serde_yaml::from_str(yaml)
            .context("Failed to parse YAML")?;

        Self::new(policy_set)
    }

    /// Cria engine com policy set
    pub fn new(policy_set: PolicySet) -> Result<Self> {
        // Valida policies
        for policy in &policy_set.policies {
            if policy.conditions.min_severity > 1.0 || policy.conditions.min_severity < 0.0 {
                anyhow::bail!("Invalid min_severity in policy {}: must be 0.0-1.0", policy.id);
            }
            if policy.conditions.min_confidence > 1.0 || policy.conditions.min_confidence < 0.0 {
                anyhow::bail!("Invalid min_confidence in policy {}: must be 0.0-1.0", policy.id);
            }
        }

        // Constrói index por validator
        let mut validator_index: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, policy) in policy_set.policies.iter().enumerate() {
            if !policy.enabled {
                continue;
            }

            for validator in &policy.conditions.validators {
                validator_index
                    .entry(validator.clone())
                    .or_default()
                    .push(idx);
            }
        }

        Ok(Self {
            policy_set,
            validator_index,
            metrics: PolicyMetrics::default(),
        })
    }

    /// Avalia políticas dado um finding
    ///
    /// Retorna a ação mais restritiva que aplica.
    pub fn evaluate(
        &mut self,
        validator_name: &str,
        category: &str,
        severity: f32,
        confidence: f32,
    ) -> PolicyAction {
        self.metrics.evaluations_total += 1;

        let mut max_action = PolicyAction::Allow;

        // Busca policies relevantes (indexed)
        let relevant_policies: Vec<&Policy> = if let Some(indices) = self.validator_index.get(validator_name) {
            indices.iter().map(|&idx| &self.policy_set.policies[idx]).collect()
        } else {
            // Fallback: busca em todas
            self.policy_set.policies
                .iter()
                .filter(|p| p.enabled)
                .collect()
        };

        // Avalia cada policy (por prioridade)
        for policy in relevant_policies {
            if self.matches_policy(policy, validator_name, category, severity, confidence) {
                self.metrics.matches_total += 1;

                // Atualiza ação se mais restritiva
                if policy.action.severity_level() > max_action.severity_level() {
                    max_action = policy.action;
                }
            }
        }

        // Atualiza métricas
        self.metrics.actions_by_level[max_action.severity_level() as usize] += 1;

        max_action
    }

    /// Verifica se policy aplica
    fn matches_policy(
        &self,
        policy: &Policy,
        validator_name: &str,
        category: &str,
        severity: f32,
        confidence: f32,
    ) -> bool {
        let cond = &policy.conditions;

        // Validator match
        let validator_match = cond.validators.is_empty()
            || cond.validators.contains(&validator_name.to_string());

        // Category match
        let category_match = cond.categories.is_empty()
            || cond.categories.contains(&category.to_string());

        // Severity check
        let severity_match = severity >= cond.min_severity;

        // Confidence check
        let confidence_match = confidence >= cond.min_confidence;

        validator_match && category_match && severity_match && confidence_match
    }

    /// Retorna métricas
    pub fn get_metrics(&self) -> &PolicyMetrics {
        &self.metrics
    }

    /// Retorna policy set
    pub fn get_policy_set(&self) -> &PolicySet {
        &self.policy_set
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_from_yaml() {
        let yaml = r#"
version: "1.0"
metadata:
  name: "Test Policy Set"
  description: "Test policies"
  created_at: "2026-02-04"
  updated_at: "2026-02-04"
  author: "Test"
policies:
  - id: "block-cpf"
    name: "Block CPF"
    description: "Block valid CPF"
    enabled: true
    priority: 100
    conditions:
      validators: ["cpf"]
      min_severity: 0.7
      min_confidence: 0.9
    action: BLOCK

  - id: "log-url"
    name: "Log URLs"
    description: "Log all URLs"
    enabled: true
    priority: 50
    conditions:
      validators: ["url"]
    action: LOG
"#;

        let engine = PolicyEngine::from_yaml_str(yaml).unwrap();
        assert_eq!(engine.policy_set.policies.len(), 2);
        assert_eq!(engine.policy_set.policies[0].action, PolicyAction::Block);
    }

    #[test]
    fn test_policy_evaluation() {
        let yaml = r#"
version: "1.0"
metadata:
  name: "Test"
  description: "Test"
  created_at: "2026-02-04"
  updated_at: "2026-02-04"
  author: "Test"
policies:
  - id: "high-severity"
    name: "High Severity Block"
    description: "Block high severity"
    enabled: true
    priority: 100
    conditions:
      min_severity: 0.8
    action: BLOCK
"#;

        let mut engine = PolicyEngine::from_yaml_str(yaml).unwrap();

        // Alta severidade → BLOCK
        let action = engine.evaluate("cpf", "pii", 0.9, 0.95);
        assert_eq!(action, PolicyAction::Block);

        // Baixa severidade → ALLOW
        let action = engine.evaluate("cpf", "pii", 0.3, 0.95);
        assert_eq!(action, PolicyAction::Allow);
    }

    #[test]
    fn test_multiple_policies() {
        let yaml = r#"
version: "1.0"
metadata:
  name: "Test"
  description: "Test"
  created_at: "2026-02-04"
  updated_at: "2026-02-04"
  author: "Test"
policies:
  - id: "log-all"
    name: "Log All"
    enabled: true
    priority: 10
    conditions: {}
    action: LOG

  - id: "block-cpf"
    name: "Block CPF"
    enabled: true
    priority: 100
    conditions:
      validators: ["cpf"]
    action: BLOCK
"#;

        let mut engine = PolicyEngine::from_yaml_str(yaml).unwrap();

        // CPF → BLOCK (mais restritivo que LOG)
        let action = engine.evaluate("cpf", "pii", 0.8, 0.9);
        assert_eq!(action, PolicyAction::Block);

        // URL → LOG (não tem policy específica)
        let action = engine.evaluate("url", "network", 0.5, 0.8);
        assert_eq!(action, PolicyAction::Log);
    }

    #[test]
    fn test_metrics() {
        let yaml = r#"
version: "1.0"
metadata:
  name: "Test"
  description: "Test"
  created_at: "2026-02-04"
  updated_at: "2026-02-04"
  author: "Test"
policies:
  - id: "block"
    name: "Block"
    enabled: true
    priority: 100
    conditions:
      min_severity: 0.8
    action: BLOCK
"#;

        let mut engine = PolicyEngine::from_yaml_str(yaml).unwrap();

        // 3 avaliações
        engine.evaluate("cpf", "pii", 0.9, 0.95);
        engine.evaluate("cpf", "pii", 0.5, 0.95);
        engine.evaluate("url", "network", 0.9, 0.8);

        let metrics = engine.get_metrics();
        assert_eq!(metrics.evaluations_total, 3);
        assert_eq!(metrics.actions_by_level[4], 2); // 2 BLOCKs
        assert_eq!(metrics.actions_by_level[0], 1); // 1 ALLOW
    }
}
