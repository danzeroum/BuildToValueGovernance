//! Policy Engine v1.0 (placeholder)
//! Carregamento de políticas YAML.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};

// ---------------------------------------------------------------------
// POLICY TYPES
// ---------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub version: String,
    pub metadata: PolicyMetadata,
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
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: u32,
    pub conditions: PolicyConditions,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConditions {
    #[serde(default)]
    pub validators: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub min_severity: f32,
    #[serde(default)]
    pub min_confidence: f32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyAction {
    Allow,
    Log,
    Educate,
    Redact,
    Block,
}

impl PolicyAction {
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

// ---------------------------------------------------------------------
// POLICY ENGINE (STUB)
// ---------------------------------------------------------------------
pub struct PolicyEngine {
    policy_set: PolicySet,
    validator_index: HashMap<String, Vec<usize>>,
    metrics: PolicyMetrics,
}

#[derive(Debug, Default)]
pub struct PolicyMetrics {
    pub evaluations_total: u64,
    pub matches_total: u64,
    pub actions_by_level: [u64; 5],
}

impl PolicyEngine {
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let yaml = fs::read_to_string(path).context("Failed to read policy file")?;
        Self::from_yaml_str(&yaml)
    }

    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        let policy_set: PolicySet = serde_yaml::from_str(yaml).context("Failed to parse YAML")?;
        Self::new(policy_set)
    }

    pub fn new(policy_set: PolicySet) -> Result<Self> {
        // Validação básica
        for p in &policy_set.policies {
            if !(0.0..=1.0).contains(&p.conditions.min_severity) {
                anyhow::bail!("min_severity must be 0.0-1.0");
            }
            if !(0.0..=1.0).contains(&p.conditions.min_confidence) {
                anyhow::bail!("min_confidence must be 0.0-1.0");
            }
        }

        let mut index = HashMap::new();
        for (idx, p) in policy_set.policies.iter().enumerate() {
            if p.enabled {
                for v in &p.conditions.validators {
                    index.entry(v.clone()).or_insert_with(Vec::new).push(idx);
                }
            }
        }

        Ok(Self {
            policy_set,
            validator_index: index,
            metrics: PolicyMetrics::default(),
        })
    }

    pub fn evaluate(
        &mut self,
        validator_name: &str,
        _category: &str,
        severity: f32,
        confidence: f32,
    ) -> PolicyAction {
        self.metrics.evaluations_total += 1;
        let mut max_action = PolicyAction::Allow;

        let relevant: Vec<&Policy> = if let Some(indices) = self.validator_index.get(validator_name) {
            indices.iter().map(|&i| &self.policy_set.policies[i]).collect()
        } else {
            self.policy_set.policies.iter().filter(|p| p.enabled).collect()
        };

        for policy in relevant {
            if self.matches(policy, validator_name, severity, confidence) {
                self.metrics.matches_total += 1;
                if policy.action.severity_level() > max_action.severity_level() {
                    max_action = policy.action;
                }
            }
        }

        self.metrics.actions_by_level[max_action.severity_level() as usize] += 1;
        max_action
    }

    fn matches(&self, policy: &Policy, validator: &str, severity: f32, confidence: f32) -> bool {
        let cond = &policy.conditions;
        let v_match = cond.validators.is_empty() || cond.validators.contains(&validator.to_string());
        let sev_match = severity >= cond.min_severity;
        let conf_match = confidence >= cond.min_confidence;
        v_match && sev_match && conf_match
    }

    pub fn get_metrics(&self) -> &PolicyMetrics { &self.metrics }
    pub fn get_policy_set(&self) -> &PolicySet { &self.policy_set }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_from_yaml() {
        let yaml = r#"
version: "1.0"
metadata:
  name: "Test"
  description: "Test"
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
"#;
        let engine = PolicyEngine::from_yaml_str(yaml).unwrap();
        assert_eq!(engine.policy_set.policies.len(), 1);
        assert_eq!(engine.policy_set.policies[0].action, PolicyAction::Block);
    }
}