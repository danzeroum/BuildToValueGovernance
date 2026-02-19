//! Policy Engine v1.6.0 — YAML → Runtime with hard blocks
//! ADR-011: Policy-as-Code (Legislativo da República Algorítmica)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};
use crate::core::types::BiasDeclaration;
use crate::evidence::Finding;

// ---------------------------------------------------------------------
// POLICY TYPES
// ---------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub version: String,
    pub metadata: PolicyMetadata,
    #[serde(default)]
    pub hard_blocks: Vec<String>,
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
// EVALUATION RESULT
// ---------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct PolicyEvaluation {
    pub action: PolicyAction,
    pub matched_policies: Vec<String>,
    pub hard_blocked: bool,
    pub hard_block_term: Option<String>,
}

impl PolicyEvaluation {
    fn allow() -> Self {
        Self {
            action: PolicyAction::Allow,
            matched_policies: Vec::new(),
            hard_blocked: false,
            hard_block_term: None,
        }
    }

    fn hard_block(term: String) -> Self {
        Self {
            action: PolicyAction::Block,
            matched_policies: vec!["HARD_BLOCK".to_string()],
            hard_blocked: true,
            hard_block_term: Some(term),
        }
    }
}

// ---------------------------------------------------------------------
// POLICY ENGINE
// ---------------------------------------------------------------------
pub struct PolicyEngine {
    policy_set: PolicySet,
    validator_index: HashMap<String, Vec<usize>>,
    hard_block_set: HashSet<String>,
    metrics: PolicyMetrics,
}

#[derive(Debug, Default)]
pub struct PolicyMetrics {
    pub evaluations_total: u64,
    pub matches_total: u64,
    pub hard_blocks_total: u64,
    pub actions_by_level: [u64; 5],
}

impl PolicyEngine {
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let yaml = fs::read_to_string(path).context("Failed to read policy file")?;
        Self::from_yaml_str(&yaml)
    }

    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        let policy_set: PolicySet = serde_yaml::from_str(yaml)
            .context("Failed to parse policy YAML")?;
        Self::new(policy_set)
    }

    /// Fail-secure: if YAML is invalid, returns engine that blocks everything.
    pub fn from_yaml_str_failsecure(yaml: &str) -> Self {
        Self::from_yaml_str(yaml).unwrap_or_else(|e| {
            log::error!("Policy YAML invalid, fail-secure BLOCK ALL: {}", e);
            Self::block_all_engine()
        })
    }

    pub fn new(policy_set: PolicySet) -> Result<Self> {
        // Validate policies
        for p in &policy_set.policies {
            if !(0.0..=1.0).contains(&p.conditions.min_severity) {
                anyhow::bail!("Policy '{}': min_severity must be 0.0-1.0", p.id);
            }
            if !(0.0..=1.0).contains(&p.conditions.min_confidence) {
                anyhow::bail!("Policy '{}': min_confidence must be 0.0-1.0", p.id);
            }
        }

        // Build validator index (enabled policies only)
        let mut index: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, p) in policy_set.policies.iter().enumerate() {
            if p.enabled {
                for v in &p.conditions.validators {
                    index.entry(v.clone()).or_default().push(idx);
                }
                if p.conditions.validators.is_empty() {
                    index.entry("*".to_string()).or_default().push(idx);
                }
            }
        }

        // Build hard block set (case-insensitive, O(1) lookup)
        let hard_block_set: HashSet<String> = policy_set
            .hard_blocks
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        Ok(Self {
            policy_set,
            validator_index: index,
            hard_block_set,
            metrics: PolicyMetrics::default(),
        })
    }

    /// Returns a fail-secure engine that blocks everything.
    fn block_all_engine() -> Self {
        let policy_set = PolicySet {
            version: "failsecure".to_string(),
            metadata: PolicyMetadata {
                name: "FAIL-SECURE".to_string(),
                description: "Blocks all — policy load failed".to_string(),
                created_at: String::new(),
                updated_at: String::new(),
                author: "system".to_string(),
            },
            hard_blocks: Vec::new(),
            policies: vec![Policy {
                id: "failsecure-block-all".to_string(),
                name: "Block All".to_string(),
                description: "Fail-secure: policy load failed".to_string(),
                enabled: true,
                priority: u32::MAX,
                conditions: PolicyConditions::default(),
                action: PolicyAction::Block,
            }],
        };
        // Safe to unwrap: manually constructed valid policy
        Self::new(policy_set).unwrap()
    }

    // -----------------------------------------------------------------
    // HARD BLOCK CHECK (O(1) per term)
    // -----------------------------------------------------------------

    /// Check input against hard block list.
    /// Returns Some(matched_term) if blocked.
    pub fn check_hard_blocks(&mut self, input: &str) -> Option<String> {
        let lower = input.to_lowercase();
        for term in &self.hard_block_set {
            if lower.contains(term) {
                self.metrics.hard_blocks_total += 1;
                return Some(term.clone());
            }
        }
        None
    }

    // -----------------------------------------------------------------
    // EVALUATE (per-finding)
    // -----------------------------------------------------------------

    pub fn evaluate(
        &mut self,
        validator_name: &str,
        _category: &str,
        severity: f32,
        confidence: f32,
    ) -> PolicyAction {
        self.metrics.evaluations_total += 1;
        let mut max_action = PolicyAction::Allow;

        // Get policies for this validator + wildcard policies
        let mut relevant: Vec<&Policy> = Vec::new();
        if let Some(indices) = self.validator_index.get(validator_name) {
            for &i in indices {
                relevant.push(&self.policy_set.policies[i]);
            }
        }
        if let Some(indices) = self.validator_index.get("*") {
            for &i in indices {
                relevant.push(&self.policy_set.policies[i]);
            }
        }

        // Sort by priority descending (highest first)
        relevant.sort_by(|a, b| b.priority.cmp(&a.priority));

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

    // -----------------------------------------------------------------
    // EVALUATE FULL (input + findings)
    // -----------------------------------------------------------------

    /// Full evaluation: hard blocks + per-finding policy evaluation.
    pub fn evaluate_full(
        &mut self,
        input: &str,
        findings: &[&Finding],
    ) -> PolicyEvaluation {
        // 1. Hard block check first
        if let Some(term) = self.check_hard_blocks(input) {
            return PolicyEvaluation::hard_block(term);
        }

        // 2. No findings → allow
        if findings.is_empty() {
            return PolicyEvaluation::allow();
        }

        // 3. Evaluate each finding, take most severe action
        let mut max_action = PolicyAction::Allow;
        let mut matched_ids: Vec<String> = Vec::new();

        for finding in findings {
            let validator_name = format!("{:?}", finding.module).to_lowercase();
            let severity = finding.severity.to_score();
            let confidence = finding.confidence as f32 / 100.0;

            let action = self.evaluate(&validator_name, "", severity, confidence);
            if action.severity_level() > max_action.severity_level() {
                max_action = action;
            }

            if action != PolicyAction::Allow {
                matched_ids.push(format!("{}->{:?}", validator_name, action));
            }
        }

        PolicyEvaluation {
            action: max_action,
            matched_policies: matched_ids,
            hard_blocked: false,
            hard_block_term: None,
        }
    }

    // -----------------------------------------------------------------
    // BIAS DECLARATION
    // -----------------------------------------------------------------

    pub fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.05, 0.03, 20260215, 0)
            .with_limitations(
                "Policy accuracy depends on YAML author. Hard blocks are exact-match only."
            )
            .with_affected_groups(
                "Obfuscated inputs may bypass string-match hard blocks."
            )
    }

    // -----------------------------------------------------------------
    // ACCESSORS
    // -----------------------------------------------------------------

    fn matches(&self, policy: &Policy, validator: &str, severity: f32, confidence: f32) -> bool {
        let cond = &policy.conditions;
        let v_match = cond.validators.is_empty()
            || cond.validators.iter().any(|v| v == validator);
        let sev_match = severity >= cond.min_severity;
        let conf_match = confidence >= cond.min_confidence;
        v_match && sev_match && conf_match
    }

    pub fn get_metrics(&self) -> &PolicyMetrics { &self.metrics }
    pub fn get_policy_set(&self) -> &PolicySet { &self.policy_set }
    pub fn hard_block_count(&self) -> usize { self.hard_block_set.len() }
    pub fn policy_count(&self) -> usize { self.policy_set.policies.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_yaml() -> &'static str {
        r#"
version: "1.6"
metadata:
  name: "Test"
  description: "Test"
  created_at: "2026-02-15"
  updated_at: "2026-02-15"
  author: "Test"
hard_blocks:
  - "DROP TABLE"
  - "<script>"
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
  - id: "redact-email"
    name: "Redact email"
    description: "Mask emails"
    enabled: true
    priority: 80
    conditions:
      validators: ["email"]
      min_severity: 0.3
      min_confidence: 0.8
    action: REDACT
  - id: "log-all"
    name: "Log everything"
    description: "Log all findings"
    enabled: true
    priority: 1
    conditions:
      validators: []
      min_severity: 0.0
      min_confidence: 0.0
    action: LOG
"#
    }

    #[test]
    fn test_policy_from_yaml() {
        let engine = PolicyEngine::from_yaml_str(test_yaml()).unwrap();
        assert_eq!(engine.policy_count(), 3);
        assert_eq!(engine.hard_block_count(), 2);
    }

    #[test]
    fn test_hard_block_detection() {
        let mut engine = PolicyEngine::from_yaml_str(test_yaml()).unwrap();
        assert!(engine.check_hard_blocks("SELECT * DROP TABLE users").is_some());
        assert!(engine.check_hard_blocks("<script>alert(1)</script>").is_some());
        assert!(engine.check_hard_blocks("normal input").is_none());
    }

    #[test]
    fn test_hard_block_case_insensitive() {
        let mut engine = PolicyEngine::from_yaml_str(test_yaml()).unwrap();
        assert!(engine.check_hard_blocks("drop table users").is_some());
        assert!(engine.check_hard_blocks("DROP TABLE").is_some());
    }

    #[test]
    fn test_evaluate_cpf_blocks() {
        let mut engine = PolicyEngine::from_yaml_str(test_yaml()).unwrap();
        let action = engine.evaluate("cpf", "", 0.8, 0.95);
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn test_evaluate_email_redacts() {
        let mut engine = PolicyEngine::from_yaml_str(test_yaml()).unwrap();
        let action = engine.evaluate("email", "", 0.5, 0.9);
        assert_eq!(action, PolicyAction::Redact);
    }

    #[test]
    fn test_evaluate_below_threshold_logs() {
        let mut engine = PolicyEngine::from_yaml_str(test_yaml()).unwrap();
        // Low severity, low confidence — only matches "log-all" wildcard
        let action = engine.evaluate("unknown_validator", "", 0.05, 0.05);
        assert_eq!(action, PolicyAction::Log);
    }

    #[test]
    fn test_failsecure_invalid_yaml() {
        let engine = PolicyEngine::from_yaml_str_failsecure("{{invalid yaml!!");
        let action = engine.policy_set.policies[0].action;
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn test_invalid_severity_rejected() {
        let yaml = r#"
version: "1.0"
metadata:
  name: "Bad"
  description: "Bad"
  created_at: "2026-01-01"
  updated_at: "2026-01-01"
  author: "Test"
policies:
  - id: "bad"
    name: "Bad"
    description: "Bad"
    enabled: true
    priority: 1
    conditions:
      min_severity: 2.0
      min_confidence: 0.5
    action: BLOCK
"#;
        assert!(PolicyEngine::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn test_metrics_tracking() {
        let mut engine = PolicyEngine::from_yaml_str(test_yaml()).unwrap();
        engine.evaluate("cpf", "", 0.8, 0.95);
        engine.evaluate("email", "", 0.5, 0.9);
        engine.evaluate("cpf", "", 0.1, 0.1);

        let m = engine.get_metrics();
        assert_eq!(m.evaluations_total, 3);
        assert!(m.matches_total > 0);
    }
}