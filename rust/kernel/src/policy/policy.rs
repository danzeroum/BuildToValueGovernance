//! Policy Engine v1.6.0 — YAML → Runtime with hard blocks
//! ADR-011: Policy-as-Code (Legislativo da República Algorítmica)
//! ADR-045: ThreatModel + evaluate_with_context() (trust_boundary filter)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use anyhow::{Result, Context};
use crate::core::types::BiasDeclaration;
use crate::evidence::Finding;

// ─────────────────────────────────────────────────────────────────────────────
// ADR-045: THREAT MODEL
// Fail-secure: ausência de threat_model → trust_boundary = "public" (mais restritivo)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModel {
    /// Perímetro para o qual a policy foi calibrada.
    /// "public" (default) | "federated" | "internal"
    /// Fail-secure: ausência → "public".
    #[serde(default = "ThreatModel::default_trust_boundary")]
    pub trust_boundary: String,

    /// Capabilities assumidas do atacante.
    /// Lista vazia = assume atacante com todas as capabilities (máxima restrição).
    #[serde(default)]
    pub assumed_attacker_capabilities: Vec<String>,

    /// Contextos FORA do escopo desta policy.
    /// Documentação explícita previne false positives por scope creep.
    #[serde(default)]
    pub scope_exclusions: Vec<String>,
}

impl ThreatModel {
    fn default_trust_boundary() -> String {
        "public".to_string()
    }

    /// Nível numérico do perímetro. Menor = mais fechado.
    /// Fail-secure: string desconhecida → 2 (public — mais permissivo para a policy,
    /// portanto ela aplica em qualquer scan, comportamento conservador).
    pub fn boundary_level(b: &str) -> u8 {
        match b {
            "internal"  => 0,
            "federated" => 1,
            _           => 2, // "public" + qualquer desconhecido
        }
    }

    /// Policy aplica ao scan se o scan é pelo menos tão aberto quanto ela.
    ///   policy "public"    (2) → aplica em qualquer scan (0, 1, 2)
    ///   policy "federated" (1) → aplica em federated (1) e public (2)
    ///   policy "internal"  (0) → aplica APENAS em internal (0)
    pub fn applies_to_scan(&self, scan_boundary: &str) -> bool {
        let scan_level   = Self::boundary_level(scan_boundary);
        let policy_level = Self::boundary_level(&self.trust_boundary);
        scan_level <= policy_level
    }
}

impl Default for ThreatModel {
    fn default() -> Self {
        Self {
            trust_boundary: Self::default_trust_boundary(),
            assumed_attacker_capabilities: Vec::new(),
            scope_exclusions: Vec::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POLICY TYPES
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub version: String,
    pub metadata: PolicyMetadata,
    #[serde(default)]
    pub hard_blocks: Vec<String>,
    pub policies: Vec<Policy>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub name: String,
    #[allow(dead_code)]
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
    pub author: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    #[allow(dead_code)]
    pub description: String,
    pub enabled: bool,
    pub priority: u32,
    pub conditions: PolicyConditions,
    pub action: PolicyAction,
    // ADR-045: opcional, default fail-secure (public)
    #[serde(default)]
    pub threat_model: Option<ThreatModel>,
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
            PolicyAction::Allow   => 0,
            PolicyAction::Log     => 1,
            PolicyAction::Educate => 2,
            PolicyAction::Redact  => 3,
            PolicyAction::Block   => 4,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EVALUATION RESULT
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// POLICY ENGINE
// ─────────────────────────────────────────────────────────────────────────────

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

    /// Fail-secure: YAML inválido → engine que bloqueia tudo.
    pub fn from_yaml_str_failsecure(yaml: &str) -> Self {
        Self::from_yaml_str(yaml).unwrap_or_else(|e| {
            log::error!("Policy YAML invalid, fail-secure BLOCK ALL: {}", e);
            Self::block_all_engine()
        })
    }

    pub fn new(policy_set: PolicySet) -> Result<Self> {
        for p in &policy_set.policies {
            if !(0.0..=1.0).contains(&p.conditions.min_severity) {
                anyhow::bail!("Policy '{}': min_severity must be 0.0-1.0", p.id);
            }
            if !(0.0..=1.0).contains(&p.conditions.min_confidence) {
                anyhow::bail!("Policy '{}': min_confidence must be 0.0-1.0", p.id);
            }
        }

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

    /// Engine fail-secure: bloqueia tudo.
    /// BTV invariant: o YAML hardcoded é válido por construção.
    /// Regressão de parse → bug no código, não em input de usuário → panic rastreável.
    fn block_all_engine() -> Self {
        let yaml = r#"
version: "failsafe"
metadata:
  name: "FAILSAFE"
  description: "Emergency block-all policy"
  created_at: "1970-01-01"
  updated_at: "1970-01-01"
  author: "system"
policies:
  - id: "block-all"
    name: "Block All"
    description: "Emergency failsafe"
    enabled: true
    priority: 999
    conditions:
      min_severity: 0.0
      min_confidence: 0.0
    action: BLOCK
"#;
        Self::from_yaml_str(yaml).unwrap_or_else(|e| {
            panic!("BTV invariant violation: failsafe YAML is always valid — {e}")
        })
    }

    // ─── HARD BLOCKS ────────────────────────────────────────────────────────

    /// Returns Some(matched_term) se bloqueado.
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

    // ─── EVALUATE (per-finding, sem contexto) ────────────────────────────────
    // Wrapper retrocompatível: chama evaluate_with_context com "public".

    pub fn evaluate(
        &mut self,
        validator_name: &str,
        category: &str,
        severity: f32,
        confidence: f32,
    ) -> PolicyAction {
        self.evaluate_with_context(validator_name, category, severity, confidence, "public")
    }

    // ─── EVALUATE WITH CONTEXT (ADR-045) ─────────────────────────────────────

    /// Avalia com filtro de trust_boundary.
    ///
    /// INVARIANTE (ADR-045): Hard blocks absolutos são verificados apenas via
    /// evaluate_full() que recebe o input bruto. Este método não recebe input
    /// — hard blocks aqui seriam falsos positivos por ausência de contexto.
    ///
    /// `scan_trust_boundary`: perímetro em que o scan está sendo executado.
    ///   "public"    → recebe políticas public (mais restritivo)
    ///   "federated" → recebe políticas public + federated
    ///   "internal"  → recebe todas as políticas
    ///
    /// Hard blocks SEMPRE aplicam, independente de trust_boundary.
    pub fn evaluate_with_context(
        &mut self,
        validator_name: &str,
        _category: &str,
        severity: f32,
        confidence: f32,
        scan_trust_boundary: &str,
    ) -> PolicyAction {
        self.metrics.evaluations_total += 1;
        let mut max_action = PolicyAction::Allow;

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
        relevant.sort_by_key(|p| std::cmp::Reverse(p.priority));

        for policy in relevant {
            // ADR-045: filtrar policies fora do perímetro do scan
            let applies = policy.threat_model
                .as_ref()
                .map(|tm| tm.applies_to_scan(scan_trust_boundary))
                .unwrap_or(true); // sem threat_model → public → aplica sempre

            if !applies {
                continue;
            }

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

    // ─── EVALUATE FULL (input + findings) ────────────────────────────────────

    /// Full evaluation: hard blocks + per-finding policy evaluation.
    /// Usa "public" como trust_boundary (retrocompatível).
    pub fn evaluate_full(
        &mut self,
        input: &str,
        findings: &[&Finding],
    ) -> PolicyEvaluation {
        if let Some(term) = self.check_hard_blocks(input) {
            return PolicyEvaluation::hard_block(term);
        }

        if findings.is_empty() {
            return PolicyEvaluation::allow();
        }

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

    // ─── BIAS DECLARATION ─────────────────────────────────────────────────────

    pub fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.05, 0.03, 20260304, 0)
            .with_limitations(
                "Policy accuracy depends on YAML author. \
                 Hard blocks are exact-match only. \
                 ThreatModel trust_boundary filters reduce FP in internal contexts (ADR-045)."
            )
            .with_affected_groups(
                "Obfuscated inputs may bypass string-match hard blocks."
            )
    }

    // ─── ACCESSORS ────────────────────────────────────────────────────────────

    fn matches(
        &self,
        policy: &Policy,
        validator: &str,
        severity: f32,
        confidence: f32,
    ) -> bool {
        let cond = &policy.conditions;
        let v_match = cond.validators.is_empty()
            || cond.validators.iter().any(|v| v == validator);
        let sev_match  = severity   >= cond.min_severity;
        let conf_match = confidence >= cond.min_confidence;
        v_match && sev_match && conf_match
    }

    pub fn get_metrics(&self)    -> &PolicyMetrics { &self.metrics }
    pub fn get_policy_set(&self) -> &PolicySet     { &self.policy_set }
    pub fn hard_block_count(&self) -> usize        { self.hard_block_set.len() }
    pub fn policy_count(&self) -> usize            { self.policy_set.policies.len() }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    fn internal_policy_yaml() -> &'static str {
        r#"
version: "1.6"
metadata:
  name: "ThreatModelTest"
  description: "Threat model filter tests"
  created_at: "2026-03-04"
  updated_at: "2026-03-04"
  author: "Test"
policies:
  - id: "internal-only"
    name: "Internal Only"
    description: "Only for internal scans"
    enabled: true
    priority: 50
    conditions:
      validators: ["debug"]
      min_severity: 0.1
      min_confidence: 0.1
    action: BLOCK
    threat_model:
      trust_boundary: "internal"
      assumed_attacker_capabilities: []
      scope_exclusions: []
  - id: "public-always"
    name: "Public CPF"
    description: "CPF blocked in all contexts"
    enabled: true
    priority: 100
    conditions:
      validators: ["cpf"]
      min_severity: 0.7
      min_confidence: 0.9
    action: BLOCK
    threat_model:
      trust_boundary: "public"
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

    #[test]
    fn test_policy_without_threat_model_defaults_public() {
        let mut engine = PolicyEngine::from_yaml_str(test_yaml()).unwrap();
        let a1 = engine.evaluate("cpf", "", 0.8, 0.95);
        let a2 = engine.evaluate_with_context("cpf", "", 0.8, 0.95, "public");
        assert_eq!(a1, a2);
        assert_eq!(a1, PolicyAction::Block);
    }

    #[test]
    fn test_threat_model_internal_skipped_in_public_scan() {
        let mut engine = PolicyEngine::from_yaml_str(internal_policy_yaml()).unwrap();
        let action = engine.evaluate_with_context("debug", "", 0.5, 0.5, "public");
        assert_eq!(action, PolicyAction::Allow, "internal policy must not fire in public scan");
    }

    #[test]
    fn test_threat_model_internal_fires_in_internal_scan() {
        let mut engine = PolicyEngine::from_yaml_str(internal_policy_yaml()).unwrap();
        let action = engine.evaluate_with_context("debug", "", 0.5, 0.5, "internal");
        assert_eq!(action, PolicyAction::Block, "internal policy must fire in internal scan");
    }

    #[test]
    fn test_threat_model_public_applies_to_all_scans() {
        let mut engine = PolicyEngine::from_yaml_str(internal_policy_yaml()).unwrap();
        for boundary in &["public", "federated", "internal"] {
            let action = engine.evaluate_with_context("cpf", "", 0.8, 0.95, boundary);
            assert_eq!(action, PolicyAction::Block,
                       "public policy must fire in {} scan", boundary);
        }
    }

    #[test]
    fn test_evaluate_wrapper_backward_compat() {
        let mut engine = PolicyEngine::from_yaml_str(internal_policy_yaml()).unwrap();
        let a1 = engine.evaluate("cpf", "", 0.8, 0.95);
        let a2 = engine.evaluate_with_context("cpf", "", 0.8, 0.95, "public");
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_yaml_with_threat_model_parses() {
        let engine = PolicyEngine::from_yaml_str(internal_policy_yaml()).unwrap();
        assert_eq!(engine.policy_count(), 2);
        let internal = &engine.policy_set.policies[0];
        let tm = internal.threat_model.as_ref().unwrap();
        assert_eq!(tm.trust_boundary, "internal");
    }

    #[test]
    fn test_yaml_without_threat_model_parses() {
        let engine = PolicyEngine::from_yaml_str(test_yaml()).unwrap();
        for p in &engine.policy_set.policies {
            assert!(p.threat_model.is_none());
        }
    }

    #[test]
    fn test_boundary_level_unknown_is_public() {
        assert_eq!(ThreatModel::boundary_level("unknown"), 2);
        assert_eq!(ThreatModel::boundary_level(""), 2);
    }
}
