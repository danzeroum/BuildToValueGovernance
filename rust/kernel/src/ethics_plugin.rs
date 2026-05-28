//! Trait pública e registry para motores éticos plugáveis.
//!
//! O `EthicsValidator` é o principal ponto de extensão do BTV: futuros
//! motores Rawls (DIR), Jonas (PSI), Levinas (alteridade) e Gilligan
//! (cuidado/SLA) implementam este trait. Mantemos o trait **síncrono**
//! deliberadamente — `async-trait` alocaria `Box<dyn Future>` a cada
//! chamada de `validate()`, violando o invariante de zero heap no hot
//! path e o SLA de `<30ms p99`. A fronteira assíncrona é reservada para
//! o ABI Wasm (ADR-053).
//!
//! Filosofia de execução do `EthicsPluginRegistry`: **short-circuit
//! fail-secure**. A primeira decisão `Block` ou qualquer `Err` interrompe
//! a cadeia. A explicabilidade exigida por LGPD Art. 20 é atendida pelas
//! `BiasDeclaration` coletadas via `explain()` em todos os plugins
//! **antes** de qualquer `validate()`, mais o campo `skipped_plugins`.
//! Ver ADR-0082 §5.

use crate::evidence::TechnicalEvidence;
use crate::core::types::BiasDeclaration;

/// Erro retornado por um plugin quando não consegue completar a validação.
/// `&'static str` para evitar alocação no hot path.
#[derive(Debug, Clone)]
pub struct EthicsPluginError {
    pub plugin_id: &'static str,
    pub message: &'static str,
}

impl std::fmt::Display for EthicsPluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "plugin '{}' failed: {}", self.plugin_id, self.message)
    }
}

impl std::error::Error for EthicsPluginError {}

/// Decisão de um plugin individual.
#[derive(Debug, Clone)]
pub enum EthicsDecision {
    Allow,
    Block {
        reason: &'static str,
        adr_ref: &'static str,
    },
}

/// Contrato público de plugin ético. Síncrono por design (ver header).
pub trait EthicsValidator: Send + Sync {
    /// Valida a evidência. NUNCA panic — retorna `Err` em falha.
    /// Invariante: falha de plugin → BLOCK (fail-secure no Registry).
    fn validate(
        &self,
        evidence: &TechnicalEvidence,
    ) -> Result<EthicsDecision, EthicsPluginError>;

    /// Obrigatório — Transparência Radical (ADR-0010).
    /// Chamado **antes** de `validate()` pelo Registry, sempre coletado
    /// no resultado mesmo se o plugin não chegar a executar.
    fn explain(&self) -> BiasDeclaration;

    /// Identificador único do plugin (ex: "rawls-v2", "jonas-v1").
    fn plugin_id(&self) -> &'static str;

    /// Versão semântica do plugin — usado para deprecation (ADR-0082).
    fn version(&self) -> &'static str;
}

/// Resultado agregado da execução do Registry.
///
/// Ver ADR-0082 §5: o short-circuit é intencional. `declarations` contém
/// **todas** as `BiasDeclaration` (incluindo dos plugins não executados,
/// pois `explain()` é chamado primeiro). `skipped_plugins` lista IDs
/// dos plugins cujo `validate()` não chegou a rodar.
pub struct RegistryResult {
    pub decision: EthicsDecision,
    pub declarations: Vec<BiasDeclaration>,
    pub plugin_error: Option<EthicsPluginError>,
    pub skipped_plugins: Vec<&'static str>,
}

impl std::fmt::Display for RegistryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let verdict = match &self.decision {
            EthicsDecision::Allow => "ALLOW".to_string(),
            EthicsDecision::Block { reason, adr_ref } => {
                format!("BLOCK reason={reason} adr={adr_ref}")
            }
        };
        write!(
            f,
            "RegistryResult({verdict}, declarations={}, skipped={:?}, error={:?})",
            self.declarations.len(),
            self.skipped_plugins,
            self.plugin_error.as_ref().map(|e| e.plugin_id),
        )
    }
}

/// Registry de plugins éticos. Carregado no boot, imutável em runtime.
pub struct EthicsPluginRegistry {
    validators: Vec<Box<dyn EthicsValidator>>,
}

impl EthicsPluginRegistry {
    pub fn new(validators: Vec<Box<dyn EthicsValidator>>) -> Self {
        Self { validators }
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Executa a cadeia de plugins com **short-circuit fail-secure**.
    ///
    /// 1. Coleta `explain()` de todos os plugins primeiro.
    /// 2. Itera `validate()`; primeiro `Block` ou `Err` interrompe.
    /// 3. Plugins não executados ficam em `skipped_plugins` para
    ///    auditoria (ADR-0082 §5).
    pub fn run_all(&self, evidence: &TechnicalEvidence) -> RegistryResult {
        // Fase 1 — coleta de declarações ANTES de qualquer validate().
        // Isso garante explicabilidade LGPD Art. 20 mesmo se houver
        // short-circuit posterior.
        let declarations: Vec<BiasDeclaration> =
            self.validators.iter().map(|v| v.explain()).collect();

        // Fase 2 — execução com short-circuit.
        for (idx, validator) in self.validators.iter().enumerate() {
            match validator.validate(evidence) {
                Ok(EthicsDecision::Allow) => continue,
                Ok(EthicsDecision::Block { reason, adr_ref }) => {
                    let skipped = self
                        .validators
                        .iter()
                        .skip(idx + 1)
                        .map(|v| v.plugin_id())
                        .collect();
                    return RegistryResult {
                        decision: EthicsDecision::Block { reason, adr_ref },
                        declarations,
                        plugin_error: None,
                        skipped_plugins: skipped,
                    };
                }
                Err(e) => {
                    // Invariante kernel: erro de plugin ⇒ BLOCK.
                    let skipped = self
                        .validators
                        .iter()
                        .skip(idx + 1)
                        .map(|v| v.plugin_id())
                        .collect();
                    return RegistryResult {
                        decision: EthicsDecision::Block {
                            reason: "plugin_execution_failed",
                            adr_ref: "early-guard-fail-secure",
                        },
                        declarations,
                        plugin_error: Some(e),
                        skipped_plugins: skipped,
                    };
                }
            }
        }

        // Todos os plugins retornaram Allow.
        RegistryResult {
            decision: EthicsDecision::Allow,
            declarations,
            plugin_error: None,
            skipped_plugins: Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::core::types::BiasDeclaration;
    use crate::evidence::TechnicalEvidence;

    /// Construtor explícito para testes — evita `TechnicalEvidence::default()`
    /// que não existe e mascaria invariantes do tipo (ver ADR-0063).
    fn mock_evidence() -> TechnicalEvidence {
        TechnicalEvidence::new(0)
    }

    struct AllowingPlugin {
        id: &'static str,
    }

    impl EthicsValidator for AllowingPlugin {
        fn validate(&self, _: &TechnicalEvidence) -> Result<EthicsDecision, EthicsPluginError> {
            Ok(EthicsDecision::Allow)
        }
        fn explain(&self) -> BiasDeclaration {
            BiasDeclaration::default()
        }
        fn plugin_id(&self) -> &'static str {
            self.id
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
    }

    struct BlockingPlugin;

    impl EthicsValidator for BlockingPlugin {
        fn validate(&self, _: &TechnicalEvidence) -> Result<EthicsDecision, EthicsPluginError> {
            Ok(EthicsDecision::Block {
                reason: "test_block",
                adr_ref: "test-adr",
            })
        }
        fn explain(&self) -> BiasDeclaration {
            BiasDeclaration::default()
        }
        fn plugin_id(&self) -> &'static str {
            "blocking"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
    }

    struct ErroringPlugin;

    impl EthicsValidator for ErroringPlugin {
        fn validate(&self, _: &TechnicalEvidence) -> Result<EthicsDecision, EthicsPluginError> {
            Err(EthicsPluginError {
                plugin_id: "erroring",
                message: "synthetic failure",
            })
        }
        fn explain(&self) -> BiasDeclaration {
            BiasDeclaration::default()
        }
        fn plugin_id(&self) -> &'static str {
            "erroring"
        }
        fn version(&self) -> &'static str {
            "1.0.0"
        }
    }

    #[test]
    fn all_allow_returns_allow_with_no_skipped() {
        let registry = EthicsPluginRegistry::new(vec![
            Box::new(AllowingPlugin { id: "a" }),
            Box::new(AllowingPlugin { id: "b" }),
        ]);
        let result = registry.run_all(&mock_evidence());
        assert!(matches!(result.decision, EthicsDecision::Allow));
        assert_eq!(result.declarations.len(), 2);
        assert!(result.skipped_plugins.is_empty());
        assert!(result.plugin_error.is_none());
    }

    #[test]
    fn first_block_short_circuits_and_lists_remaining_as_skipped() {
        let registry = EthicsPluginRegistry::new(vec![
            Box::new(AllowingPlugin { id: "a" }),
            Box::new(BlockingPlugin),
            Box::new(AllowingPlugin { id: "c" }),
            Box::new(AllowingPlugin { id: "d" }),
        ]);
        let result = registry.run_all(&mock_evidence());

        match result.decision {
            EthicsDecision::Block { reason, .. } => assert_eq!(reason, "test_block"),
            _ => panic!("expected Block"),
        }
        // explain() chamado em todos — explicabilidade preservada.
        assert_eq!(result.declarations.len(), 4);
        // validate() pulado nos dois últimos.
        assert_eq!(result.skipped_plugins, vec!["c", "d"]);
        assert!(result.plugin_error.is_none());
    }

    #[test]
    fn plugin_error_becomes_fail_secure_block() {
        let registry = EthicsPluginRegistry::new(vec![
            Box::new(AllowingPlugin { id: "a" }),
            Box::new(ErroringPlugin),
            Box::new(AllowingPlugin { id: "c" }),
        ]);
        let result = registry.run_all(&mock_evidence());

        match result.decision {
            EthicsDecision::Block { reason, adr_ref } => {
                assert_eq!(reason, "plugin_execution_failed");
                assert_eq!(adr_ref, "early-guard-fail-secure");
            }
            _ => panic!("expected fail-secure Block"),
        }
        assert_eq!(result.skipped_plugins, vec!["c"]);
        let err = result.plugin_error.expect("error registrado");
        assert_eq!(err.plugin_id, "erroring");
    }

    #[test]
    fn empty_registry_returns_allow() {
        let registry = EthicsPluginRegistry::new(vec![]);
        let result = registry.run_all(&mock_evidence());
        assert!(matches!(result.decision, EthicsDecision::Allow));
        assert!(result.declarations.is_empty());
    }

    #[test]
    fn display_includes_decision_and_skipped() {
        let registry = EthicsPluginRegistry::new(vec![
            Box::new(BlockingPlugin),
            Box::new(AllowingPlugin { id: "after" }),
        ]);
        let result = registry.run_all(&mock_evidence());
        let s = format!("{result}");
        assert!(s.contains("BLOCK"));
        assert!(s.contains("test_block"));
        assert!(s.contains("after"));
    }
}
