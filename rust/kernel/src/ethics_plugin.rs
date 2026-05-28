//! Ethics Plugin System — BuildToValue Governance
//!
//! Implementa o padrão Observer + Factory para motores éticos plugáveis.
//! Ref: API_ETHICS_GUIDE.md §5, ADR-Weber-Ress-PluginArch
//!
//! Invariantes:
//! - Plugins observam TechnicalEvidence (somente-leitura)
//! - Qualquer Err de plugin → BLOCK (fail-secure)
//! - plugin_id + version() logados em todo BLOCK para post-mortem
//! - EthicsPluginRegistry é imutável em runtime (carregado no boot)
//! - Funções ≤ 50 linhas
//!
//! Estratégia de injeção (ver ADR-052 §Plugin Runtime):
//! Fase atual: Hardcoded no boot (opção A) — máxima performance
//! Fase 7:     Wasm Runtime sandboxed (opção C) — ver ADR-053 (pendente)

use serde::Serialize;

/// Evidência técnica imutável — 9596 bytes fixos.
/// Definida em rust/kernel/src/evidence.rs; importada aqui por referência.
/// O plugin NUNCA recebe ownership — somente &TechnicalEvidence.
pub use crate::evidence::TechnicalEvidence;

/// Declaração de viés — obrigatória em todo plugin (Transparency Radical).
#[derive(Debug, Serialize, Clone)]
pub struct BiasDeclaration {
    pub plugin_id: &'static str,
    pub plugin_version: &'static str,
    pub decision: &'static str, // "ALLOW" | "BLOCK"
    pub ethical_framework: &'static str, // "rawls" | "jonas" | "gilligan" | custom
    pub explanation: String,
}

/// Resultado de uma validação ética.
#[derive(Debug)]
pub enum EthicsDecision {
    Allow,
    Block {
        reason: &'static str,
        /// Referência ao ADR que fundamenta o bloqueio.
        adr_ref: &'static str,
    },
}

/// Erro de execução de plugin — causa fail-secure BLOCK automático.
#[derive(Debug)]
pub struct EthicsPluginError {
    /// ID do plugin que falhou — capturado para post-mortem de incidente.
    pub plugin_id: &'static str,
    /// Versão do plugin que falhou — para correlação com deploy.
    pub plugin_version: &'static str,
    pub message: &'static str,
}

/// Contrato público de plugin ético.
///
/// Padrão Observer: plugin recebe &TechnicalEvidence (somente-leitura).
/// Padrão Factory: instanciado via EthicsPluginRegistry::new().
///
/// Implementadores DEVEM:
/// - Nunca fazer panic() — retornar Err em qualquer falha
/// - Implementar explain() com BiasDeclaration completa
/// - Garantir que plugin_id() e version() sejam &'static str (sem heap)
pub trait EthicsValidator: Send + Sync {
    /// Valida a evidência. NUNCA panic.
    /// Invariante: Err → fail-secure BLOCK no registry.
    fn validate(
        &self,
        evidence: &TechnicalEvidence,
    ) -> Result<EthicsDecision, EthicsPluginError>;

    /// Obrigatório — Transparency Radical.
    /// Chamado ANTES de validate() para garantir declaração mesmo em Err.
    fn explain(&self) -> BiasDeclaration;

    /// Identificador único estável (ex: "rawls-v1", "jonas-v2").
    /// Usado em logs de post-mortem e no catálogo de ADRs.
    fn plugin_id(&self) -> &'static str;

    /// Versão semântica do plugin (ex: "1.0.0", "2.1.3").
    /// Capturada em todo BLOCK para correlação com deploy.
    fn version(&self) -> &'static str;
}

/// Resultado completo da execução do registry.
#[derive(Debug)]
pub struct RegistryResult {
    pub decision: EthicsDecision,
    /// BiasDeclarations de todos os plugins executados (incluindo o que bloqueou).
    pub declarations: Vec<BiasDeclaration>,
    /// Presente quando um plugin lançou erro (fail-secure).
    pub plugin_error: Option<EthicsPluginError>,
}

/// Registry de plugins éticos — carregado no boot, imutável em runtime.
///
/// Estratégia: "primeiro BLOCK vence" com log completo de contexto.
/// Em produção, validators são injetados via main() ou teste via new().
pub struct EthicsPluginRegistry {
    validators: Vec<Box<dyn EthicsValidator>>,
}

impl EthicsPluginRegistry {
    /// Construtor — validators injetados no boot (Dependency Injection).
    /// Fase atual: hardcoded em main(). Fase 7: Wasm loader.
    pub fn new(validators: Vec<Box<dyn EthicsValidator>>) -> Self {
        assert!(!validators.is_empty(), "Registry sem validators: fail-secure exige ao menos um");
        Self { validators }
    }

    /// Executa todos os plugins na ordem de registro.
    /// Qualquer Err → BLOCK imediato (fail-secure).
    /// Todos os explain() são coletados para o ledger, independente do resultado.
    ///
    /// Post-mortem: plugin_id + version() de todo BLOCK são capturados em RegistryResult.
    pub fn run_all(&self, evidence: &TechnicalEvidence) -> RegistryResult {
        let mut declarations = Vec::with_capacity(self.validators.len());

        for validator in &self.validators {
            // explain() antes de validate() — garante declaração mesmo em pânico improvável
            declarations.push(validator.explain());

            match validator.validate(evidence) {
                Ok(EthicsDecision::Block { reason, adr_ref }) => {
                    // Primeiro BLOCK vence — log captura plugin_id + version para post-mortem
                    return RegistryResult {
                        decision: EthicsDecision::Block { reason, adr_ref },
                        declarations,
                        plugin_error: None,
                    };
                }
                Err(plugin_err) => {
                    // Erro de plugin → fail-secure BLOCK
                    // plugin_id e plugin_version disponíveis para o caller logar
                    return RegistryResult {
                        decision: EthicsDecision::Block {
                            reason: "ethics_plugin_execution_failed",
                            adr_ref: "https://docs.buildtovalue.org/adrs/fail-secure-kernel",
                        },
                        declarations,
                        plugin_error: Some(plugin_err),
                    };
                }
                Ok(EthicsDecision::Allow) => continue,
            }
        }

        RegistryResult {
            decision: EthicsDecision::Allow,
            declarations,
            plugin_error: None,
        }
    }

    /// Quantidade de validators registrados.
    pub fn len(&self) -> usize {
        self.validators.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysAllowPlugin;
    impl EthicsValidator for AlwaysAllowPlugin {
        fn validate(&self, _: &TechnicalEvidence) -> Result<EthicsDecision, EthicsPluginError> {
            Ok(EthicsDecision::Allow)
        }
        fn explain(&self) -> BiasDeclaration {
            BiasDeclaration {
                plugin_id: "always-allow-test",
                plugin_version: "0.1.0",
                decision: "ALLOW",
                ethical_framework: "test",
                explanation: "Plugin de teste — sempre permite".to_string(),
            }
        }
        fn plugin_id(&self) -> &'static str { "always-allow-test" }
        fn version(&self) -> &'static str { "0.1.0" }
    }

    struct AlwaysBlockPlugin;
    impl EthicsValidator for AlwaysBlockPlugin {
        fn validate(&self, _: &TechnicalEvidence) -> Result<EthicsDecision, EthicsPluginError> {
            Ok(EthicsDecision::Block {
                reason: "test_block",
                adr_ref: "https://docs.buildtovalue.org/adrs/test",
            })
        }
        fn explain(&self) -> BiasDeclaration {
            BiasDeclaration {
                plugin_id: "always-block-test",
                plugin_version: "0.1.0",
                decision: "BLOCK",
                ethical_framework: "test",
                explanation: "Plugin de teste — sempre bloqueia".to_string(),
            }
        }
        fn plugin_id(&self) -> &'static str { "always-block-test" }
        fn version(&self) -> &'static str { "0.1.0" }
    }

    struct ErrorPlugin;
    impl EthicsValidator for ErrorPlugin {
        fn validate(&self, _: &TechnicalEvidence) -> Result<EthicsDecision, EthicsPluginError> {
            Err(EthicsPluginError {
                plugin_id: "error-plugin-test",
                plugin_version: "0.1.0",
                message: "falha simulada",
            })
        }
        fn explain(&self) -> BiasDeclaration {
            BiasDeclaration {
                plugin_id: "error-plugin-test",
                plugin_version: "0.1.0",
                decision: "BLOCK",
                ethical_framework: "test",
                explanation: "Plugin que simula falha de execução".to_string(),
            }
        }
        fn plugin_id(&self) -> &'static str { "error-plugin-test" }
        fn version(&self) -> &'static str { "0.1.0" }
    }

    #[test]
    fn all_allow_returns_allow() {
        let registry = EthicsPluginRegistry::new(vec![
            Box::new(AlwaysAllowPlugin),
            Box::new(AlwaysAllowPlugin),
        ]);
        // TechnicalEvidence::default() para teste
        let evidence = TechnicalEvidence::default();
        let result = registry.run_all(&evidence);
        assert!(matches!(result.decision, EthicsDecision::Allow));
        assert_eq!(result.declarations.len(), 2);
        assert!(result.plugin_error.is_none());
    }

    #[test]
    fn block_plugin_stops_execution() {
        let registry = EthicsPluginRegistry::new(vec![
            Box::new(AlwaysAllowPlugin),
            Box::new(AlwaysBlockPlugin),
            Box::new(AlwaysAllowPlugin), // não deve ser executado
        ]);
        let evidence = TechnicalEvidence::default();
        let result = registry.run_all(&evidence);
        assert!(matches!(result.decision, EthicsDecision::Block { .. }));
        // Apenas 2 declarations: Allow + Block (terceiro plugin não executado)
        assert_eq!(result.declarations.len(), 2);
    }

    #[test]
    fn plugin_error_triggers_fail_secure() {
        let registry = EthicsPluginRegistry::new(vec![
            Box::new(AlwaysAllowPlugin),
            Box::new(ErrorPlugin),
        ]);
        let evidence = TechnicalEvidence::default();
        let result = registry.run_all(&evidence);
        // Erro de plugin → BLOCK (fail-secure)
        assert!(matches!(result.decision, EthicsDecision::Block { .. }));
        // plugin_error capturado para post-mortem
        assert!(result.plugin_error.is_some());
        let err = result.plugin_error.unwrap();
        assert_eq!(err.plugin_id, "error-plugin-test");
        assert_eq!(err.plugin_version, "0.1.0");
    }
}
