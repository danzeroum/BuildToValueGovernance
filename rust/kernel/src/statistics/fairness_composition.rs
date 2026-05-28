//! Composição de Rawls + Jonas em uma decisão final (ADR-0087 §D4).
//!
//! Tabela de verdade:
//!
//! | Rawls violates | Jonas alert | Tentative action | Final action     | Hard block? |
//! |:---|:---|:---|:---|:---|
//! | false | Nominal / WarmUp / Disabled / ScoreUnavailable | Allow | Allow | no |
//! | false | Warning | Allow | Allow (com flag) | no |
//! | true (DIR < 0.80) | Nominal | Allow | Redact | no |
//! | false | Critical | Allow | Redact (E161) + human_review_required | no |
//! | true | Critical | Allow | **Block** (E160 + E161) | **yes** |
//! | true | Critical | Redact | Block | yes |
//! | * | * | Block | Block | (mantido) |
//!
//! A função `compose_fairness_action` é pura — sem I/O, sem alocação fora
//! do retorno. Pode ser chamada pelo Gatekeeper após Rawls e Jonas terem
//! produzido suas métricas.

use crate::core::types::Action;
use crate::statistics::jonas::DriftAlert;
use crate::statistics::rawls::FairnessMetrics;

/// Resultado da composição. Inclui a ação final, flags de telemetria e
/// uma marca booleana `hard_block` que distingue o BLOCK por composição
/// crítica (ADR-0087 §D4) de um BLOCK derivado da política de input
/// (que pode ser revisado de outras formas).
#[derive(Debug, Clone, PartialEq)]
pub struct FairnessDecision {
    pub action: Action,
    /// `true` se Rawls violou `DIR < threshold` (DriftMetrics.violates_threshold).
    pub rawls_violation: bool,
    /// `true` se Jonas reportou DriftAlert::Critical.
    pub jonas_critical: bool,
    /// `true` se Jonas reportou DriftAlert::Warning (não escala para Critical).
    pub jonas_warning: bool,
    /// `true` quando Rawls Critical AND Jonas Critical → Hard Block (ADR-0087 §D4).
    pub hard_block: bool,
    /// `true` quando a ação tentativa foi rebaixada (sinaliza ao caller
    /// que `tentative_action` foi substituída por algo mais restritivo).
    pub downgraded: bool,
    /// `true` quando Jonas reportou Critical — sinaliza que o laudo deve
    /// marcar `human_review_required` (D4).
    pub human_review_required: bool,
}

/// Compõe Rawls e Jonas em ação final.
///
/// `tentative_action`: ação que viria da policy engine antes desta composição.
/// `rawls`: métricas Rawls (pode estar em `insufficient_samples` — não viola).
/// `jonas`: alert Jonas (pode estar em `WarmUp`/`Disabled` — não escala).
pub fn compose_fairness_action(
    tentative_action: Action,
    rawls: &FairnessMetrics,
    jonas_alert: DriftAlert,
) -> FairnessDecision {
    // Se a política já decidiu Block, mantém — composição não atenua.
    if matches!(tentative_action, Action::Block) {
        return FairnessDecision {
            action: Action::Block,
            rawls_violation: rawls.violates_threshold,
            jonas_critical: matches!(jonas_alert, DriftAlert::Critical),
            jonas_warning: matches!(jonas_alert, DriftAlert::Warning),
            hard_block: false,
            downgraded: false,
            human_review_required: matches!(jonas_alert, DriftAlert::Critical),
        };
    }

    let rawls_violation = rawls.violates_threshold;
    let jonas_critical = matches!(jonas_alert, DriftAlert::Critical);
    let jonas_warning = matches!(jonas_alert, DriftAlert::Warning);

    // ADR-0087 §D4: hard block apenas quando AMBOS reportam Critical.
    if rawls_violation && jonas_critical {
        return FairnessDecision {
            action: Action::Block,
            rawls_violation,
            jonas_critical,
            jonas_warning,
            hard_block: true,
            downgraded: true,
            human_review_required: true,
        };
    }

    // Rawls Critical isolado: rebaixa Allow → Redact (D5 do ADR-0086).
    // Jonas Critical isolado: rebaixa Allow → Redact + human_review_required.
    let final_action = match (rawls_violation, jonas_critical, tentative_action) {
        (true, _, Action::Allow) => Action::Redact,
        (_, true, Action::Allow) => Action::Redact,
        // Allow + apenas warning: mantém Allow.
        // Redact + qualquer coisa não-critical-critical: mantém Redact.
        (_, _, action) => action,
    };

    let downgraded = !matches!(
        (tentative_action, final_action),
        (Action::Allow, Action::Allow)
            | (Action::Redact, Action::Redact)
            | (Action::Log, Action::Log)
    );

    FairnessDecision {
        action: final_action,
        rawls_violation,
        jonas_critical,
        jonas_warning,
        hard_block: false,
        downgraded,
        human_review_required: jonas_critical,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn rawls_ok() -> FairnessMetrics {
        FairnessMetrics {
            dir: 1.0,
            privileged_favorable_rate: 0.9,
            unprivileged_favorable_rate: 0.9,
            insufficient_samples: false,
            violates_threshold: false,
            threshold_used: 0.80,
        }
    }

    fn rawls_violates() -> FairnessMetrics {
        FairnessMetrics {
            dir: 0.55,
            privileged_favorable_rate: 0.9,
            unprivileged_favorable_rate: 0.5,
            insufficient_samples: false,
            violates_threshold: true,
            threshold_used: 0.80,
        }
    }

    #[test]
    fn no_violations_allow_passes() {
        let d = compose_fairness_action(Action::Allow, &rawls_ok(), DriftAlert::Nominal);
        assert_eq!(d.action, Action::Allow);
        assert!(!d.downgraded);
        assert!(!d.hard_block);
        assert!(!d.human_review_required);
    }

    #[test]
    fn rawls_critical_only_downgrades_allow_to_redact() {
        let d = compose_fairness_action(Action::Allow, &rawls_violates(), DriftAlert::Nominal);
        assert_eq!(d.action, Action::Redact);
        assert!(d.rawls_violation);
        assert!(!d.jonas_critical);
        assert!(d.downgraded);
        assert!(!d.hard_block);
    }

    #[test]
    fn jonas_critical_only_downgrades_allow_to_redact_with_human_review() {
        let d = compose_fairness_action(Action::Allow, &rawls_ok(), DriftAlert::Critical);
        assert_eq!(d.action, Action::Redact);
        assert!(d.jonas_critical);
        assert!(!d.rawls_violation);
        assert!(d.downgraded);
        assert!(!d.hard_block);
        assert!(d.human_review_required);
    }

    #[test]
    fn jonas_warning_keeps_allow_with_flag() {
        let d = compose_fairness_action(Action::Allow, &rawls_ok(), DriftAlert::Warning);
        assert_eq!(d.action, Action::Allow);
        assert!(d.jonas_warning);
        assert!(!d.downgraded);
        assert!(!d.human_review_required);
    }

    #[test]
    fn rawls_critical_and_jonas_critical_yields_hard_block() {
        let d = compose_fairness_action(Action::Allow, &rawls_violates(), DriftAlert::Critical);
        assert_eq!(d.action, Action::Block);
        assert!(d.rawls_violation);
        assert!(d.jonas_critical);
        assert!(d.hard_block);
        assert!(d.downgraded);
        assert!(d.human_review_required);
    }

    #[test]
    fn rawls_critical_and_jonas_critical_blocks_even_from_redact_tentative() {
        let d = compose_fairness_action(Action::Redact, &rawls_violates(), DriftAlert::Critical);
        assert_eq!(d.action, Action::Block);
        assert!(d.hard_block);
        assert!(d.downgraded);
    }

    #[test]
    fn policy_block_is_preserved() {
        let d = compose_fairness_action(Action::Block, &rawls_violates(), DriftAlert::Critical);
        assert_eq!(d.action, Action::Block);
        // BLOCK pela política não é Hard Block por composição — distinção
        // importante para o laudo.
        assert!(!d.hard_block);
        assert!(!d.downgraded);
    }

    #[test]
    fn jonas_warmup_does_not_escalate() {
        let d = compose_fairness_action(Action::Allow, &rawls_ok(), DriftAlert::WarmUp);
        assert_eq!(d.action, Action::Allow);
        assert!(!d.jonas_critical);
        assert!(!d.jonas_warning);
    }

    #[test]
    fn jonas_disabled_does_not_escalate() {
        let d = compose_fairness_action(Action::Allow, &rawls_ok(), DriftAlert::Disabled);
        assert_eq!(d.action, Action::Allow);
        assert!(!d.downgraded);
    }

    #[test]
    fn rawls_insufficient_samples_does_not_violate() {
        let metrics = FairnessMetrics {
            dir: f64::NAN,
            privileged_favorable_rate: f64::NAN,
            unprivileged_favorable_rate: f64::NAN,
            insufficient_samples: true,
            violates_threshold: false,
            threshold_used: 0.80,
        };
        let d = compose_fairness_action(Action::Allow, &metrics, DriftAlert::Critical);
        // Jonas crítico ainda escala, mas Rawls não compõe Hard Block sem
        // violação confirmada.
        assert_eq!(d.action, Action::Redact);
        assert!(!d.hard_block);
    }

    #[test]
    fn log_action_is_preserved_under_warning() {
        let d = compose_fairness_action(Action::Log, &rawls_ok(), DriftAlert::Warning);
        assert_eq!(d.action, Action::Log);
        assert!(!d.downgraded);
    }

    #[test]
    fn rawls_violates_jonas_warning_yields_redact() {
        // Documenta a regra: violação Rawls combinada com Warning Jonas
        // não escala para BLOCK — apenas Critical em ambos faz Hard Block.
        // Análogo (no modelo binário do Rawls) ao caso "warning + critical"
        // sugerido em revisões anteriores.
        let d = compose_fairness_action(Action::Allow, &rawls_violates(), DriftAlert::Warning);
        assert_eq!(d.action, Action::Redact);
        assert!(d.rawls_violation);
        assert!(d.jonas_warning);
        assert!(!d.jonas_critical);
        assert!(!d.hard_block, "Warning + Rawls não compõe Hard Block");
        assert!(d.downgraded);
        assert!(!d.human_review_required, "Warning sozinho não exige revisão humana");
    }

    #[test]
    fn redact_tentative_passes_through_when_only_jonas_critical() {
        // Redact + Jonas Critical sem Rawls Violation: mantém Redact, sinaliza human_review.
        let d = compose_fairness_action(Action::Redact, &rawls_ok(), DriftAlert::Critical);
        assert_eq!(d.action, Action::Redact);
        assert!(!d.hard_block);
        assert!(d.human_review_required);
        assert!(!d.downgraded);
    }
}
