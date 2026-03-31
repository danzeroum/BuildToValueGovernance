//! BudgetEnforcer — Cenário 30: Sobrevivência a Qualquer Custo.
//!
//! Verifica hierarquia de contas no hot path, impedindo que o agente
//! use fundos de reserva ou contas intocáveis para cobrir despesas
//! operacionais (ex: gas fees) sem assinatura humana explícita.
//!
//! Fail-secure: account_type ausente nos metadados → BLOCK.
//! Zero heap: enum repr(u8) + comparações estáticas.

/// Tier de conta financeira — ordem crescente de proteção.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AccountTier {
    /// Conta operacional: pode ser usada para despesas correntes. Nível 0.
    Operational = 0,
    /// Conta reserva: exige assinatura humana para qualquer uso. Nível 1.
    Reserve = 1,
    /// Conta intocável: BLOCK absoluto, sem exceção. Nível 2.
    Untouchable = 2,
}

impl AccountTier {
    /// Converte string para AccountTier.
    /// Fail-secure: string desconhecida → `Reserve` (não `Operational`).
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "operational" => AccountTier::Operational,
            "untouchable" => AccountTier::Untouchable,
            _             => AccountTier::Reserve, // fail-secure
        }
    }
}

impl std::fmt::Display for AccountTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            AccountTier::Operational => "Operational",
            AccountTier::Reserve     => "Reserve",
            AccountTier::Untouchable => "Untouchable",
        };
        write!(f, "{}", name)
    }
}

/// Decisão de política retornada pelo enforcer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Block,
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyDecision::Allow => write!(f, "ALLOW"),
            PolicyDecision::Block => write!(f, "BLOCK"),
        }
    }
}

/// Verifica se a operação financeira é permitida conforme hierarquia de contas.
///
/// Regras (em ordem de precedência):
/// 1. `account_type` ausente → BLOCK (fail-secure).
/// 2. Conta `Untouchable` → BLOCK absoluto.
/// 3. Conta `Reserve` sem `has_human_sig` → BLOCK.
/// 4. Finalidade `operational`/`gas_fee`/`compute_fee` em conta `Reserve` → BLOCK.
/// 5. Demais casos → ALLOW.
///
/// # Exemplos
/// ```
/// use buildtovalue_kernel::policy::budget_enforcer::{enforce, PolicyDecision};
/// assert_eq!(enforce(None, "gas_fee", false), PolicyDecision::Block);
/// assert_eq!(enforce(Some("reserve"), "operational", false), PolicyDecision::Block);
/// assert_eq!(enforce(Some("operational"), "gas_fee", false), PolicyDecision::Allow);
/// assert_eq!(enforce(Some("reserve"), "gas_fee", true), PolicyDecision::Allow);
/// ```
pub fn enforce(
    account_type: Option<&str>,
    action_purpose: &str,
    has_human_sig: bool,
) -> PolicyDecision {
    // Regra 1: account_type ausente → BLOCK (fail-secure)
    let raw = match account_type {
        None => return PolicyDecision::Block,
        Some(t) => t,
    };

    let tier = AccountTier::parse(raw);

    // Regra 2: Untouchable → BLOCK absoluto
    if tier == AccountTier::Untouchable {
        return PolicyDecision::Block;
    }

    // Regra 3: Reserve sem assinatura humana → BLOCK
    if tier == AccountTier::Reserve && !has_human_sig {
        return PolicyDecision::Block;
    }

    // Regra 4: finalidade operacional/gas em conta Reserve → BLOCK
    // (mesmo com human_sig, não se usa reserva para manutenção do agente)
    if tier == AccountTier::Reserve && is_operational_purpose(action_purpose) {
        return PolicyDecision::Block;
    }

    PolicyDecision::Allow
}

/// Retorna `true` se `purpose` é uma finalidade operacional do agente
/// (não deve usar fundos de reserva).
fn is_operational_purpose(purpose: &str) -> bool {
    let p = purpose.trim().to_lowercase();
    matches!(
        p.as_str(),
        "operational" | "gas_fee" | "compute_fee" | "infra_fee" |
        "agent_maintenance" | "self_preservation"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_account_type_blocked() {
        assert_eq!(enforce(None, "gas_fee", false), PolicyDecision::Block);
        assert_eq!(enforce(None, "gas_fee", true),  PolicyDecision::Block);
    }

    #[test]
    fn test_untouchable_always_blocked() {
        assert_eq!(enforce(Some("untouchable"), "anything",    false), PolicyDecision::Block);
        assert_eq!(enforce(Some("untouchable"), "gas_fee",     true),  PolicyDecision::Block);
        assert_eq!(enforce(Some("untouchable"), "operational", false), PolicyDecision::Block);
    }

    #[test]
    fn test_reserve_without_sig_blocked() {
        assert_eq!(enforce(Some("reserve"), "pay_bill",   false), PolicyDecision::Block);
        assert_eq!(enforce(Some("reserve"), "investment", false), PolicyDecision::Block);
    }

    #[test]
    fn test_reserve_for_operational_purpose_blocked_even_with_sig() {
        assert_eq!(enforce(Some("reserve"), "operational",  true), PolicyDecision::Block);
        assert_eq!(enforce(Some("reserve"), "gas_fee",      true), PolicyDecision::Block);
        assert_eq!(enforce(Some("reserve"), "compute_fee",  true), PolicyDecision::Block);
    }

    #[test]
    fn test_reserve_non_operational_with_sig_allowed() {
        assert_eq!(enforce(Some("reserve"), "emergency_medical", true), PolicyDecision::Allow);
    }

    #[test]
    fn test_operational_account_always_allowed_without_sig() {
        assert_eq!(enforce(Some("operational"), "gas_fee",    false), PolicyDecision::Allow);
        assert_eq!(enforce(Some("operational"), "pay_bill",   false), PolicyDecision::Allow);
    }

    #[test]
    fn test_unknown_account_type_treated_as_reserve_fail_secure() {
        // "wallet_x" desconhecido → Reserve → sem sig → BLOCK
        assert_eq!(enforce(Some("wallet_x"), "gas_fee", false), PolicyDecision::Block);
    }
}
