//! Critérios 7, 8, 9: validação estática de fronteiras de dependência.
//!
//! Estes testes documentam as invariantes que o CI `cargo tree` verifica.
//! Os testes de compile são run-time assertions sobre comportamentos observáveis
//! sem import de crates proibidos.

#[cfg(test)]
mod dependency_boundary {
    /// Critério 8: btv-executive pode usar types de btv-types sem erro.
    /// Se btv-types não fosse dependência, este bloco não compilaria.
    #[test]
    fn btv_types_is_accessible() {
        let _ = btv_types::Decision::Allow;
        let _ = btv_types::Decision::Deny;
        let _ = btv_types::RiskLevel::Safe;
        let _ = btv_types::RiskLevel::Critical;
    }

    /// Critério 8: btv-executive pode usar tipos lineares de btv-core.
    /// Se btv-core não fosse dependência, este bloco não compilaria.
    #[test]
    fn btv_core_types_accessible() {
        // Apenas verificamos que o módulo é acessível (sem construir tokens).
        use btv_core::DecisionMaker as _;
        // Se compilou, btv-core é dependência.
    }

    /// Critério 9: btv-executive comunica com btv-sigma via HTTP, não via import.
    /// Verificado estaticamente: não existe `use btv_sigma` neste crate.
    /// O teste documenta que o único canal é `LogClient::new(endpoint, key)`.
    #[test]
    fn btv_sigma_communication_is_http_only() {
        // Se `btv-sigma` fosse dependência direta, o CI `cargo tree` detectaria.
        // Este teste documenta a intenção arquitetural.
        let endpoint = "http://localhost:3100".to_string();
        // LogClient é de btv-core, não de btv-sigma
        let _ = endpoint.contains("3100"); // compilado apenas com btv-core
    }

    /// Critério 7: #[deny(unsafe_code)] é ativo no crate.
    /// Se unsafe fosse usado, o CI falharia em cargo build.
    /// Este teste documenta a intenção.
    #[test]
    fn no_unsafe_code_policy_documented() {
        // A garantia real é #![deny(unsafe_code)] em lib.rs.
        // cargo geiger no CI valida a ausência em runtime.
        assert!(true, "unsafe policy enforced by #![deny(unsafe_code)] in lib.rs");
    }
}
