#[cfg(test)]
mod tests {
    use buildtovalue_kernel::Gatekeeper;
    use buildtovalue_kernel::core::types::ValidatorModule;

    #[test]
    fn test_all_modules_implement_module_trait() {
        // Já garantido em tempo de compilação pela construção do Gatekeeper.
        // Se algum módulo não implementar Module, não compila.
    }

    #[test]
    fn test_bias_aggregation_includes_all_modules() {
        let mut gk = Gatekeeper::new();
        let ev = gk.scan_for_evidence("test input", 0x1234);
        // O bias agregado deve ter valores > 0 (pois todos os módulos declaram bias)
        assert!(ev.bias.false_positive_rate > 0.0);
        assert!(ev.bias.false_negative_rate > 0.0);
        assert!(ev.bias.test_dataset_size >= 500);
    }

    #[test]
    fn test_scan_context_stats_properly_filled() {
        let mut gk = Gatekeeper::new();
        let ev = gk.scan_for_evidence("Hello world, this is a test with varied chars!", 0x1234);
        // O módulo de entropia deve ter preenchido stats.entropy
        assert!(ev.stats.entropy > 0.0);
    }
}