#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::json;

    // Helper: simula POST /v1/guard
    // (requer test harness com axum::test ou reqwest)

    #[test]
    fn test_guard_clean_text_passes_through() {
        let input = "A clínica funciona das 8h às 18h.";
        // Expect: text unchanged, modified=false, pii_masked=0
        let sanitizer = buildtovalue_kernel::output_guard::OutputSanitizer::new();
        let result = sanitizer.sanitize(input);
        assert_eq!(result.masks_applied, 0);
        assert!(result.rescan_clean);
    }

    #[test]
    fn test_guard_masks_cpf_in_llm_response() {
        let input = "Seu CPF é 123.456.789-09, conforme cadastro.";
        let sanitizer = buildtovalue_kernel::output_guard::OutputSanitizer::new();
        let result = sanitizer.sanitize(input);
        assert!(result.masks_applied >= 1);
        assert!(!result.output.contains("123.456.789-09"));
        assert!(result.output.contains("***.***"));
        assert!(result.rescan_clean);
    }

    #[test]
    fn test_guard_masks_email_in_llm_response() {
        let input = "Enviamos para joao@empresa.com o recibo.";
        let sanitizer = buildtovalue_kernel::output_guard::OutputSanitizer::new();
        let result = sanitizer.sanitize(input);
        assert!(result.masks_applied >= 1);
        assert!(!result.output.contains("joao@empresa.com"));
        assert!(result.rescan_clean);
    }

    #[test]
    fn test_guard_masks_credit_card() {
        let input = "Cartão: 4532 0151 1283 0366 aprovado.";
        let sanitizer = buildtovalue_kernel::output_guard::OutputSanitizer::new();
        let result = sanitizer.sanitize(input);
        assert!(result.masks_applied >= 1);
        assert!(result.output.contains("****"));
        assert!(result.rescan_clean);
    }

    #[test]
    fn test_guard_strips_xss() {
        let input = "Resultado: <script>alert('xss')</script> processado.";
        let guard = buildtovalue_kernel::security::output_guard::OutputGuard::new();
        let analysis = guard.analyze_content(input);
        assert!(analysis.has_dangerous_patterns);
        assert!(analysis.dangerous_patterns_found.contains(&"SCRIPT_TAG".to_string()));
    }

    #[test]
    fn test_guard_multiple_pii_types() {
        let input = "CPF: 123.456.789-09, email: test@test.com, cartão: 4532 0151 1283 0366";
        let sanitizer = buildtovalue_kernel::output_guard::OutputSanitizer::new();
        let result = sanitizer.sanitize(input);
        assert!(result.masks_applied >= 3);
        assert!(result.rescan_clean);
    }

    #[test]
    fn test_guard_rescan_confirms_clean() {
        let input = "CPF 111.222.333-44 e CPF 555.666.777-88";
        let sanitizer = buildtovalue_kernel::output_guard::OutputSanitizer::new();
        let result = sanitizer.sanitize(input);
        assert_eq!(result.masks_applied, 2);
        assert!(result.rescan_clean, "Re-scan must confirm no PII remains");
    }
}