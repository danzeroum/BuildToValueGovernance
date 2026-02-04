
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::evidence::Finding;
    
    // ═══════════════════════════════════════════════════════════════
    // Valid CPF Detection
    // ═══════════════════════════════════════════════════════════════
    
    #[test]
    fn test_valid_cpf_formatted() {
        let validator = CpfValidator::new();
        let mut findings = Vec::new();
        
        validator.validate("My CPF is 123.456.789-09", &mut findings);
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].r#type, FindingType::CpfDetected);
        assert_eq!(findings[0].value, "123.456.789-09");
        assert!(findings[0].confidence > 0.9);
    }
    
    #[test]
    fn test_valid_cpf_unformatted() {
        let validator = CpfValidator::new();
        let mut findings = Vec::new();
        
        validator.validate("CPF: 12345678909", &mut findings);
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].value, "12345678909");
    }
    
    #[test]
    fn test_multiple_cpfs() {
        let validator = CpfValidator::new();
        let mut findings = Vec::new();
        
        validator.validate(
            "CPF 1: 123.456.789-09 and CPF 2: 987.654.321-00",
            &mut findings
        );
        
        assert_eq!(findings.len(), 2);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Invalid CPF (Checksum)
    // ═══════════════════════════════════════════════════════════════
    
    #[test]
    fn test_invalid_checksum() {
        let validator = CpfValidator::new();
        let mut findings = Vec::new();
        
        // Invalid checksum (last digit wrong)
        validator.validate("123.456.789-00", &mut findings);
        
        // Should NOT be detected (checksum validation)
        assert_eq!(findings.len(), 0);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Edge Cases
    // ═══════════════════════════════════════════════════════════════
    
    #[test]
    fn test_all_same_digits() {
        let validator = CpfValidator::new();
        let mut findings = Vec::new();
        
        // Invalid: all same digits
        validator.validate("111.111.111-11", &mut findings);
        
        assert_eq!(findings.len(), 0); // Rejected by validator
    }
    
    #[test]
    fn test_cpf_in_url() {
        let validator = CpfValidator::new();
        let mut findings = Vec::new();
        
        validator.validate(
            "https://example.com/user/12345678909",
            &mut findings
        );
        
        // Should detect (might be user ID that happens to be CPF)
        assert_eq!(findings.len(), 1);
        assert!(findings[0].confidence < 0.8); // Lower confidence
    }
    
    #[test]
    fn test_cpf_obfuscated() {
        let validator = CpfValidator::new();
        let mut findings = Vec::new();
        
        // Zero-width spaces
        validator.validate("123\u{200B}.456\u{200B}.789\u{200B}-09", &mut findings);
        
        // Should detect after normalization
        assert_eq!(findings.len(), 1);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Performance Tests
    // ═══════════════════════════════════════════════════════════════
    
    #[test]
    fn test_large_input_performance() {
        use std::time::Instant;
        
        let validator = CpfValidator::new();
        let mut findings = Vec::new();
        
        // 10KB text with 10 CPFs
        let input = (0..10).map(|i| {
            format!("User {}: 123.456.789-{:02}", i, i)
        }).collect::<Vec<_>>().join(" ");
        
        let start = Instant::now();
        validator.validate(&input, &mut findings);
        let elapsed = start.elapsed();
        
        assert_eq!(findings.len(), 10);
        assert!(elapsed.as_millis() < 10); // <10ms for 10KB
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Property-Based Tests (proptest)
    // ═══════════════════════════════════════════════════════════════
    
    #[cfg(feature = "proptest")]
    use proptest::prelude::*;
    
    #[cfg(feature = "proptest")]
    proptest! {
        #[test]
        fn test_no_crash_on_random_input(s in "\\PC*") {
            let validator = CpfValidator::new();
            let mut findings = Vec::new();
            
            // Should never panic, regardless of input
            validator.validate(&s, &mut findings);
        }
        
        #[test]
        fn test_deterministic(s in "\\PC{1,1000}") {
            let validator = CpfValidator::new();
            
            let mut findings1 = Vec::new();
            validator.validate(&s, &mut findings1);
            
            let mut findings2 = Vec::new();
            validator.validate(&s, &mut findings2);
            
            // Same input → same output
            assert_eq!(findings1.len(), findings2.len());
        }
    }
}