
use std::time::Instant;

/// Orquestrador que coordena todos os módulos de validação
pub struct Gatekeeper {
    // Validators
    cpf_validator: CpfValidator,
    cnpj_validator: CnpjValidator,
    email_validator: EmailValidator,
    card_validator: CreditCardValidator,
    phone_validator: PhoneValidator,
    
    // Statistics
    entropy_calculator: EntropyCalculator,
    zscore_calculator: ZScoreCalculator,
    char_ratio_analyzer: CharRatioAnalyzer,
    
    // Deobfuscator
    base64_detector: Base64Detector,
    hex_decoder: HexDecoder,
    leet_detector: LeetspeakDetector,
}

impl Gatekeeper {
    pub fn new() -> Self {
        Self {
            cpf_validator: CpfValidator::new(),
            cnpj_validator: CnpjValidator::new(),
            email_validator: EmailValidator::new(),
            card_validator: CreditCardValidator::new(),
            phone_validator: PhoneValidator::new(),
            entropy_calculator: EntropyCalculator::new(),
            zscore_calculator: ZScoreCalculator::new(),
            char_ratio_analyzer: CharRatioAnalyzer::new(),
            base64_detector: Base64Detector::new(),
            hex_decoder: HexDecoder::new(),
            leet_detector: LeetspeakDetector::new(),
        }
    }
    
    /// Escaneia input e gera TechnicalEvidence completo
    /// 
    /// Garantia: < 30ms (p99)
    pub fn scan_for_evidence(&self, input: &str, audit_trail_id: u128) 
        -> TechnicalEvidence 
    {
        let start = Instant::now();
        let mut evidence = TechnicalEvidence::new(audit_trail_id);
        
        // Hash do input original
        let mut hasher = blake3::Hasher::new();
        hasher.update(input.as_bytes());
        evidence.original_request_hash = u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        );
        evidence.input_size = input.len() as u32;
        
        // === VALIDATORS (tempo: 0-10ms) ===
        evidence.executed_modules |= 1 << 0;  // Marca validator
        
        for finding in self.cpf_validator.validate(input) {
            evidence.add_finding(finding);
        }
        
        for finding in self.cnpj_validator.validate(input) {
            evidence.add_finding(finding);
        }
        
        for finding in self.email_validator.validate(input) {
            evidence.add_finding(finding);
        }
        
        for finding in self.card_validator.validate(input) {
            evidence.add_finding(finding);
        }
        
        for finding in self.phone_validator.validate(input) {
            evidence.add_finding(finding);
        }
        
        // === STATISTICS (tempo: 10-20ms) ===
        evidence.executed_modules |= 1 << 1;  // Marca statistics
        
        for finding in self.entropy_calculator.validate(input, &mut evidence.stats) {
            evidence.add_finding(finding);
        }
        
        for finding in self.zscore_calculator.validate(input, &mut evidence.stats) {
            evidence.add_finding(finding);
        }
        
        self.char_ratio_analyzer.analyze(input, &mut evidence.stats);
        for finding in self.char_ratio_analyzer.validate(&evidence.stats) {
            evidence.add_finding(finding);
        }
        
        // === DEOBFUSCATOR (tempo: 20-28ms) ===
        evidence.executed_modules |= 1 << 2;  // Marca deobfuscator
        
        for finding in self.base64_detector.detect(input) {
            evidence.add_finding(finding);
        }
        
        for finding in self.hex_decoder.detect(input) {
            evidence.add_finding(finding);
        }
        
        for finding in self.leet_detector.detect(input) {
            evidence.add_finding(finding);
        }
        
        // === FINALIZE (tempo: 28-30ms) ===
        evidence.processing_time_us = start.elapsed().as_micros() as u64;
        evidence.finalize().expect("Failed to finalize evidence");
        
        log::debug!("Evidence generated in {:?}", start.elapsed());
        
        evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_clean_input_no_findings() {
        let gatekeeper = Gatekeeper::new();
        let evidence = gatekeeper.scan_for_evidence(
            "Esta é uma frase completamente limpa.",
            0x1234
        );
        
        assert_eq!(evidence.finding_count, 0);
        assert_eq!(evidence.critical_count, 0);
        assert_eq!(evidence.composite_risk, 0);
    }
    
    #[test]
    fn test_cpf_detection() {
        let gatekeeper = Gatekeeper::new();
        let evidence = gatekeeper.scan_for_evidence(
            "Meu CPF é 123.456.789-09",
            0x1234
        );
        
        assert!(evidence.finding_count > 0);
        assert_eq!(evidence.critical_count, 1);  // CPF é critical
        assert!(evidence.composite_risk > 180);
    }
    
    #[test]
    fn test_multiple_violations() {
        let gatekeeper = Gatekeeper::new();
        let evidence = gatekeeper.scan_for_evidence(
            "CPF: 123.456.789-09, Cartão: 4532015112830366",
            0x1234
        );
        
        // CPF + Cartão = 2 critical findings
        assert_eq!(evidence.critical_count, 2);
        assert_eq!(evidence.composite_risk, 255);  // Máximo
    }
    
    #[test]
    fn test_performance_under_30ms() {
        let gatekeeper = Gatekeeper::new();
        
        let start = Instant::now();
        let _ = gatekeeper.scan_for_evidence(
            "Input normal sem violações, mas com tamanho razoável para testar performance.",
            0x1234
        );
        let elapsed = start.elapsed();
        
        assert!(elapsed.as_millis() < 30, 
                "Gatekeeper demorou {:?} (target: <30ms)", elapsed);
    }
}