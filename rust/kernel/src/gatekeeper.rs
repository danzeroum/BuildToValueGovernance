
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

//! Gatekeeper v2.1 - Core scanning engine
//!
//! Orquestra todos os validators e produz TechnicalEvidence v2.1.
//!
//! Gate: Week 2 - Day 7

use crate::types::{TechnicalEvidence, Finding, Statistics, RiskLevel};
use crate::validators::{ValidatorRegistry, ValidationResult};
use std::sync::Arc;
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════════════════
// GATEKEEPER
// ═══════════════════════════════════════════════════════════════════════════

/// Gatekeeper - Core scanning engine
///
/// Responsabilidades:
/// - Orquestrar validators
/// - Coletar findings
/// - Produzir TechnicalEvidence v2.1
/// - Garantir latência <30ms (p99)
pub struct Gatekeeper {
    /// Registry de validators
    validators: Arc<ValidatorRegistry>,

    /// Métricas
    pub metrics: GatekeeperMetrics,
}

#[derive(Debug, Default)]
pub struct GatekeeperMetrics {
    pub scans_total: u64,
    pub findings_total: u64,
    pub critical_findings: u64,
    pub avg_latency_ms: f32,
    pub p99_latency_ms: f32,
}

impl Gatekeeper {
    /// Cria novo Gatekeeper
    pub fn new() -> Self {
        Self {
            validators: Arc::new(ValidatorRegistry::new()),
            metrics: GatekeeperMetrics::default(),
        }
    }

    /// Escaneia input e produz TechnicalEvidence
    ///
    /// # Performance
    /// - Target: <30ms (p99)
    /// - Zero heap allocations no hot path
    /// - Stack-only TechnicalEvidence
    ///
    /// # Arguments
    /// * `input` - Texto a escanear
    ///
    /// # Returns
    /// TechnicalEvidence v2.1 (9.4KB)
    pub fn scan_for_evidence(&mut self, input: &str) -> TechnicalEvidence {
        let start = Instant::now();

        // Cria evidence (stack-allocated, 9.4KB)
        let mut evidence = TechnicalEvidence::new();

        // 1. Calcula statistics
        evidence.stats = Statistics::from_text(input);

        // 2. Executa validators
        let results = self.validators.validate_all(input);

        // 3. Processa findings
        for result in results {
            if let Some(finding) = self.result_to_finding(result) {
                evidence.add_finding(finding);
                self.metrics.findings_total += 1;

                if finding.severity >= 0.8 {
                    self.metrics.critical_findings += 1;
                }
            }
        }

        // 4. Finaliza evidence
        evidence.recalculate_risk();
        evidence.calculate_hash();

        // 5. Atualiza métricas
        let latency_ms = start.elapsed().as_micros() as f32 / 1000.0;
        self.update_metrics(latency_ms);
        self.metrics.scans_total += 1;

        evidence
    }

    /// Converte ValidationResult para Finding
    fn result_to_finding(&self, result: ValidationResult) -> Option<Finding> {
        if !result.is_violation {
            return None;
        }

        Some(Finding::new(
            &result.validator_name,
            &result.message,
            &result.category,
            &result.location,
            &result.evidence,
            result.severity,
            result.confidence,
        ))
    }

    /// Atualiza métricas de latência
    fn update_metrics(&mut self, latency_ms: f32) {
        // Exponential moving average
        let alpha = 0.1;
        self.metrics.avg_latency_ms =
            alpha * latency_ms + (1.0 - alpha) * self.metrics.avg_latency_ms;

        // P99 approximation (simple)
        if latency_ms > self.metrics.p99_latency_ms {
            self.metrics.p99_latency_ms = latency_ms;
        }
    }

    /// Retorna métricas
    pub fn get_metrics(&self) -> &GatekeeperMetrics {
        &self.metrics
    }
}

impl Default for Gatekeeper {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gatekeeper_scan() {
        let mut gatekeeper = Gatekeeper::new();

        let input = "Test input with CPF: 123.456.789-00";
        let evidence = gatekeeper.scan_for_evidence(input);

        // Verifica estrutura
        assert_eq!(evidence.version, TechnicalEvidence::VERSION);
        assert!(evidence.timestamp > 0);

        // Verifica statistics
        assert_eq!(evidence.stats.input_size, input.len() as u32);
        assert!(evidence.stats.entropy > 0.0);

        // Verifica hash
        assert!(evidence.validate_hash());
    }

    #[test]
    fn test_evidence_size() {
        let evidence = TechnicalEvidence::new();

        // Garante 9.4KB exato
        assert_eq!(
            std::mem::size_of_val(&evidence),
            TechnicalEvidence::SIZE
        );
    }

    #[test]
    fn test_ring_buffer_overflow() {
        let mut evidence = TechnicalEvidence::new();

        // Adiciona 15 findings (mais que MAX_FINDINGS = 10)
        for i in 0..15 {
            let finding = Finding::new(
                &format!("Finding {}", i),
                "Test description",
                "test",
                "location",
                "evidence",
                0.5,
                0.8,
            );
            evidence.add_finding(finding);
        }

        // Deve ter exatamente 10 findings (ring buffer)
        assert_eq!(evidence.finding_count, 10);

        // Ring index deve estar em 5 (15 % 10)
        assert_eq!(evidence.ring_index, 5);
    }

    #[test]
    fn test_critical_preservation() {
        let mut evidence = TechnicalEvidence::new();

        // Adiciona findings críticos
        for i in 0..5 {
            let finding = Finding::new(
                &format!("Critical {}", i),
                "Critical issue",
                "security",
                "location",
                "evidence",
                0.9, // Crítico (>= 0.8)
                0.95,
            );
            evidence.add_finding(finding);
        }

        // Deve ter exatamente 3 críticos (MAX_CRITICAL_FINDINGS)
        assert_eq!(evidence.critical_count, 3);

        // Todos devem estar no array critical
        for i in 0..3 {
            assert!(!evidence.critical[i].is_empty());
            assert!(evidence.critical[i].severity >= 0.8);
        }
    }

    #[test]
    fn test_risk_calculation() {
        let mut evidence = TechnicalEvidence::new();

        // Adiciona findings de severidades variadas
        evidence.add_finding(Finding::new(
            "Low risk",
            "desc",
            "cat",
            "loc",
            "ev",
            0.3,
            0.8,
        ));

        evidence.add_finding(Finding::new(
            "High risk",
            "desc",
            "cat",
            "loc",
            "ev",
            0.9,
            0.9,
        ));

        // Composite risk deve estar entre 0.3 e 0.9
        assert!(evidence.composite_risk > 0.3);
        assert!(evidence.composite_risk < 0.9);

        // Risk level deve ser calculado
        assert!(matches!(
            evidence.risk_level,
            RiskLevel::Medium | RiskLevel::High
        ));
    }

    #[test]
    fn test_hash_integrity() {
        let mut evidence = TechnicalEvidence::new();

        evidence.add_finding(Finding::new(
            "Test",
            "desc",
            "cat",
            "loc",
            "ev",
            0.5,
            0.8,
        ));

        evidence.calculate_hash();

        // Hash deve validar
        assert!(evidence.validate_hash());

        // Modifica evidence
        evidence.composite_risk = 0.99;

        // Hash não deve mais validar
        assert!(!evidence.validate_hash());
    }

    #[test]
    fn test_performance_target() {
        let mut gatekeeper = Gatekeeper::new();

        let input = "Performance test input with various patterns: \
                     email@test.com, https://example.com, 192.168.1.1";

        // Executa 100 scans
        for _ in 0..100 {
            let _evidence = gatekeeper.scan_for_evidence(input);
        }

        let metrics = gatekeeper.get_metrics();

        // Target: <30ms (p99)
        println!("Avg latency: {:.2}ms", metrics.avg_latency_ms);
        println!("P99 latency: {:.2}ms", metrics.p99_latency_ms);

        // Verifica SLA (permissivo para CI)
        assert!(
            metrics.p99_latency_ms < 100.0,
            "P99 latency {}ms exceeds 100ms threshold",
            metrics.p99_latency_ms
        );
    }
}
