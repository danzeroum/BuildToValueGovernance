//! Security Audit - Probing Detector v2.3.1
//!
//! Detecta padrões de ataques de timing analysis e probing.
//! Implementa detecção estatística de variância para identificar
//! tentativas de ataque por análise de tempo (side-channel).
//!
//! Princípio: Ataques de probing normalmente apresentam
//! baixa variância no tempo de resposta (tentativa de mapeamento sistemático).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Instant, Duration};

/// Detector de ataques de probing por análise de timing
#[derive(Debug)]
pub struct ProbingDetector {
    request_history: HashMap<IpAddr, Vec<(Instant, Duration)>>,
    window_seconds: u64, // Janela temporal para análise (padrão: 3600 = 1 hora)
}

impl ProbingDetector {
    /// Cria um novo detector com janela temporal padrão (1 hora)
    pub fn new() -> Self {
        Self {
            request_history: HashMap::new(),
            window_seconds: 3600,
        }
    }

    /// Cria detector com janela personalizada
    pub fn with_window(mut self, seconds: u64) -> Self {
        self.window_seconds = seconds;
        self
    }

    /// Detecta padrões de timing analysis
    pub fn detect_probing(&mut self, ip: IpAddr, response_time: Duration) -> bool {
        let now = Instant::now();

        // Registra request
        self.request_history
            .entry(ip)
            .or_insert_with(Vec::new)
            .push((now, response_time));

        // Limpa histórico antigo (fora da janela)
        self.cleanup_old_entries(ip);

        let history = match self.request_history.get(&ip) {
            Some(h) => h,
            None => return false,
        };

        // Necessário volume mínimo para análise estatística
        if history.len() < 50 {
            return false;
        }

        // 1. Detecção por alta frequência (> 20 req/s)
        let recent_count = history.iter()
            .filter(|(time, _)| now.duration_since(*time).as_secs() < 1)
            .count();

        if recent_count > 20 {
            log::warn!("Probing detected: High frequency ({} req/s) from {}", recent_count, ip);
            return true;
        }

        // 2. Detecção por baixa variância (timing analysis)
        let timings: Vec<f64> = history.iter()
            .map(|(_, dur)| dur.as_micros() as f64)
            .collect();

        let variance = self.calculate_variance(&timings);

        // Variância abaixo de 100 µs² é suspeita para ataques de timing
        if variance < 100.0 && history.len() > 100 {
            log::warn!("Probing detected: Low variance ({:.2} µs²) from {}", variance, ip);
            return true;
        }

        // 3. Detecção por padrão regular (request a cada X ms)
        if self.detect_regular_pattern(&timings) {
            log::warn!("Probing detected: Regular pattern from {}", ip);
            return true;
        }

        false
    }

    /// Limpa entradas antigas (fora da janela temporal)
    fn cleanup_old_entries(&mut self, ip: IpAddr) {
        let now = Instant::now();
        if let Some(history) = self.request_history.get_mut(&ip) {
            history.retain(|(time, _)| now.duration_since(*time).as_secs() < self.window_seconds);
        }
    }

    /// Calcula variância de uma série temporal
    fn calculate_variance(&self, values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }

        let mean: f64 = values.iter().sum::<f64>() / values.len() as f64;
        let variance: f64 = values.iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>() / (values.len() - 1) as f64;

        variance
    }

    /// Detecta padrões regulares (requests a intervalos fixos)
    fn detect_regular_pattern(&self, timings: &[f64]) -> bool {
        if timings.len() < 10 {
            return false;
        }

        // Calcula diferenças entre requests consecutivos
        let diffs: Vec<f64> = timings.windows(2)
            .map(|window| window[1] - window[0])
            .collect();

        // Calcula variância das diferenças
        let diff_variance = self.calculate_variance(&diffs);

        // Baixa variância nas diferenças indica padrão regular
        diff_variance < 50.0
    }

    /// Retorna estatísticas para um IP específico
    pub fn get_stats(&self, ip: &IpAddr) -> Option<ProbingStats> {
        self.request_history.get(ip).map(|history| {
            let timings: Vec<f64> = history.iter()
                .map(|(_, dur)| dur.as_micros() as f64)
                .collect();

            let count = history.len();
            let variance = self.calculate_variance(&timings);
            let mean = if count > 0 {
                timings.iter().sum::<f64>() / count as f64
            } else { 0.0 };

            ProbingStats {
                request_count: count,
                mean_response_us: mean,
                variance_us2: variance,
                last_detected: history.last().map(|(time, _)| *time),
            }
        })
    }
}

impl Default for ProbingDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Estatísticas de probing para um IP
#[derive(Debug, Clone)]
pub struct ProbingStats {
    pub request_count: usize,
    pub mean_response_us: f64,
    pub variance_us2: f64,
    pub last_detected: Option<Instant>,
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_probing_detection_high_frequency() {
        let mut detector = ProbingDetector::new().with_window(1);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let mut detected = false;
        for _ in 0..100 {
            if detector.detect_probing(ip, Duration::from_millis(10)) {
                detected = true;
                break;
            }
        }
        assert!(detected, "Probing should have been detected within 100 requests");
    }
    #[test]
    fn test_variance_calculation() {
        let detector = ProbingDetector::new();

        // Dados com variância conhecida
        let data = vec![100.0, 102.0, 98.0, 101.0, 99.0];
        let variance = detector.calculate_variance(&data);

        // Variância aproximada calculada manualmente
        assert!(variance > 2.0 && variance < 3.0);
    }

    #[test]
    fn test_regular_pattern_detection() {
        let detector = ProbingDetector::new();

        // Dados com padrão regular (100ms entre cada)
        let regular_data: Vec<f64> = (0..20)
            .map(|i| (i as f64) * 100_000.0) // 100ms em microssegundos
            .collect();

        assert!(detector.detect_regular_pattern(&regular_data));

        // Dados aleatórios não devem ser detectados
        let random_data = vec![
            100_000.0, 150_000.0, 80_000.0, 200_000.0, 120_000.0,
            90_000.0, 180_000.0, 110_000.0, 160_000.0, 95_000.0,
        ];

        assert!(!detector.detect_regular_pattern(&random_data));
    }

    #[test]
    fn test_stats_retrieval() {
        let mut detector = ProbingDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Adiciona alguns dados
        detector.detect_probing(ip, Duration::from_millis(100));
        detector.detect_probing(ip, Duration::from_millis(150));

        let stats = detector.get_stats(&ip).unwrap();
        assert_eq!(stats.request_count, 2);
        assert!(stats.mean_response_us > 0.0);
    }
}