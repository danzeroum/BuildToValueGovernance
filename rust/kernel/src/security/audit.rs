//! Security Audit - Probing Detector
//!
//! Detecta padrões de ataques de timing analysis e probing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Instant, Duration};

/// Detector de ataques de probing por análise de timing
pub struct ProbingDetector {
    request_history: HashMap<IpAddr, Vec<(Instant, Duration)>>,
}

impl ProbingDetector {
    /// Cria um novo detector
    pub fn new() -> Self {
        Self {
            request_history: HashMap::new(),
        }
    }

    /// Detecta padrões de timing analysis
    pub fn detect_probing(&mut self, ip: IpAddr, response_time: Duration) -> bool {
        let now = Instant::now();

        // Registra request
        self.request_history
            .entry(ip)
            .or_insert_with(Vec::new)
            .push((now, response_time));

        // Limpa histórico antigo (últimas 24h)
        self.cleanup_old_entries(ip);

        let history = match self.request_history.get(&ip) {
            Some(h) => h,
            None => return false,
        };

        if history.len() < 100 {
            return false;  // Insuficiente para análise estatística
        }

        // Detecta padrões suspeitos:

        // 1. Alta frequência (> 10 req/s)
        let recent_count = history.iter()
            .filter(|(time, _)| now.duration_since(*time).as_secs() < 1)
            .count();

        if recent_count > 10 {
            log::warn!("Probing detected: High frequency from {}", ip);
            return true;
        }

        // 2. Timing analysis (variância baixa = suspeito)
        let timings: Vec<f64> = history.iter()
            .map(|(_, dur)| dur.as_micros() as f64)
            .collect();

        let variance = self.calculate_variance(&timings);
        if variance < 100.0 { // 100 microssegundos² de variância mínima
            log::warn!("Probing detected: Low variance ({}) from {}", variance, ip);
            return true;
        }

        false
    }

    /// Remove entradas mais antigas que 24 horas
    fn cleanup_old_entries(&mut self, ip: IpAddr) {
        let now = Instant::now();
        if let Some(entries) = self.request_history.get_mut(&ip) {
            entries.retain(|(time, _)| now.duration_since(*time).as_secs() < 24 * 3600);
        }
    }

    /// Calcula a variância de uma amostra
    fn calculate_variance(&self, values: &[f64]) -> f64 {
        if values.len() < 2 {
            return 0.0;
        }

        let mean: f64 = values.iter().sum::<f64>() / values.len() as f64;
        let variance: f64 = values.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / (values.len() - 1) as f64;

        variance
    }
}

impl Default for ProbingDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_probing_detection() {
        let mut detector = ProbingDetector::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Teste com poucas requisições (não deve detectar)
        for _ in 0..50 {
            assert!(!detector.detect_probing(ip, Duration::from_millis(100)));
        }

        // Teste com alta frequência (deve detectar)
        for _ in 0..20 {
            assert!(detector.detect_probing(ip, Duration::from_millis(10)));
        }
    }

    #[test]
    fn test_variance_calculation() {
        let detector = ProbingDetector::new();
        let values = vec![100.0, 200.0, 300.0, 400.0, 500.0];
        let variance = detector.calculate_variance(&values);

        assert!(variance > 0.0);
        assert_eq!(variance, 25000.0); // (200^2 + 100^2 + 0^2 + 100^2 + 200^2) / 4
    }
}