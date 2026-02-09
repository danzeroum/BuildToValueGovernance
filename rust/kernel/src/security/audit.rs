use std::collections::HashMap;
use std::net::IpAddr;

pub struct ProbingDetector {
    request_history: HashMap<IpAddr, Vec<(Instant, Duration)>>,
}

impl ProbingDetector {
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
        
        let history = &self.request_history[&ip];
        
        if history.len() < 100 {
            return false;  // Insuficiente para análise
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
        
        if variance < 5.0 {  // Variância muito baixa
            log::warn!("Probing detected: Suspicious timing pattern from {}", ip);
            return true;
        }
        
        // 3. Scanning pattern (inputs incrementais)
        // TODO: Detectar CPFs sequenciais (123.456.789-00, 123.456.789-01, ...)
        
        false
    }
    
    fn calculate_variance(&self, values: &[f64]) -> f64 {
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        variance
    }
}