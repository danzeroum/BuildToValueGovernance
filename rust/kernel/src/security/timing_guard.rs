
use rand::Rng;
use std::time::{Duration, Instant};

pub struct TimingGuard {
    start: Instant,
    target_duration_us: u64,
    jitter_percent: f32,
}

impl TimingGuard {
    pub fn new(target_duration_us: u64, jitter_percent: f32) -> Self {
        Self {
            start: Instant::now(),
            target_duration_us,
            jitter_percent,
        }
    }
    
    /// Adiciona jitter aleatório (dificulta timing analysis)
    pub fn add_jitter(&self) -> Duration {
        let mut rng = rand::thread_rng();
        
        // Jitter aleatório: ±jitter_percent do target
        let jitter_range = (self.target_duration_us as f32 * self.jitter_percent) as u64;
        let jitter_us = rng.gen_range(0..jitter_range);
        
        // 50% chance de ser positivo ou negativo
        let jitter_signed = if rng.gen_bool(0.5) {
            jitter_us
        } else {
            jitter_us.wrapping_neg()
        };
        
        Duration::from_micros(jitter_signed)
    }
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        
        // Calcula tempo restante (com jitter)
        let jitter = self.add_jitter();
        let target = Duration::from_micros(self.target_duration_us) + jitter;
        
        if elapsed < target {
            let padding = target - elapsed;
            std::thread::sleep(padding);
        }
        // Se elapsed > target, não faz nada (já demorou mais que esperado)
    }
}