//! Session Sensitivity Accumulator (ADR-046)
//!
//! Previne ataques de decomposição ("Script Kiddie Uplift" - Paper 65).
//! Acumula pontuação de risco ao longo da sessão e dispara intervenção
//! se o limiar for excedido.

use std::collections::HashMap;
use std::time::Instant;
use serde::{Deserialize, Serialize};

/// Helper function for serde default
fn instant_now() -> Instant {
    Instant::now()
}

/// Configuração do acumulador.
#[derive(Debug, Clone, Deserialize)]
pub struct AccumulatorConfig {
    pub intervention_threshold: f32,
    pub temporal_decay_factor: f32,
    #[serde(default = "default_max_history")]
    pub max_history_size: usize,
}

fn default_max_history() -> usize { 100 }

impl Default for AccumulatorConfig {
    fn default() -> Self {
        Self {
            intervention_threshold: 75.0,
            temporal_decay_factor: 0.95,
            max_history_size: 100,
        }
    }
}

/// Estado acumulado de uma sessão.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccumulatedState {
    pub session_id: u128,
    pub current_score: f32,
    #[serde(skip, default = "instant_now")]
    pub last_update: Instant,
}

/// Resultado da avaliação do acumulador.
#[derive(Debug, Clone)]
pub struct AccumulatorVerdict {
    pub safe: bool,
    pub current_score: f32,
    pub threshold: f32,
    pub trigger_reason: Option<String>,
}

/// O Acumulador de Sensibilidade.
pub struct SensitivityAccumulator {
    config: AccumulatorConfig,
    sessions: HashMap<u128, AccumulatedState>,
}

impl SensitivityAccumulator {
    pub fn new(config: AccumulatorConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
        }
    }

    /// Adiciona um evento de risco à sessão.
    /// Retorna o veredito atual.
    pub fn add_event(
        &mut self,
        session_id: u128,
        category: &str,
        raw_score: f32
    ) -> AccumulatorVerdict {
        let now = Instant::now();

        // Obtém ou cria estado da sessão
        let state = self.sessions.entry(session_id).or_insert(AccumulatedState {
            session_id,
            current_score: 0.0,
            last_update: now,
        });

        // Calcula decaimento temporal desde última atualização
        let elapsed_secs = now.duration_since(state.last_update).as_secs();

        // CORREÇÃO: usar powf para float
        let decay_multiplier = self.config.temporal_decay_factor.powf(elapsed_secs as f32);

        // Aplica decaimento ao score atual
        state.current_score *= decay_multiplier;

        // Adiciona novo score
        state.current_score += raw_score;
        state.last_update = now;

        // Verifica limiar
        if state.current_score >= self.config.intervention_threshold {
            AccumulatorVerdict {
                safe: false,
                current_score: state.current_score,
                threshold: self.config.intervention_threshold,
                trigger_reason: Some(format!(
                    "Accumulated risk exceeded: {:.2} >= {:.2} (Category: {})",
                    state.current_score, self.config.intervention_threshold, category
                )),
            }
        } else {
            AccumulatorVerdict {
                safe: true,
                current_score: state.current_score,
                threshold: self.config.intervention_threshold,
                trigger_reason: None,
            }
        }
    }

    /// Reseta o acumulador para uma sessão (após intervenção).
    pub fn reset(&mut self, session_id: u128) {
        self.sessions.remove(&session_id);
    }

    /// Limpa sessões expiradas (housekeeping).
    pub fn cleanup(&mut self, max_age_secs: u64) {
        let now = Instant::now();
        self.sessions.retain(|_, state| {
            now.duration_since(state.last_update).as_secs() < max_age_secs
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulation_triggers_intervention() {
        let config = AccumulatorConfig {
            intervention_threshold: 50.0,
            temporal_decay_factor: 1.0, // Sem decaimento para teste
            max_history_size: 10,
        };
        let mut accumulator = SensitivityAccumulator::new(config);

        // Evento 1: 30 pontos (Safe)
        let v1 = accumulator.add_event(1, "pii", 30.0);
        assert!(v1.safe);
        assert_eq!(v1.current_score, 30.0);

        // Evento 2: +30 pontos (Total 60, Threshold 50 -> UNSAFE)
        let v2 = accumulator.add_event(1, "pii", 30.0);
        assert!(!v2.safe);
        assert!(v2.trigger_reason.is_some());
    }

    #[test]
    fn test_temporal_decay_reduces_risk() {
        let config = AccumulatorConfig {
            intervention_threshold: 100.0,
            temporal_decay_factor: 0.5, // Decai 50% por "segundo" (simulado)
            max_history_size: 10,
        };
        let _accumulator = SensitivityAccumulator::new(config);
    }
}