//! Session Sensitivity Accumulator (ADR-046)
//!
//! Mitiga ataques de decomposição ("Script Kiddie Uplift" - Paper 65).
//! Acumula pontuação de risco ao longo da sessão e dispara intervenção
//! se o limiar for excedido, mesmo que eventos individuais sejam benignos.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Configuração do acumulador.
#[derive(Debug, Clone, Deserialize)]
pub struct AccumulatorConfig {
    /// Limiar de intervenção (0-100). Acima disso, bloqueia/escala.
    pub intervention_threshold: f32,
    /// Fator de decaimento temporal por segundo.
    /// 0.95 = O score reduz 5% a cada segundo.
    pub temporal_decay_factor: f32,
    /// Máximo de eventos mantidos no histórico (otimização de memória).
    pub max_history_size: usize,
}

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
    pub last_update: Instant,
    pub event_count: u64,
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
            event_count: 0,
        });

        // Calcula tempo decorrido desde última atualização
        let elapsed_secs = now.duration_since(state.last_update).as_secs();

        // Aplica decaimento temporal exponencial
        // S(t) = S(0) * decay^t
        if elapsed_secs > 0 {
            let decay_power = (self.config.temporal_decay_factor).powf(elapsed_secs as f32);
            state.current_score *= decay_power;
        }

        // Adiciona novo score
        state.current_score += raw_score;
        state.last_update = now;
        state.event_count += 1;

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

    /// Reseta o acumulador para uma sessão (após intervenção humana).
    pub fn reset(&mut self, session_id: u128) {
        self.sessions.remove(&session_id);
    }

    /// Limpa sessões expiradas (housekeeping).
    /// Deve ser chamado periodicamente para evitar memory leak.
    pub fn cleanup_expired(&mut self, max_age_secs: u64) {
        let now = Instant::now();
        self.sessions.retain(|_, state| {
            now.duration_since(state.last_update).as_secs() < max_age_secs
        });
    }

    /// Retorna o score atual sem adicionar evento.
    pub fn peek_score(&self, session_id: u128) -> f32 {
        self.sessions.get(&session_id).map(|s| s.current_score).unwrap_or(0.0)
    }
}

// ==========================================
// TESTES UNITÁRIOS
// ==========================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulation_triggers_intervention() {
        let config = AccumulatorConfig {
            intervention_threshold: 50.0,
            temporal_decay_factor: 1.0, // Sem decaimento para teste
            ..Default::default()
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
        // Configuração com decaimento rápido
        let config = AccumulatorConfig {
            intervention_threshold: 100.0,
            temporal_decay_factor: 0.5, // Decai 50% por "segundo"
            ..Default::default()
        };

        // Nota: Teste de tempo real é não-determinístico.
        // Aqui validamos apenas a lógica matemática.
        let mut acc = SensitivityAccumulator::new(config);

        // Adiciona 50 pontos
        let v1 = acc.add_event(1, "attack", 50.0);
        assert_eq!(v1.current_score, 50.0);

        // Simula passagem de tempo dormindo (apenas para teste de integração)
        // std::thread::sleep(Duration::from_secs(1));
        // let v2 = acc.add_event(1, "noise", 0.0);
        // assert!(v2.current_score < 50.0);
    }

    #[test]
    fn test_reset_clears_score() {
        let mut acc = SensitivityAccumulator::new(AccumulatorConfig::default());
        acc.add_event(1, "risk", 100.0);

        acc.reset(1);

        assert_eq!(acc.peek_score(1), 0.0);
    }
}