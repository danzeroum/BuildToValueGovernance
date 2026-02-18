//! SessionTracker v1.7.0 — Accumulates behavioral vectors per session.
//! Compares current request against session baseline (running average).
//!
//! Filosofia (Levinas): Detectar escalation protege o usuário legítimo
//! contra hijacking. Fail-secure: unknown session = fresh baseline.

use std::collections::HashMap;
use std::time::Instant;

use crate::evidence::TechnicalEvidence;
use super::drift::{SessionDrift, SessionVector, DriftResult, DriftLevel};

const DEFAULT_MAX_SESSIONS: usize = 10_000;
const SESSION_TTL_SECS: u64 = 1800; // 30 min

// ─────────────────────────────────────────────────────────────
// SESSION STATE
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct SessionState {
    baseline: SessionVector,
    request_count: u32,
    first_seen: Instant,
    last_seen: Instant,
}

impl SessionState {
    fn new(initial: &SessionVector) -> Self {
        let now = Instant::now();
        Self {
            baseline: initial.clone(),
            request_count: 1,
            first_seen: now,
            last_seen: now,
        }
    }

    fn is_expired(&self) -> bool {
        self.last_seen.elapsed().as_secs() > SESSION_TTL_SECS
    }

    /// Update baseline with exponential moving average (alpha=0.3).
    fn update_baseline(&mut self, current: &SessionVector) {
        const ALPHA: f32 = 0.3;
        self.baseline.avg_input_len =
            self.baseline.avg_input_len * (1.0 - ALPHA) + current.avg_input_len * ALPHA;
        self.baseline.avg_entropy =
            self.baseline.avg_entropy * (1.0 - ALPHA) + current.avg_entropy * ALPHA;
        self.baseline.finding_rate =
            self.baseline.finding_rate * (1.0 - ALPHA) + current.finding_rate * ALPHA;
        self.baseline.critical_rate =
            self.baseline.critical_rate * (1.0 - ALPHA) + current.critical_rate * ALPHA;
        self.baseline.pii_rate =
            self.baseline.pii_rate * (1.0 - ALPHA) + current.pii_rate * ALPHA;
        self.baseline.request_frequency =
            self.baseline.request_frequency * (1.0 - ALPHA) + current.request_frequency * ALPHA;

        self.request_count += 1;
        self.last_seen = Instant::now();
    }
}

// ─────────────────────────────────────────────────────────────
// TRACKER METRICS
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct TrackerMetrics {
    pub sessions_tracked: u64,
    pub drift_checks: u64,
    pub challenges_triggered: u64,
    pub evictions: u64,
}

// ─────────────────────────────────────────────────────────────
// SESSION TRACKER
// ─────────────────────────────────────────────────────────────

pub struct SessionTracker {
    sessions: HashMap<u128, SessionState>,
    drift: SessionDrift,
    metrics: TrackerMetrics,
    max_sessions: usize,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            drift: SessionDrift::new(),
            metrics: TrackerMetrics::default(),
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }

    pub fn with_max_sessions(max: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            drift: SessionDrift::new(),
            metrics: TrackerMetrics::default(),
            max_sessions: max,
        }
    }

    /// Build a SessionVector from TechnicalEvidence.
    pub fn vector_from_evidence(evidence: &TechnicalEvidence) -> SessionVector {
        let input_len = evidence.stats.total_chars as f32;
        let entropy = evidence.stats.entropy;
        let total = evidence.finding_count as f32 + evidence.critical_count as f32;
        let finding_rate = if input_len > 0.0 {
            total / input_len.max(1.0)
        } else {
            0.0
        };
        let critical_rate = if total > 0.0 {
            evidence.critical_count as f32 / total
        } else {
            0.0
        };
        let pii_rate = evidence.composite_risk;

        SessionVector {
            avg_input_len: input_len,
            avg_entropy: entropy,
            finding_rate,
            critical_rate,
            pii_rate,
            request_frequency: 1.0,
        }
    }

    /// Track a request and return drift result.
    /// First request for a session → DriftLevel::None (no baseline yet).
    pub fn track(
        &mut self,
        session_id: u128,
        evidence: &TechnicalEvidence,
    ) -> DriftResult {
        self.evict_expired();
        self.metrics.drift_checks += 1;

        let current = Self::vector_from_evidence(evidence);

        match self.sessions.get_mut(&session_id) {
            Some(state) => {
                let elapsed_mins = state.first_seen.elapsed().as_secs_f32() / 60.0;
                let freq = if elapsed_mins > 0.01 {
                    state.request_count as f32 / elapsed_mins
                } else {
                    1.0
                };
                let mut current_with_freq = current.clone();
                current_with_freq.request_frequency = freq;

                let result = self.drift.compare(&state.baseline, &current_with_freq);

                if result.identity_challenge {
                    self.metrics.challenges_triggered += 1;
                }

                state.update_baseline(&current_with_freq);
                result
            }
            None => {
                if self.sessions.len() >= self.max_sessions {
                    self.evict_oldest();
                }
                self.sessions.insert(session_id, SessionState::new(&current));
                self.metrics.sessions_tracked += 1;

                DriftResult {
                    similarity: 1.0,
                    drift: 0.0,
                    level: DriftLevel::None,
                    identity_challenge: false,
                }
            }
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn get_metrics(&self) -> &TrackerMetrics {
        &self.metrics
    }

    fn evict_expired(&mut self) {
        let before = self.sessions.len();
        self.sessions.retain(|_, state| !state.is_expired());
        let evicted = before - self.sessions.len();
        self.metrics.evictions += evicted as u64;
    }

    fn evict_oldest(&mut self) {
        if let Some((&oldest_id, _)) = self.sessions
            .iter()
            .min_by_key(|(_, state)| state.last_seen)
        {
            self.sessions.remove(&oldest_id);
            self.metrics.evictions += 1;
        }
    }
}

impl Default for SessionTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Gatekeeper;

    #[test]
    fn test_first_request_no_drift() {
        let mut tracker = SessionTracker::new();
        let mut gk = Gatekeeper::new();
        let evidence = gk.scan_for_evidence("hello world", 0x1111);
        let result = tracker.track(0x1111, &evidence);
        assert_eq!(result.level, DriftLevel::None);
        assert_eq!(tracker.session_count(), 1);
    }

    #[test]
    fn test_consistent_requests_no_drift() {
        let mut tracker = SessionTracker::new();
        let mut gk = Gatekeeper::new();

        for _ in 0..5 {
            let evidence = gk.scan_for_evidence("hello world normal text", 0x2222);
            let result = tracker.track(0x2222, &evidence);
            assert_eq!(result.level, DriftLevel::None);
        }
        assert_eq!(tracker.session_count(), 1);
    }

    #[test]
    fn test_sudden_pii_triggers_drift() {
        let mut tracker = SessionTracker::new();
        let mut gk = Gatekeeper::new();

        for _ in 0..5 {
            let evidence = gk.scan_for_evidence("hello world normal text", 0x3333);
            tracker.track(0x3333, &evidence);
        }

        let evidence = gk.scan_for_evidence(
            "CPF 123.456.789-09 email test@test.com cartao 4532 0151 1283 0366",
            0x3333,
        );
        let result = tracker.track(0x3333, &evidence);

        assert!(
            result.drift > 0.0,
            "Drift should be > 0 after PII burst, got {}",
            result.drift
        );
    }

    #[test]
    fn test_different_sessions_independent() {
        let mut tracker = SessionTracker::new();
        let mut gk = Gatekeeper::new();

        let e1 = gk.scan_for_evidence("clean text", 0xAAAA);
        let e2 = gk.scan_for_evidence("CPF 123.456.789-09", 0xBBBB);

        tracker.track(0xAAAA, &e1);
        tracker.track(0xBBBB, &e2);

        assert_eq!(tracker.session_count(), 2);
    }

    #[test]
    fn test_max_sessions_eviction() {
        let mut tracker = SessionTracker::with_max_sessions(50);
        let mut gk = Gatekeeper::new();

        for i in 0..55u128 {
            let evidence = gk.scan_for_evidence("test", i);
            tracker.track(i, &evidence);
        }

        assert!(tracker.session_count() <= 50);
        assert!(tracker.get_metrics().evictions > 0);
    }

    #[test]
    fn test_metrics_tracked() {
        let mut tracker = SessionTracker::new();
        let mut gk = Gatekeeper::new();

        let evidence = gk.scan_for_evidence("test input", 0x5555);
        tracker.track(0x5555, &evidence);
        tracker.track(0x5555, &evidence);

        let m = tracker.get_metrics();
        assert_eq!(m.sessions_tracked, 1);
        assert_eq!(m.drift_checks, 2);
    }
}