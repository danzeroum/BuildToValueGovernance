//! Session Aggregator v1.0.0 — PROP-005 (Fourth Estate)
//! Agrega eventos de sessão para o ledger do Fourth Estate.
//! Zero heap após init: ring buffer de capacidade fixa na stack.
//! Fail-secure: overflow → entradas mais antigas descartadas (ring FIFO).

use crate::core::types::RiskLevel;

/// Capacidade do ring buffer.
pub const SESSION_RING_CAPACITY: usize = 256;

/// Evento individual de sessão.
#[derive(Debug, Clone, Copy)]
pub struct SessionEvent {
    pub timestamp_us: u64,
    pub risk_level: RiskLevel,
    pub composite_risk: f32,
    pub blocked: bool,
    pub has_pii: bool,
}

impl SessionEvent {
    pub fn new(
        timestamp_us: u64,
        risk_level: RiskLevel,
        composite_risk: f32,
        blocked: bool,
        has_pii: bool,
    ) -> Self {
        Self { timestamp_us, risk_level, composite_risk, blocked, has_pii }
    }
}

/// Métricas agregadas da sessão para o Fourth Estate ledger.
#[derive(Debug, Clone)]
pub struct SessionAggregate {
    pub session_id: u128,
    pub event_count: usize,
    pub block_count: usize,
    pub pii_count: usize,
    pub avg_risk: f32,
    pub max_risk_level: RiskLevel,
    pub first_event_us: u64,
    pub last_event_us: u64,
}

/// Aggregator com ring buffer fixo (zero heap após new()).
pub struct SessionAggregator {
    session_id: u128,
    buffer: [Option<SessionEvent>; SESSION_RING_CAPACITY],
    head: usize,
    count: usize,
}

impl SessionAggregator {
    pub fn new(session_id: u128) -> Self {
        Self {
            session_id,
            buffer: [None; SESSION_RING_CAPACITY],
            head: 0,
            count: 0,
        }
    }

    /// Insere evento no ring buffer (FIFO, zero heap).
    pub fn push(&mut self, event: SessionEvent) {
        self.buffer[self.head % SESSION_RING_CAPACITY] = Some(event);
        self.head = self.head.wrapping_add(1);
        if self.count < SESSION_RING_CAPACITY {
            self.count += 1;
        }
    }

    pub fn len(&self) -> usize { self.count }
    pub fn is_empty(&self) -> bool { self.count == 0 }

    /// Agrega todos os eventos em SessionAggregate.
    pub fn aggregate(&self) -> SessionAggregate {
        let mut block_count = 0usize;
        let mut pii_count = 0usize;
        let mut total_risk = 0.0f32;
        let mut max_risk = RiskLevel::Safe;
        let mut first_us = u64::MAX;
        let mut last_us = u64::MIN;
        let mut valid_count = 0usize;

        for slot in &self.buffer {
            if let Some(ev) = slot {
                valid_count += 1;
                if ev.blocked { block_count += 1; }
                if ev.has_pii { pii_count += 1; }
                total_risk += ev.composite_risk;
                if (ev.risk_level as u8) > (max_risk as u8) {
                    max_risk = ev.risk_level;
                }
                if ev.timestamp_us < first_us { first_us = ev.timestamp_us; }
                if ev.timestamp_us > last_us { last_us = ev.timestamp_us; }
            }
        }

        SessionAggregate {
            session_id: self.session_id,
            event_count: valid_count,
            block_count,
            pii_count,
            avg_risk: if valid_count > 0 { total_risk / valid_count as f32 } else { 0.0 },
            max_risk_level: max_risk,
            first_event_us: if first_us == u64::MAX { 0 } else { first_us },
            last_event_us: if last_us == u64::MIN { 0 } else { last_us },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::RiskLevel;

    fn ev(risk: RiskLevel, composite: f32, blocked: bool) -> SessionEvent {
        SessionEvent::new(1_000_000, risk, composite, blocked, false)
    }

    #[test]
    fn empty_aggregator() {
        let agg = SessionAggregator::new(42);
        assert!(agg.is_empty());
        let r = agg.aggregate();
        assert_eq!(r.event_count, 0);
        assert_eq!(r.block_count, 0);
        assert_eq!(r.avg_risk, 0.0);
    }

    #[test]
    fn single_event() {
        let mut agg = SessionAggregator::new(1);
        agg.push(ev(RiskLevel::Low, 25.0, false));
        let r = agg.aggregate();
        assert_eq!(r.event_count, 1);
        assert!((r.avg_risk - 25.0).abs() < 0.001);
    }

    #[test]
    fn block_count_tracked() {
        let mut agg = SessionAggregator::new(2);
        agg.push(ev(RiskLevel::High, 80.0, true));
        agg.push(ev(RiskLevel::Low, 20.0, false));
        agg.push(ev(RiskLevel::High, 90.0, true));
        let r = agg.aggregate();
        assert_eq!(r.block_count, 2);
        assert_eq!(r.event_count, 3);
    }

    #[test]
    fn ring_overflow_evicts_oldest() {
        let mut agg = SessionAggregator::new(3);
        for i in 0..SESSION_RING_CAPACITY + 10 {
            agg.push(SessionEvent::new(i as u64, RiskLevel::Safe, 0.0, false, false));
        }
        assert_eq!(agg.len(), SESSION_RING_CAPACITY);
    }

    #[test]
    fn max_risk_tracked() {
        let mut agg = SessionAggregator::new(4);
        agg.push(ev(RiskLevel::Safe, 5.0, false));
        agg.push(ev(RiskLevel::Critical, 95.0, true));
        let r = agg.aggregate();
        assert_eq!(r.max_risk_level as u8, RiskLevel::Critical as u8);
    }

    #[test]
    fn session_id_preserved() {
        let r = SessionAggregator::new(0xDEAD_BEEF_u128).aggregate();
        assert_eq!(r.session_id, 0xDEAD_BEEF_u128);
    }

    #[test]
    fn pii_count_tracked() {
        let mut agg = SessionAggregator::new(5);
        agg.push(SessionEvent::new(1, RiskLevel::Low, 10.0, false, true));
        agg.push(SessionEvent::new(2, RiskLevel::Safe, 0.0, false, false));
        assert_eq!(agg.aggregate().pii_count, 1);
    }
}
