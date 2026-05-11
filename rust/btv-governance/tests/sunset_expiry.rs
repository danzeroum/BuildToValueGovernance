//! Integration test: SunsetPolicy — automatic expiry and bounded renewals.

#![allow(clippy::expect_used, clippy::unwrap_used)] // testes de integração: pânico = asserção

use btv_governance::{
    error::GovernanceError,
    sunset::SunsetPolicy,
};
use chrono::Duration;

#[test]
fn new_policy_is_active() {
    let p = SunsetPolicy::new(
        "POLICY-TEST-001".into(),
        Duration::days(30),
        3,
        "legislative".into(),
    );
    assert!(p.is_active());
    assert!(p.time_remaining() > Duration::zero());
}

#[test]
fn expired_policy_is_not_active() {
    // Use a negative duration so it already expired.
    let p = SunsetPolicy::new(
        "POLICY-TEST-002".into(),
        Duration::seconds(-1),
        3,
        "legislative".into(),
    );
    assert!(!p.is_active());
    assert_eq!(p.time_remaining(), Duration::zero());
}

#[test]
fn renewal_extends_and_increments_count() {
    let mut p = SunsetPolicy::new(
        "POLICY-TEST-003".into(),
        Duration::days(30),
        3,
        "legislative".into(),
    );
    assert!(p.renew(Duration::days(30)).is_ok());
    assert_eq!(p.renewal_count, 1);
    assert!(p.is_active());
}

#[test]
fn renewal_exhaustion_returns_error() {
    let mut p = SunsetPolicy::new(
        "POLICY-TEST-004".into(),
        Duration::days(30),
        1,
        "legislative".into(),
    );
    p.renew(Duration::days(30)).expect("first renewal must succeed");
    match p.renew(Duration::days(30)) {
        Err(GovernanceError::SunsetPolicyExhausted { renewals: 1, max: 1, .. }) => {}
        other => panic!("Expected SunsetPolicyExhausted, got {:?}", other),
    }
}

#[test]
fn zero_max_renewals_fails_immediately() {
    let mut p = SunsetPolicy::new(
        "POLICY-TEST-005".into(),
        Duration::days(30),
        0,
        "legislative".into(),
    );
    assert!(matches!(
        p.renew(Duration::days(30)),
        Err(GovernanceError::SunsetPolicyExhausted { .. })
    ));
}
