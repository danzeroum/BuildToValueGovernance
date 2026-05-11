//! NHS, VAT, IBAN PII detection integration tests
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use buildtovalue_kernel::gatekeeper::Gatekeeper;

    #[test]
    fn nhs_number_detected() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"Patient NHS number: 943 476 5919").unwrap();
        assert!(ev.composite_risk_score > 0.0);
    }

    #[test]
    fn vat_number_detected() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"VAT GB123456789").unwrap();
        assert!(ev.composite_risk_score > 0.0);
    }

    #[test]
    fn iban_detected() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"IBAN: GB29NWBK60161331926819").unwrap();
        assert!(ev.composite_risk_score > 0.0);
    }

    #[test]
    fn clean_text_low_risk() {
        let gk = Gatekeeper::new();
        let ev = gk.adapt(b"The weather today is sunny").unwrap();
        assert!(ev.composite_risk_score < 0.5);
    }
}
