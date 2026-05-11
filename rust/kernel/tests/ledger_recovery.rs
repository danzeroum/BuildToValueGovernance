//! Ledger recovery tests
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use buildtovalue_kernel::ledger::DurableLedger;

    #[test]
    fn ledger_append_and_read_single_entry() {
        let mut ledger = DurableLedger::new();
        let ev = make_evidence(1);
        ledger.append(&ev).unwrap();
        let entries = ledger.entries();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn ledger_append_multiple_entries_in_order() {
        let mut ledger = DurableLedger::new();
        for i in 1u64..=5 {
            let ev = make_evidence(i);
            ledger.append(&ev).unwrap();
        }
        let entries = ledger.entries();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn ledger_hmac_chain_valid_after_append() {
        let mut ledger = DurableLedger::new();
        let ev = make_evidence(1);
        ledger.append(&ev).unwrap();
        assert!(ledger.verify_chain());
    }

    #[test]
    fn ledger_chain_valid_after_multiple_appends() {
        let mut ledger = DurableLedger::new();
        for i in 1u64..=3 {
            ledger.append(&make_evidence(i)).unwrap();
        }
        assert!(ledger.verify_chain());
    }

    #[test]
    fn ledger_tampered_entry_fails_verification() {
        let mut ledger = DurableLedger::new();
        ledger.append(&make_evidence(1)).unwrap();
        ledger.append(&make_evidence(2)).unwrap();
        ledger.tamper_for_test(0);
        assert!(!ledger.verify_chain());
    }

    #[test]
    fn ledger_empty_chain_is_valid() {
        let ledger = DurableLedger::new();
        assert!(ledger.verify_chain());
    }

    #[test]
    fn ledger_entry_count_matches_appends() {
        let mut ledger = DurableLedger::new();
        let n = 7usize;
        for i in 0..n {
            ledger.append(&make_evidence(i as u64)).unwrap();
        }
        assert_eq!(ledger.entries().len(), n);
    }

    // -- Helpers --
    fn make_evidence(seq: u64) -> buildtovalue_kernel::evidence::TechnicalEvidence {
        buildtovalue_kernel::evidence::TechnicalEvidence::new(seq)
    }
}
