//! F1.5-04: DurableLedger Recovery + Chain Integrity tests

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::suspicious_open_options, clippy::field_reassign_with_default)]
mod tests {
    use buildtovalue_kernel::ledger::durable_ledger::{ChainStatus, DurableLedger};
    use buildtovalue_kernel::ledger::entry::LedgerEntry;
    use tempfile::tempdir;

    // -----------------------------------------------------------------
    // TEST 1: Chain verification on empty ledger
    // -----------------------------------------------------------------
    #[test]
    fn test_chain_empty_ledger() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.dat");

        let status = DurableLedger::verify_chain_integrity(&path).unwrap();
        assert_eq!(status, ChainStatus::Empty);
    }

    // -----------------------------------------------------------------
    // TEST 2: Chain verification with valid entries
    // -----------------------------------------------------------------
    #[test]
    fn test_chain_valid_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("valid.dat");

        // Write 5 chained entries manually
        write_chained_entries(&path, 5);

        let status = DurableLedger::verify_chain_integrity(&path).unwrap();
        assert_eq!(status, ChainStatus::Valid { entry_count: 5 });
    }

    // -----------------------------------------------------------------
    // TEST 3: Tampered entry detected
    // -----------------------------------------------------------------
    #[test]
    fn test_chain_tampered_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tampered.dat");

        // Write 3 entries, tamper the 2nd
        write_chained_entries_with_tamper(&path, 3, 1);

        let status = DurableLedger::verify_chain_integrity(&path).unwrap();
        match status {
            ChainStatus::TamperedAt { entry_id, .. } => {
                assert_eq!(entry_id, 2); // 0-indexed entry 1 = id 2
            }
            other => panic!("Expected TamperedAt, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------
    // TEST 4: Broken chain link detected
    // -----------------------------------------------------------------
    #[test]
    fn test_chain_broken_link() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("broken.dat");

        write_entries_with_broken_chain(&path, 3);

        let status = DurableLedger::verify_chain_integrity(&path).unwrap();
        match status {
            ChainStatus::BrokenAt { entry_id } => {
                assert!(entry_id > 1);
            }
            other => panic!("Expected BrokenAt, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------
    // TEST 5: Recovery reads correct entry count
    // -----------------------------------------------------------------
    #[test]
    fn test_recovery_reads_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("recovery.dat");

        write_chained_entries(&path, 10);

        let result = DurableLedger::recover(&path).unwrap();
        assert_eq!(result.entries_from_disk, 10);
        assert_eq!(result.chain_status, ChainStatus::Valid { entry_count: 10 });
    }

    // -----------------------------------------------------------------
    // TEST 6: Recovery < 5s for 10k entries (benchmark)
    // -----------------------------------------------------------------
    #[test]
    fn test_recovery_performance_10k() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("perf_10k.dat");

        write_chained_entries(&path, 10_000);

        let result = DurableLedger::recover(&path).unwrap();
        assert_eq!(result.entries_from_disk, 10_000);
        assert!(
            result.recovery_time_ms < 5000.0,
            "Recovery took {:.2}ms, exceeds 5s SLA",
            result.recovery_time_ms
        );
        assert_eq!(result.chain_status, ChainStatus::Valid { entry_count: 10_000 });
    }

    // =================================================================
    // HELPERS
    // =================================================================

    fn write_chained_entries(path: &std::path::PathBuf, count: u64) {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .unwrap();

        let mut prev_hash = [0u8; 32];

        for i in 1..=count {
            let mut entry = LedgerEntry::default();
            entry.entry_id = i;
            entry.audit_trail_id = i as u128;
            entry.timestamp = i as u128 * 1000;
            entry.previous_hash = prev_hash;
            entry.finalize();
            prev_hash = entry.entry_hash;

            let bytes = bincode::serialize(&entry).unwrap();
            file.write_all(&bytes).unwrap();
        }
        file.sync_all().unwrap();
    }

    fn write_chained_entries_with_tamper(
        path: &std::path::PathBuf,
        count: u64,
        tamper_index: u64,
    ) {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .unwrap();

        let mut prev_hash = [0u8; 32];

        for i in 1..=count {
            let mut entry = LedgerEntry::default();
            entry.entry_id = i;
            entry.audit_trail_id = i as u128;
            entry.timestamp = i as u128 * 1000;
            entry.previous_hash = prev_hash;
            entry.finalize();
            prev_hash = entry.entry_hash;

            // Tamper after finalize (hash won't match)
            if i == tamper_index + 1 {
                entry.audit_trail_id = 0xDEAD;
            }

            let bytes = bincode::serialize(&entry).unwrap();
            file.write_all(&bytes).unwrap();
        }
        file.sync_all().unwrap();
    }

    fn write_entries_with_broken_chain(path: &std::path::PathBuf, count: u64) {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .unwrap();

        let mut prev_hash = [0u8; 32];

        for i in 1..=count {
            let mut entry = LedgerEntry::default();
            entry.entry_id = i;
            entry.audit_trail_id = i as u128;
            entry.timestamp = i as u128 * 1000;

            // Break chain at entry 3
            if i == 3 {
                entry.previous_hash = [0xFF; 32]; // Wrong hash
            } else {
                entry.previous_hash = prev_hash;
            }

            entry.finalize();
            prev_hash = entry.entry_hash;

            let bytes = bincode::serialize(&entry).unwrap();
            file.write_all(&bytes).unwrap();
        }
        file.sync_all().unwrap();
    }
}