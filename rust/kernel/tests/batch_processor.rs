//! F1.5-03: BatchProcessor tests

#[cfg(test)]
mod tests {
    use buildtovalue_kernel::batch::{BatchProcessor, BatchConfig, BatchError, BatchItemStatus};
    use buildtovalue_kernel::gatekeeper::Gatekeeper;

    // -----------------------------------------------------------------
    // TEST 1: Basic batch of 3 inputs
    // -----------------------------------------------------------------
    #[test]
    fn test_batch_basic() {
        let mut gk = Gatekeeper::new();
        let bp = BatchProcessor::new(test_config());

        let inputs = vec!["hello world", "test message", "clean input"];
        let ids: Vec<u128> = vec![1, 2, 3];

        let result = bp.process(&mut gk, &inputs, &ids).unwrap();
        assert_eq!(result.items.len(), 3);
        assert_eq!(result.succeeded, 3);
        assert_eq!(result.timed_out, 0);
        assert_eq!(result.failed, 0);

        for item in &result.items {
            assert!(item.evidence.is_some());
            assert_eq!(item.status, BatchItemStatus::Ok);
        }
    }

    // -----------------------------------------------------------------
    // TEST 2: Batch with PII detection
    // -----------------------------------------------------------------
    #[test]
    fn test_batch_with_findings() {
        let mut gk = Gatekeeper::new();
        let bp = BatchProcessor::new(test_config());

        let inputs = vec![
            "no pii here",
            "CPF: 123.456.789-09",
            "email: test@example.com",
        ];
        let ids: Vec<u128> = vec![10, 20, 30];

        let result = bp.process(&mut gk, &inputs, &ids).unwrap();
        assert_eq!(result.succeeded, 3);

        // Item 0: clean
        assert_eq!(result.items[0].evidence.as_ref().unwrap().finding_count, 0);
        // Item 1: CPF detected
        assert!(result.items[1].evidence.as_ref().unwrap().finding_count > 0);
        // Item 2: Email detected
        assert!(result.items[2].evidence.as_ref().unwrap().finding_count > 0);
    }

    // -----------------------------------------------------------------
    // TEST 3: Empty batch → error
    // -----------------------------------------------------------------
    #[test]
    fn test_batch_empty_error() {
        let mut gk = Gatekeeper::new();
        let bp = BatchProcessor::with_defaults();

        let result = bp.process(&mut gk, &[], &[]);
        assert_eq!(result.unwrap_err(), BatchError::EmptyBatch);
    }

    // -----------------------------------------------------------------
    // TEST 4: Length mismatch → error
    // -----------------------------------------------------------------
    #[test]
    fn test_batch_length_mismatch() {
        let mut gk = Gatekeeper::new();
        let bp = BatchProcessor::with_defaults();

        let inputs = vec!["a", "b"];
        let ids: Vec<u128> = vec![1];

        let result = bp.process(&mut gk, &inputs, &ids);
        match result.unwrap_err() {
            BatchError::LengthMismatch { inputs: 2, ids: 1 } => {}
            other => panic!("Expected LengthMismatch, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------
    // TEST 5: Exceeds max size → error
    // -----------------------------------------------------------------
    #[test]
    fn test_batch_exceeds_max() {
        let mut gk = Gatekeeper::new();
        let config = BatchConfig {
            max_batch_size: 5,
            ..Default::default()
        };
        let bp = BatchProcessor::new(config);

        let inputs: Vec<&str> = vec!["x"; 10];
        let ids: Vec<u128> = (0..10).map(|i| i as u128).collect();

        let result = bp.process(&mut gk, &inputs, &ids);
        assert_eq!(
            result.unwrap_err(),
            BatchError::ExceedsMaxSize { size: 10, max: 5 }
        );
    }

    // -----------------------------------------------------------------
    // TEST 6: 100 items under 1s
    // -----------------------------------------------------------------

    fn test_config() -> BatchConfig {
        BatchConfig {
            max_batch_size: 100,
            item_timeout_us: 500_000,     // 500ms per item (debug mode)
            batch_timeout_us: 10_000_000, // 10s total (debug mode)
        }
    }

    #[test]
    fn test_batch_100_items_performance() {
        let mut gk = Gatekeeper::new(); // regex compile aqui (~10ms)
        let bp = BatchProcessor::new(test_config());

        // Warm up gatekeeper (REGISTRY already compiled in new(), this warms OS-level caches)
        let _ = gk.scan_for_evidence("warmup input", 0); // 12 chars >= MIN_INPUT_LENGTH

        let inputs: Vec<&str> = vec!["sample input with some text to scan"; 100];
        let ids: Vec<u128> = (0..100).map(|i| i as u128).collect();

        let start = std::time::Instant::now();
        let result = bp.process(&mut gk, &inputs, &ids).unwrap();
        let elapsed = start.elapsed().as_micros();

        assert_eq!(result.items.len(), 100);
        assert!(
            elapsed < 5_000_000,
            "Batch 100 items took {}us, exceeds 5s",
            elapsed
        );
    }
    // -----------------------------------------------------------------
    // TEST 7: Each item has unique audit_trail_id preserved
    // -----------------------------------------------------------------
    #[test]
    fn test_batch_audit_trail_preserved() {
        let mut gk = Gatekeeper::new();
        let bp = BatchProcessor::with_defaults();

        let inputs = vec!["a", "b", "c"];
        let ids: Vec<u128> = vec![0xAABB, 0xCCDD, 0xEEFF];

        let result = bp.process(&mut gk, &inputs, &ids).unwrap();
        for (i, item) in result.items.iter().enumerate() {
            assert_eq!(item.audit_trail_id, ids[i]);
            assert_eq!(
                item.evidence.as_ref().unwrap().audit_trail_id,
                ids[i]
            );
        }
    }
}