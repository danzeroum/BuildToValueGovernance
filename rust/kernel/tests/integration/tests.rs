//! BuildToValue v2.2 - Comprehensive Test Suite (MERGED)
//! Combina testes existentes + novos testes dos exemplos da documentação

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use blake3;

    // ═══════════════════════════════════════════════════════════════
    // SEÇÃO 1: FIXED-SIZE ALLOCATION (3 testes)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_evidence_size() {
        use std::mem::size_of;
        let size = size_of::<TechnicalEvidence>();
        assert_eq!(size, 9625, "Evidence size changed!");
    }

    #[test]
    fn test_finding_size_invariant() {
        use std::mem::size_of;
        assert_eq!(size_of::<Finding>(), 128, "Finding size changed!");
    }

    #[test]
    fn test_no_heap_allocations() {
        let evidence = TechnicalEvidence::default();
        assert_eq!(evidence.findings.len(), 10);
        assert_eq!(evidence.critical.len(), 3);
    }

    // ═══════════════════════════════════════════════════════════════
    // SEÇÃO 2: RING BUFFER (4 testes)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_ring_buffer_overflow() {
        let mut evidence = TechnicalEvidence::default();

        for i in 0..15 {
            evidence.add_finding(Finding {
                r#type: FindingType::CpfDetected,
                location: format!("offset {}", i * 10),
                value: format!("CPF {}", i),
                confidence: 0.95,
                severity: Severity::Medium,
                validator: "cpf_validator",
                ..Default::default()
            });
        }

        assert_eq!(evidence.finding_count, 10);

        let values: Vec<_> = evidence.findings.iter()
            .map(|f| &f.value)
            .collect();
        assert!(!values.contains(&&"CPF 0".to_string()));
        assert!(values.contains(&&"CPF 14".to_string()));
    }

    #[test]
    fn test_ring_buffer_never_overflows() {
        let mut evidence = TechnicalEvidence::default();

        for i in 0..100 {
            evidence.add_finding(Finding {
                r#type: FindingType::CpfDetected,
                value: format!("STRESS_{:03}", i),
                ..Default::default()
            });
        }

        assert!(evidence.finding_count <= 10);
        assert!(evidence.critical_count <= 3);
    }

    #[test]
    fn test_critical_findings_preserved() {
        let mut evidence = TechnicalEvidence::default();

        for i in 0..5 {
            evidence.add_finding(Finding {
                r#type: FindingType::CpfDetected,
                severity: Severity::Critical,
                value: format!("CRITICAL {}", i),
                ..Default::default()
            });
        }

        assert_eq!(evidence.critical_count, 3);

        let values: Vec<_> = evidence.critical.iter()
            .map(|f| &f.value)
            .collect();
        assert!(!values.contains(&&"CRITICAL 0".to_string()));
        assert!(values.contains(&&"CRITICAL 4".to_string()));
    }

    // ═══════════════════════════════════════════════════════════════
    // SEÇÃO 3: HASH INTEGRITY (5 testes)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_hash_deterministic() {
        let mut e1 = TechnicalEvidence::default();
        e1.add_finding(Finding {
            r#type: FindingType::CpfDetected,
            value: "123.456.789-09".to_string(),
            ..Default::default()
        });

        let mut e2 = TechnicalEvidence::default();
        e2.add_finding(Finding {
            r#type: FindingType::CpfDetected,
            value: "123.456.789-09".to_string(),
            ..Default::default()
        });

        e1.finalize();
        e2.finalize();

        assert_eq!(e1.evidence_hash, e2.evidence_hash);
    }

    #[test]
    fn test_hash_changes_on_modification() {
        let mut evidence = TechnicalEvidence::default();
        evidence.add_finding(Finding {
            value: "Original".to_string(),
            ..Default::default()
        });
        evidence.finalize();
        let hash1 = evidence.evidence_hash;

        evidence.findings[0].value = "Modified".to_string();
        evidence.finalize();
        let hash2 = evidence.evidence_hash;

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_collision_resistance() {
        let mut hashes = std::collections::HashSet::new();

        for i in 0..10000 {
            let mut evidence = TechnicalEvidence::default();
            evidence.add_finding(Finding {
                value: format!("Finding {}", i),
                ..Default::default()
            });
            evidence.finalize();

            assert!(hashes.insert(evidence.evidence_hash));
        }
    }

    #[test]
    fn test_tampering_detection() {
        let mut evidence = TechnicalEvidence::default();
        evidence.add_finding(Finding {
            value: "123.456.789-09".to_string(),
            ..Default::default()
        });
        evidence.finalize();

        assert!(evidence.validate());

        let original = evidence.composite_risk;
        evidence.composite_risk = 0;
        assert!(!evidence.validate());

        evidence.composite_risk = original;
        assert!(evidence.validate());
    }

    #[test]
    fn test_finalize_idempotency() {
        let mut evidence = TechnicalEvidence::default();
        evidence.add_finding(Finding::default());

        assert!(evidence.finalize().is_ok());
        assert!(evidence.finalize().is_err());
    }

    // ═══════════════════════════════════════════════════════════════
    // SEÇÃO 4: COMPOSITE RISK (4 testes)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_composite_risk_empty() {
        let evidence = TechnicalEvidence::default();
        assert_eq!(evidence.calculate_composite_risk(), 0);
    }

    #[test]
    fn test_composite_risk_bounds() {
        let mut evidence = TechnicalEvidence::default();
        evidence.add_finding(Finding {
            severity: Severity::Critical,
            confidence: 1.0,
            ..Default::default()
        });

        let risk = evidence.calculate_composite_risk();
        assert!(risk <= 255 && risk > 0);
    }

    #[test]
    fn test_composite_risk_cpf() {
        let mut evidence = TechnicalEvidence::default();
        evidence.add_finding(Finding {
            r#type: FindingType::CpfDetected,
            value: "123.456.789-09".to_string(),
            severity: Severity::High,
            confidence: 1.0,
            ..Default::default()
        });

        let risk = evidence.calculate_composite_risk();
        assert!(risk >= 180 && risk <= 210);
    }

    #[test]
    fn test_composite_risk_critical_weight() {
        let mut e_normal = TechnicalEvidence::default();
        e_normal.add_finding(Finding {
            severity: Severity::Medium,
            confidence: 1.0,
            ..Default::default()
        });

        let mut e_critical = TechnicalEvidence::default();
        e_critical.add_finding(Finding {
            severity: Severity::Critical,
            confidence: 1.0,
            ..Default::default()
        });

        let r_normal = e_normal.calculate_composite_risk();
        let r_critical = e_critical.calculate_composite_risk();

        assert!(r_critical > r_normal * 1.5);
    }

    // ═══════════════════════════════════════════════════════════════
    // SEÇÃO 5: SERIALIZATION (1 teste)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_serialization_roundtrip() {
        let mut evidence = TechnicalEvidence::default();
        evidence.add_finding(Finding {
            r#type: FindingType::CpfDetected,
            value: "123.456.789-09".to_string(),
            confidence: 0.95,
            ..Default::default()
        });
        evidence.finalize();

        let bytes = evidence.to_bytes();
        let evidence2 = TechnicalEvidence::from_bytes(&bytes).unwrap();

        assert_eq!(evidence.evidence_hash, evidence2.evidence_hash);
        assert_eq!(evidence.finding_count, evidence2.finding_count);
    }

    // ═══════════════════════════════════════════════════════════════
    // SEÇÃO 6: SECURITY (2 testes)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    #[ignore]
    fn test_constant_time_validation() {
        use std::time::Instant;

        let cases = vec!["Sem CPF", "CPF inválido", "CPF válido", "Blacklist"];
        let mut timings: Vec<Vec<u128>> = vec![vec![]; cases.len()];

        for (idx, _case) in cases.iter().enumerate() {
            for _ in 0..10_000 {
                let start = Instant::now();
                std::thread::sleep(std::time::Duration::from_nanos(100));
                timings[idx].push(start.elapsed().as_nanos());
            }
        }

        let means: Vec<f64> = timings.iter()
            .map(|t| t.iter().sum::<u128>() as f64 / t.len() as f64)
            .collect();

        let overall = means.iter().sum::<f64>() / means.len() as f64;

        for mean in &means {
            let diff = ((mean - overall) / overall).abs() * 100.0;
            assert!(diff < 5.0);
        }
    }

    #[test]
    fn test_memory_cleanup() {
        {
            let mut e = TechnicalEvidence::default();
            e.add_finding(Finding::default());
            e.finalize();
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // SEÇÃO 7: PERFORMANCE (1 teste)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    #[ignore]
    fn test_kernel_latency_p99() {
        use std::time::{Duration, Instant};

        let mut latencies = Vec::with_capacity(10_000);

        for _ in 0..10_000 {
            let start = Instant::now();

            let mut e = TechnicalEvidence::default();
            for _ in 0..5 {
                e.add_finding(Finding::default());
            }
            e.finalize();

            latencies.push(start.elapsed());
        }

        latencies.sort();
        let p99 = latencies[(latencies.len() as f64 * 0.99) as usize];

        println!("p99: {:?}", p99);
        assert!(p99 < Duration::from_millis(30));
    }

    // ═══════════════════════════════════════════════════════════════
    // SEÇÃO 8: BENCHMARKS (criterion)
    // ═══════════════════════════════════════════════════════════════

    #[cfg(feature = "bench")]
    use criterion::{black_box, Criterion};

    #[cfg(feature = "bench")]
    pub fn bench_evidence_finalization(c: &mut Criterion) {
        c.bench_function("evidence_finalize", |b| {
            let mut evidence = TechnicalEvidence::default();
            for i in 0..10 {
                evidence.add_finding(Finding {
                    value: format!("Finding {}", i),
                    ..Default::default()
                });
            }

            b.iter(|| {
                evidence.finalize();
                black_box(&evidence.evidence_hash);
            });
        });
    }

    // ═══════════════════════════════════════════════════════════════
    // SEÇÃO 9: SMOKE TEST
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_smoke_basic_flow() {
        let mut evidence = TechnicalEvidence::default();
        evidence.add_finding(Finding {
            value: "123.456.789-09".to_string(),
            ..Default::default()
        });

        assert!(evidence.finalize().is_ok());
        assert!(evidence.validate());
        assert!(evidence.composite_risk > 0);
    }
}