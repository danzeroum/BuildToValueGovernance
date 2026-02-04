
#[cfg(test)]
mod tests {
    use super::*;
    use blake3;
    
    // ═══════════════════════════════════════════════════════════════
    // Fixed-Size Allocation
    // ═══════════════════════════════════════════════════════════════
    
    #[test]
    fn test_evidence_size() {
        use std::mem::size_of;
        
        let size = size_of::<TechnicalEvidence>();
        
        // Must be exactly 9.4KB (9625 bytes)
        assert_eq!(size, 9625, "Evidence size changed! Update protocol version.");
    }
    
    #[test]
    fn test_no_heap_allocations() {
        // Evidence should live entirely on stack
        let evidence = TechnicalEvidence::default();
        
        // Verify all arrays are inline
        assert_eq!(evidence.findings.len(), 10);
        assert_eq!(evidence.critical.len(), 3);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Ring Buffer (Findings)
    // ═══════════════════════════════════════════════════════════════
    
    #[test]
    fn test_ring_buffer_overflow() {
        let mut evidence = TechnicalEvidence::default();
        
        // Add 15 findings (buffer holds 10)
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
        
        // Should keep last 10
        assert_eq!(evidence.finding_count, 10);
        
        // Oldest finding (0-4) should be gone
        let values: Vec<_> = evidence.findings.iter()
            .map(|f| &f.value)
            .collect();
        
        assert!(!values.contains(&&"CPF 0".to_string()));
        assert!(values.contains(&&"CPF 14".to_string()));
    }
    
    #[test]
    fn test_critical_findings_preserved() {
        let mut evidence = TechnicalEvidence::default();
        
        // Add 5 critical findings
        for i in 0..5 {
            evidence.add_finding(Finding {
                r#type: FindingType::CpfDetected,
                severity: Severity::Critical,
                value: format!("CRITICAL {}", i),
                ..Default::default()
            });
        }
        
        // Critical buffer holds 3, should preserve last 3
        assert_eq!(evidence.critical_count, 3);
        
        let critical_values: Vec<_> = evidence.critical.iter()
            .map(|f| &f.value)
            .collect();
        
        assert!(!critical_values.contains(&&"CRITICAL 0".to_string()));
        assert!(critical_values.contains(&&"CRITICAL 4".to_string()));
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Hash Integrity
    // ═══════════════════════════════════════════════════════════════
    
    #[test]
    fn test_hash_deterministic() {
        let mut evidence1 = TechnicalEvidence::default();
        evidence1.add_finding(Finding {
            r#type: FindingType::CpfDetected,
            value: "123.456.789-09".to_string(),
            ..Default::default()
        });
        
        let mut evidence2 = TechnicalEvidence::default();
        evidence2.add_finding(Finding {
            r#type: FindingType::CpfDetected,
            value: "123.456.789-09".to_string(),
            ..Default::default()
        });
        
        evidence1.finalize();
        evidence2.finalize();
        
        // Same input → same hash
        assert_eq!(evidence1.evidence_hash, evidence2.evidence_hash);
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
        
        // Modify and re-finalize
        evidence.findings[0].value = "Modified".to_string();
        evidence.finalize();
        let hash2 = evidence.evidence_hash;
        
        // Hash should change
        assert_ne!(hash1, hash2);
    }
    
    #[test]
    fn test_hash_collision_resistance() {
        // Try to create collision (should be computationally infeasible)
        let mut hashes = std::collections::HashSet::new();
        
        for i in 0..10000 {
            let mut evidence = TechnicalEvidence::default();
            evidence.add_finding(Finding {
                value: format!("Finding {}", i),
                ..Default::default()
            });
            evidence.finalize();
            
            // All hashes should be unique
            assert!(hashes.insert(evidence.evidence_hash));
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Serialization
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
        
        // Serialize
        let bytes = evidence.to_bytes();
        
        // Deserialize
        let evidence2 = TechnicalEvidence::from_bytes(&bytes).unwrap();
        
        // Should be identical
        assert_eq!(evidence.evidence_hash, evidence2.evidence_hash);
        assert_eq!(evidence.finding_count, evidence2.finding_count);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // Benchmarks (criterion)
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
}