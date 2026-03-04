//! Testes PROP-031 — Skill Provenance Ledger

#[cfg(test)]
mod tests {
    use buildtovalue_kernel::evidence::TechnicalEvidence;
    use buildtovalue_kernel::core::types::EVIDENCE_SIZE;
    use std::mem::size_of;

    #[test]
    fn test_skill_hash_default_is_zeros() {
        let ev = TechnicalEvidence::new(1);
        assert!(!ev.has_skill_hash());
    }

    #[test]
    fn test_set_and_get_skill_hash() {
        let mut ev = TechnicalEvidence::new(2);
        let hash = [0xABu8; 32];
        ev.set_skill_hash(&hash);
        assert!(ev.has_skill_hash());
        assert_eq!(ev.get_skill_hash(), &hash);
    }

    #[test]
    fn test_skill_hash_does_not_affect_evidence_size() {
        assert_eq!(size_of::<TechnicalEvidence>(), EVIDENCE_SIZE);
    }

    #[test]
    fn test_skill_hash_layout_offset() {
        let mut ev = TechnicalEvidence::new(3);
        let sentinel = [0xFFu8; 32];
        ev.set_skill_hash(&sentinel);
        // [0..8] pattern_epoch (ADR-033) não tocado
        assert_eq!(&ev._reserved_metadata[0..8], &[0u8; 8]);
        // [40..] não tocado
        assert_eq!(ev._reserved_metadata[40], 0u8);
    }

    #[test]
    fn test_skill_hash_preserved_after_finalize() {
        let mut ev = TechnicalEvidence::new(4);
        let hash = [0x42u8; 32];
        ev.set_skill_hash(&hash);
        ev.finalize().unwrap();
        assert_eq!(ev.get_skill_hash(), &hash);
        assert!(ev.validate_hash());
    }
}
