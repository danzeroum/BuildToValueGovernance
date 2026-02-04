
use buildtovalue::kernel::ledger::{LedgerEntry, DurableLedger, ActionType};
use buildtovalue::kernel::evidence::TechnicalEvidence;
use std::path::PathBuf;

#[test]
fn test_ledger_entry_creation() {
    let evidence = TechnicalEvidence::new(0x1234);
    let verdict = create_mock_verdict();
    
    let mut entry = LedgerEntry::new(
        1,
        0x1234,
        &evidence,
        &verdict,
        0, // previous_hash
    );
    
    assert_eq!(entry.entry_id, 1);
    assert_eq!(entry.audit_trail_id, 0x1234);
    assert_eq!(entry.action, ActionType::BLOCK);
}

#[test]
fn test_ledger_chain_of_hashes() {
    let mut ledger = DurableLedger::new(PathBuf::from("/tmp/test_ledger.dat")).unwrap();
    
    // Adiciona 3 entries
    let evidence1 = TechnicalEvidence::new(0x1001);
    let verdict1 = create_mock_verdict();
    ledger.append(create_entry(1, &evidence1, &verdict1)).unwrap();
    
    let evidence2 = TechnicalEvidence::new(0x1002);
    let verdict2 = create_mock_verdict();
    ledger.append(create_entry(2, &evidence2, &verdict2)).unwrap();
    
    let evidence3 = TechnicalEvidence::new(0x1003);
    let verdict3 = create_mock_verdict();
    ledger.append(create_entry(3, &evidence3, &verdict3)).unwrap();
    
    // Valida chain
    let entries = ledger.get_all_entries();
    
    // Entry 2 deve referenciar hash de Entry 1
    assert_eq!(entries [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/a8bf2d44-ead0-43f2-99b4-cf572fdbfb91/paste.txt).previous_entry_hash, entries[0].calculate_hash());
    
    // Entry 3 deve referenciar hash de Entry 2
    assert_eq!(entries [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/27869fa6-8980-4131-823b-4192beed20b2/ARCHITECTURE_pt.md).previous_entry_hash, entries [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/a8bf2d44-ead0-43f2-99b4-cf572fdbfb91/paste.txt).calculate_hash());
}

#[test]
fn test_ledger_chain_break_detection() {
    let mut ledger = DurableLedger::new(PathBuf::from("/tmp/test_ledger2.dat")).unwrap();
    
    let evidence1 = TechnicalEvidence::new(0x1001);
    let verdict1 = create_mock_verdict();
    let mut entry1 = create_entry(1, &evidence1, &verdict1);
    entry1.finalize();
    
    ledger.append(entry1.clone()).unwrap();
    
    // Adiciona entry2 com hash anterior ERRADO
    let evidence2 = TechnicalEvidence::new(0x1002);
    let verdict2 = create_mock_verdict();
    let mut entry2 = create_entry(2, &evidence2, &verdict2);
    entry2.previous_entry_hash = 0xDEADBEEF; // Hash inválido!
    entry2.finalize();
    
    ledger.append(entry2.clone()).unwrap();
    
    // Valida chain
    assert!(!entry2.validate_chain(&entry1)); // Deve falhar
}

#[test]
fn test_ledger_wal_behavior() {
    use buildtovalue::kernel::ledger::WriteAheadLog;
    
    let wal = WriteAheadLog::new(100);
    
    // Adiciona entries
    for i in 0..50 {
        let evidence = TechnicalEvidence::new(i);
        let verdict = create_mock_verdict();
        let entry = create_entry(i, &evidence, &verdict);
        wal.append(entry).unwrap();
    }
    
    let stats = wal.stats();
    assert_eq!(stats.current_size, 50);
    assert_eq!(stats.total_appends, 50);
    assert_eq!(stats.utilization, 0.5); // 50/100
}

#[test]
fn test_ledger_wal_overflow() {
    use buildtovalue::kernel::ledger::WriteAheadLog;
    
    let wal = WriteAheadLog::new(10); // Capacidade: 10
    
    // Adiciona 15 entries (excede)
    for i in 0..15 {
        let evidence = TechnicalEvidence::new(i);
        let verdict = create_mock_verdict();
        let entry = create_entry(i, &evidence, &verdict);
        wal.append(entry).unwrap();
    }
    
    let stats = wal.stats();
    assert_eq!(stats.current_size, 10); // Limitado
    assert_eq!(stats.total_appends, 15); // Contador correto
}

#[test]
fn test_ledger_merkle_root() {
    let mut ledger = DurableLedger::new(PathBuf::from("/tmp/test_merkle.dat")).unwrap();
    
    // Adiciona 3 entries
    for i in 1..=3 {
        let evidence = TechnicalEvidence::new(i);
        let verdict = create_mock_verdict();
        let entry = create_entry(i, &evidence, &verdict);
        ledger.append(entry).unwrap();
    }
    
    let entries = ledger.get_all_entries();
    
    // Merkle root deve ser acumulativo
    assert_ne!(entries[0].merkle_root, 0);
    assert_ne!(entries [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/a8bf2d44-ead0-43f2-99b4-cf572fdbfb91/paste.txt).merkle_root, entries[0].merkle_root);
    assert_ne!(entries [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/27869fa6-8980-4131-823b-4192beed20b2/ARCHITECTURE_pt.md).merkle_root, entries [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/a8bf2d44-ead0-43f2-99b4-cf572fdbfb91/paste.txt).merkle_root);
}

#[test]
fn test_ledger_persistence() {
    let path = PathBuf::from("/tmp/test_persistence.dat");
    
    // Cria ledger e adiciona entries
    {
        let mut ledger = DurableLedger::new(path.clone()).unwrap();
        
        for i in 1..=5 {
            let evidence = TechnicalEvidence::new(i);
            let verdict = create_mock_verdict();
            let entry = create_entry(i, &evidence, &verdict);
            ledger.append(entry).unwrap();
        }
        
        // Flush explícito
        ledger.flush().unwrap();
    } // ledger dropped
    
    // Recarrega ledger
    let ledger2 = DurableLedger::open(path).unwrap();
    let entries = ledger2.get_all_entries();
    
    // Valida que entries foram persistidos
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].entry_id, 1);
    assert_eq!(entries [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/5a044da7-0dac-4c98-89de-b104970a0d29/README.md).entry_id, 5);
}

#[test]
fn test_ledger_recovery() {
    let path = PathBuf::from("/tmp/test_recovery.dat");
    
    // Simula crash após 3 entries no WAL (não flushed)
    {
        let mut ledger = DurableLedger::new(path.clone()).unwrap();
        
        for i in 1..=3 {
            let evidence = TechnicalEvidence::new(i);
            let verdict = create_mock_verdict();
            let entry = create_entry(i, &evidence, &verdict);
            ledger.append(entry).unwrap();
        }
        
        // NÃO chama flush (simula crash)
    }
    
    // Recovery
    let ledger2 = DurableLedger::recover(path).unwrap();
    
    // WAL entries devem ser recuperados
    let entries = ledger2.get_all_entries();
    assert_eq!(entries.len(), 3);
}

// Helper functions
fn create_mock_verdict() -> EthicalVerdict {
    EthicalVerdict {
        action: ActionType::BLOCK,
        rationale: "Test verdict".to_string(),
        confidence: 0.95,
        evidence_id: "0x1234".to_string(),
        evidence_hash: 0xABCD,
        rule_id: Some("TEST_RULE".to_string()),
        context_domain: "general".to_string(),
        user_role: "anonymous".to_string(),
        signature: vec![0u8; 32],
        context_factors: HashMap::new(),
        trust_score: 0.5,
        mercy_score: 0.0,
    }
}

fn create_entry(
    id: u64,
    evidence: &TechnicalEvidence,
    verdict: &EthicalVerdict,
) -> LedgerEntry {
    LedgerEntry::new(id, evidence.audit_trail_id, evidence, verdict, 0)
}