
use quickcheck::{quickcheck, TestResult};
use buildtovalue::kernel::ledger::*;

quickcheck! {
    /// Property: Chain de hashes é transitiva
    fn prop_chain_transitivity(entry_count: u8) -> TestResult {
        if entry_count < 2 || entry_count > 50 {
            return TestResult::discard();
        }
        
        let entries = create_chain_of_entries(entry_count as usize);
        
        // Valida que cada entry aponta para anterior
        for i in 1..entries.len() {
            if !entries[i].validate_chain(&entries[i-1]) {
                return TestResult::failed();
            }
        }
        
        TestResult::passed()
    }
    
    /// Property: Quebra de chain é detectada
    fn prop_chain_break_detection(
        entry_count: u8,
        break_index: usize
    ) -> TestResult {
        if entry_count < 3 || entry_count > 20 {
            return TestResult::discard();
        }
        
        if break_index >= entry_count as usize {
            return TestResult::discard();
        }
        
        let mut entries = create_chain_of_entries(entry_count as usize);
        
        // Quebra chain (modifica hash anterior)
        entries[break_index].previous_entry_hash = 0xDEADBEEF;
        entries[break_index].finalize();
        
        // Validação do entry seguinte deve falhar
        if break_index < entries.len() - 1 {
            TestResult::from_bool(!entries[break_index + 1].validate_chain(&entries[break_index]))
        } else {
            TestResult::passed()
        }
    }
    
    /// Property: Merkle root é acumulativo
    fn prop_merkle_root_accumulative(entry_count: u8) -> TestResult {
        if entry_count < 2 || entry_count > 30 {
            return TestResult::discard();
        }
        
        let entries = create_chain_of_entries(entry_count as usize);
        
        // Merkle roots devem ser todos diferentes (acumulativos)
        let mut merkle_roots: Vec<u64> = entries.iter()
            .map(|e| e.merkle_root)
            .collect();
        
        merkle_roots.dedup();
        
        // Se todos são diferentes, dedup não muda tamanho
        TestResult::from_bool(merkle_roots.len() == entries.len())
    }
}