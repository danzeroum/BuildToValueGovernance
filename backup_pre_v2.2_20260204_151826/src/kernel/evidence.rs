
impl TechnicalEvidence {
    /// Ofusca número exato de findings (previne statistical leakage)
    pub fn obfuscated_finding_count(&self) -> u8 {
        let real_count = self.finding_count;
        
        // Agrupa em buckets (não revela número exato)
        if real_count == 0 {
            0
        } else if real_count <= 3 {
            rng::gen_range(1..=3)  // "Alguns"
        } else if real_count <= 7 {
            rng::gen_range(4..=7)  // "Vários"
        } else {
            rng::gen_range(8..=10) // "Muitos"
        }
    }
    
    /// Retorna findings em ordem aleatória (previne position leakage)
    pub fn shuffled_findings(&self) -> Vec<Finding> {
        let mut findings = self.get_all_findings();
        
        // Shuffle (Fisher-Yates)
        let mut rng = rand::thread_rng();
        for i in (1..findings.len()).rev() {
            let j = rng.gen_range(0..=i);
            findings.swap(i, j);
        }
        
        findings
    }
}