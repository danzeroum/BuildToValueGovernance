use rand::Rng;

pub mod finding;
pub mod technical;

// Re-exports para facilitar acesso externo
// O 'pub use' já traz esses tipos para o escopo deste arquivo,
// então não precisamos de 'use crate::evidence::...' no topo.
pub use finding::Finding;
pub use technical::TechnicalEvidence;

impl TechnicalEvidence {
    /// Ofusca número exato de findings (previne statistical leakage)
    /// Retorna uma contagem aproximada ou randomizada dentro de um bucket seguro.
    pub fn obfuscated_finding_count(&self) -> u8 {
        let real_count = self.finding_count;

        // Agrupa em buckets (não revela número exato)
        if real_count == 0 {
            0
        } else if real_count <= 3 {
            rand::thread_rng().gen_range(1..=3)  // "Alguns"
        } else if real_count <= 7 {
            rand::thread_rng().gen_range(4..=7)  // "Vários"
        } else {
            rand::thread_rng().gen_range(8..=10) // "Muitos"
        }
    }

    /// Retorna findings em ordem aleatória (previne position leakage)
    /// Útil para quando a evidência é exposta externamente e a ordem
    /// não deve revelar qual validador rodou primeiro.
    pub fn shuffled_findings(&self) -> Vec<Finding> {
        // Clona os findings para um vetor
        let mut findings = self.get_all_findings()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();

        // Fisher-Yates shuffle
        let mut rng = rand::thread_rng();
        for i in (1..findings.len()).rev() {
            let j = rng.gen_range(0..=i);
            findings.swap(i, j);
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscation_buckets() {
        let mut evidence = TechnicalEvidence::new(0);

        // 0 findings -> sempre 0
        assert_eq!(evidence.obfuscated_finding_count(), 0);

        // Adiciona 2 findings
        evidence.finding_count = 2;
        let count = evidence.obfuscated_finding_count();
        assert!(count >= 1 && count <= 3);
    }
}