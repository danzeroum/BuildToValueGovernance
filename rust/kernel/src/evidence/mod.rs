use rand::Rng;

pub mod finding;
pub mod technical;

pub use finding::Finding;
pub use technical::TechnicalEvidence;

impl TechnicalEvidence {
    /// Ofusca número exato de findings (previne statistical leakage)
    pub fn obfuscated_finding_count(&self) -> u8 {
        let real_count = self.finding_count;

        if real_count == 0 {
            0
        } else if (1..=3).contains(&real_count) {
            rand::thread_rng().gen_range(1..=3)
        } else if (4..=7).contains(&real_count) {
            rand::thread_rng().gen_range(4..=7)
        } else {
            rand::thread_rng().gen_range(8..=10)
        }
    }

    /// Retorna findings em ordem aleatória (previne position leakage)
    pub fn shuffled_findings(&self) -> Vec<Finding> {
        let mut findings = self.get_all_findings()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();

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

        assert_eq!(evidence.obfuscated_finding_count(), 0);

        evidence.finding_count = 2;
        let count = evidence.obfuscated_finding_count();
        assert!((1..=3).contains(&count));
    }
}
