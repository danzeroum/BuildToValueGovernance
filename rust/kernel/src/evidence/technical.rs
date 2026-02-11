//! Technical Evidence v2.4.0
//!
//! Estrutura central que representa a evidência técnica coletada durante uma validação.
//! Tamanho fixo (9.6KB) para alocação stack e serialização direta.

use serde::{Deserialize, Serialize};
use crate::core::types::{
    ValidatorModule, TechnicalSeverity, RiskLevel, BiasDeclaration,
    InputStatistics, MAX_FINDINGS, MAX_CRITICAL_FINDINGS, HASH_SIZE, EVIDENCE_SIZE
};
use crate::evidence::Finding;

/// Evidência Técnica (9.6KB fixos)
///
/// Contém todos os findings, estatísticas e metadados de uma validação.
/// Layout de memória fixo para permitir serialização direta e FFI seguro.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct TechnicalEvidence {
    // === METADADOS (24 bytes) ===
    pub version: u32,                    // 4 bytes
    pub timestamp: u128,                 // 16 bytes (microssegundos UNIX)
    pub audit_trail_id: u128,            // 16 bytes (UUID v7 ou similar)
    pub processing_time_us: u64,         // 8 bytes
    pub input_size: u32,                 // 4 bytes
    pub original_request_hash: u64,      // 8 bytes (primeiros 8 bytes do BLAKE3 do input)

    // === ESTATÍSTICAS (32 bytes) ===
    pub stats: InputStatistics,          // 32 bytes

    // === VIÉS (512 bytes) ===
    pub bias: BiasDeclaration,           // 512 bytes

    // === FINDINGS (1440 bytes) ===
    pub findings: [Finding; MAX_FINDINGS], // 10 * 144 = 1440 bytes
    pub critical_findings: [Finding; MAX_CRITICAL_FINDINGS], // 3 * 144 = 432 bytes

    // === CONTAGENS E NÍVEIS (16 bytes) ===
    pub finding_count: u8,               // 1 byte
    pub critical_count: u8,              // 1 byte
    pub risk_level: RiskLevel,           // 1 byte
    pub composite_risk: f32,             // 4 bytes
    pub executed_modules: u8,            // 1 byte (bitmask)
    pub _reserved: [u8; 8],              // 8 bytes (alinhamento)

    // === INTEGRIDADE (32 bytes) ===
    pub hash: [u8; HASH_SIZE],           // 32 bytes (BLAKE3 do conteúdo acima)
}

// Garantia de tamanho em compile-time
static_assertions::const_assert_eq!(std::mem::size_of::<TechnicalEvidence>(), EVIDENCE_SIZE);

impl TechnicalEvidence {
    /// Cria uma nova evidência técnica com o ID de trilha de auditoria fornecido.
    pub fn new(audit_trail_id: u128) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros();

        Self {
            version: 2,
            timestamp: now,
            audit_trail_id,
            processing_time_us: 0,
            input_size: 0,
            original_request_hash: 0,
            stats: InputStatistics::empty(),
            bias: BiasDeclaration::default(),
            findings: [Finding::empty(); MAX_FINDINGS],
            critical_findings: [Finding::empty(); MAX_CRITICAL_FINDINGS],
            finding_count: 0,
            critical_count: 0,
            risk_level: RiskLevel::Safe,
            composite_risk: 0.0,
            executed_modules: 0,
            _reserved: [0; 8],
            hash: [0; HASH_SIZE],
        }
    }

    /// Adiciona um finding à evidência.
    /// Se o finding for crítico, vai para o array de críticos (até 3).
    /// Caso contrário, vai para o array normal (ring buffer de 10).
    pub fn add_finding(&mut self, finding: Finding) {
        if finding.severity.is_critical() {
            // Adiciona ao array de críticos (substitui o mais antigo se cheio)
            let idx = self.critical_count as usize;
            if idx < MAX_CRITICAL_FINDINGS {
                self.critical_findings[idx] = finding;
                self.critical_count += 1;
            } else {
                // Substitui o mais antigo (simplesmente rotaciona)
                self.critical_findings.rotate_left(1);
                self.critical_findings[MAX_CRITICAL_FINDINGS - 1] = finding;
            }
        } else {
            // Adiciona ao array normal (ring buffer)
            let idx = self.finding_count as usize;
            if idx < MAX_FINDINGS {
                self.findings[idx] = finding;
                self.finding_count += 1;
            } else {
                self.findings.rotate_left(1);
                self.findings[MAX_FINDINGS - 1] = finding;
            }
        }

        // Atualiza o risco composto (simplificado)
        self.update_risk_score();
    }

    /// Atualiza o score de risco baseado nos findings atuais.
    fn update_risk_score(&mut self) {
        let mut total_score = 0.0;
        let mut count = 0;

        for i in 0..self.finding_count as usize {
            total_score += self.findings[i].severity.to_score();
            count += 1;
        }
        for i in 0..self.critical_count as usize {
            total_score += self.critical_findings[i].severity.to_score();
            count += 1;
        }

        self.composite_risk = if count > 0 {
            total_score / count as f32
        } else {
            0.0
        };

        self.risk_level = RiskLevel::from_score(self.composite_risk);
    }

    /// Retorna todos os findings (normais + críticos) como um slice.
    pub fn get_all_findings(&self) -> Vec<&Finding> {
        let mut all = Vec::new();
        for i in 0..self.finding_count as usize {
            all.push(&self.findings[i]);
        }
        for i in 0..self.critical_count as usize {
            all.push(&self.critical_findings[i]);
        }
        all
    }

    /// Calcula o hash BLAKE3 da evidência (excluindo o campo hash)
    pub fn calculate_hash(&self) -> [u8; HASH_SIZE] {
        use blake3::Hasher;

        let mut hasher = Hasher::new();

        // Metadados
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.audit_trail_id.to_le_bytes());
        hasher.update(&self.processing_time_us.to_le_bytes());
        hasher.update(&self.input_size.to_le_bytes());
        hasher.update(&self.original_request_hash.to_le_bytes());

        // Estatísticas
        hasher.update(&self.stats.to_bytes());

        // Viés
        hasher.update(&self.bias.to_bytes());

        // Findings
        for i in 0..self.finding_count as usize {
            hasher.update(&self.findings[i].to_bytes());
        }
        for i in 0..self.critical_count as usize {
            hasher.update(&self.critical_findings[i].to_bytes());
        }

        // Contagens e níveis
        hasher.update(&[self.finding_count]);
        hasher.update(&[self.critical_count]);
        hasher.update(&[self.risk_level as u8]);
        hasher.update(&self.composite_risk.to_le_bytes());
        hasher.update(&[self.executed_modules]);
        hasher.update(&self._reserved);

        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(hasher.finalize().as_bytes());
        hash
    }

    /// Finaliza a evidência, calculando e armazenando o hash.
    pub fn finalize(&mut self) -> Result<(), crate::core::errors::EvidenceError> {
        self.hash = self.calculate_hash();
        Ok(())
    }

    /// Valida a integridade da evidência comparando o hash armazenado com o calculado.
    pub fn validate_hash(&self) -> bool {
        let computed = self.calculate_hash();
        computed == self.hash
    }

    /// Serializa a evidência para um array de bytes de tamanho fixo.
    pub fn to_bytes(&self) -> [u8; EVIDENCE_SIZE] {
        unsafe {
            let mut bytes = [0u8; EVIDENCE_SIZE];
            let ptr = self as *const TechnicalEvidence as *const u8;
            std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), std::mem::size_of::<TechnicalEvidence>());
            bytes
        }
    }

    /// Desserializa a evidência a partir de um array de bytes.
    pub fn from_bytes(bytes: &[u8; EVIDENCE_SIZE]) -> Option<Self> {
        if bytes.len() == EVIDENCE_SIZE {
            unsafe {
                let ptr = bytes.as_ptr() as *const TechnicalEvidence;
                Some(std::ptr::read_unaligned(ptr))
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_size() {
        assert_eq!(std::mem::size_of::<TechnicalEvidence>(), EVIDENCE_SIZE);
    }

    #[test]
    fn test_add_finding() {
        let mut evidence = TechnicalEvidence::new(12345);
        let finding = Finding::new(
            ValidatorModule::CPF,
            TechnicalSeverity::High,
            "CPF_001",
            "PII",
            "123.456.789-09",
        );

        evidence.add_finding(finding);
        assert_eq!(evidence.finding_count, 1);
        assert!(evidence.composite_risk > 0.0);
    }

    #[test]
    fn test_hash_integrity() {
        let mut evidence = TechnicalEvidence::new(12345);
        evidence.finalize().unwrap();
        assert!(evidence.validate_hash());
    }
}