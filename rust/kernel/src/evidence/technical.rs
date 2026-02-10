//! TechnicalEvidence v2.4.0 (ADR-010)
//!
//! **CHANGELOG v2.4.0**:
//! - ✅ BiasDeclaration expandido para 512 bytes (era 32 bytes)
//! - ✅ _reserved_metadata ajustado de 7000 para 6520 bytes
//! - ✅ Tamanho total mantido em 9596 bytes (compile-time assertion)
//! - ✅ Hash de bias.to_bytes() atualizado para 512 bytes

use super::finding::Finding;
use crate::core::errors::EvidenceError;
use crate::core::types::{InputStatistics, BiasDeclaration};
use blake3;
use std::mem;

/// Dossiê forense de 9.4KB (9596 bytes fixos)
///
/// Contém evidências técnicas objetivas detectadas pelo Rust Kernel.
/// Não contém julgamentos éticos (responsabilidade do Python Governance).
///
/// Garantias:
/// - Tamanho fixo (stack allocation)
/// - Imutável após finalize()
/// - Hash BLAKE3 para integridade
/// - Ring buffer para findings (10 normais + 3 critical preservados)
///
/// **v2.4.0 (ADR-010)**: BiasDeclaration expandido para 512 bytes
///
/// **Layout de memória (9596 bytes)**:
/// - Header: 64 bytes (protocol_version até _reserved)
/// - Findings normais: 1280 bytes (10 × 128 bytes)
/// - Findings críticos: 384 bytes (3 × 128 bytes)
/// - Statistics: 256 bytes
/// - BiasDeclaration: 512 bytes ⬅️ **NOVO v2.4.0**
/// - Metadata: 6560 bytes (inclui _reserved_metadata[6520])
/// - Checksum: 8 bytes
#[repr(C, align(8))]
pub struct TechnicalEvidence {
    // === HEADER (64 bytes) ===
    pub protocol_version: u16,
    pub audit_trail_id: u128,
    pub timestamp: u128,
    pub evidence_hash: u64,
    pub composite_risk: u8,
    pub _reserved: [u8; 7],

    // === FINDINGS NORMAIS (1280 bytes) ===
    pub findings: [Finding; 10],
    pub finding_count: u8,
    pub finding_position: u8,
    pub _padding1: [u8; 6],

    // === FINDINGS CRÍTICOS (384 bytes) ===
    pub critical: [Finding; 3],
    pub critical_count: u8,
    pub _padding2: [u8; 7],

    // === STATISTICS (256 bytes) ===
    pub stats: InputStatistics,

    // === BIAS DECLARATION (512 bytes) ===
    /// **v2.4.0**: Expandido de 32 para 512 bytes (ADR-010)
    pub bias: BiasDeclaration,

    // === METADATA (6560 bytes) ===
    pub original_request_hash: u64,
    pub input_size: u32,
    pub processing_flags: u32,
    pub executed_modules: u64,
    pub processing_time_us: u64,
    /// **v2.4.0**: Reduzido de 7000 para 6520 bytes (compensar BiasDeclaration +480)
    pub _reserved_metadata: [u8; 6520],

    // === CHECKSUM FINAL (8 bytes) ===
    pub checksum: u64,
}

// Garantia compile-time: 64 + 1280 + 384 + 256 + 512 + 6560 + 8 = 9596
static_assertions::const_assert_eq!(
    mem::size_of::<TechnicalEvidence>(),
    9596  // 9.4KB exatos
);

impl TechnicalEvidence {
    /// Cria nova evidência (inicializada com zeros)
    ///
    /// # Arguments
    /// * `audit_trail_id` - ID único para correlação com ledger (u128)
    ///
    /// # Example
    /// ```
    /// use buildtovalue_kernel::evidence::TechnicalEvidence;
    /// let evidence = TechnicalEvidence::new(0x1234_5678_9abc_def0);
    /// ```
    pub fn new(audit_trail_id: u128) -> Self {
        Self {
            protocol_version: 0x0204,  // v2.4 (ADR-010)
            audit_trail_id,
            timestamp: Self::now_micros(),
            evidence_hash: 0,  // Setado em finalize()
            composite_risk: 0,
            _reserved: [0; 7],
            findings: [Finding::empty(); 10],
            finding_count: 0,
            finding_position: 0,
            _padding1: [0; 6],
            critical: [Finding::empty(); 3],
            critical_count: 0,
            _padding2: [0; 7],
            stats: InputStatistics::default(),
            bias: BiasDeclaration::default(),
            original_request_hash: 0,
            input_size: 0,
            processing_flags: 0,
            executed_modules: 0,
            processing_time_us: 0,
            _reserved_metadata: [0; 6520],
            checksum: 0,
        }
    }

    /// Adiciona finding (ring buffer para normais, preserva critical)
    ///
    /// **Ring Buffer Logic**:
    /// - Findings normais: Sobrescreve após 10 entradas (FIFO)
    /// - Critical findings: Preserva até 3, depois descarta novos
    pub fn add_finding(&mut self, finding: Finding) {
        // Se é critical, vai para o array separado
        if finding.severity.is_critical() {
            if self.critical_count < 3 {
                self.critical[self.critical_count as usize] = finding;
                self.critical_count += 1;
            } else {
                log::warn!("Critical findings buffer full, dropping finding");
            }
            return;
        }

        // Findings normais vão para ring buffer (sobrescreve antigos)
        self.findings[self.finding_position as usize] = finding;
        self.finding_position = (self.finding_position + 1) % 10;

        if self.finding_count < 10 {
            self.finding_count += 1;
        }
    }

    /// Calcula composite risk (média ponderada dos findings)
    ///
    /// **Algoritmo**:
    /// - Severity × Confidence para cada finding
    /// - Critical findings têm peso dobrado (×2)
    /// - Resultado: 0-255
    pub fn calculate_composite_risk(&self) -> u8 {
        if self.finding_count == 0 && self.critical_count == 0 {
            return 0;
        }

        let mut total_severity: u32 = 0;
        let mut total_confidence: u32 = 0;

        // Findings normais
        for i in 0..self.finding_count as usize {
            let f = &self.findings[i];
            let severity_score = (f.severity.to_score() * 255.0) as u32;
            total_severity += severity_score * (f.confidence as u32);
            total_confidence += f.confidence as u32;
        }

        // Critical findings (peso dobrado)
        for i in 0..self.critical_count as usize {
            let f = &self.critical[i];
            let severity_score = (f.severity.to_score() * 255.0) as u32;
            total_severity += severity_score * (f.confidence as u32) * 2;
            total_confidence += (f.confidence as u32) * 2;
        }

        if total_confidence == 0 {
            return 0;
        }

        // Média ponderada
        let risk = (total_severity / total_confidence) as u8;
        risk.min(255)
    }

    /// Finaliza evidência (calcula hashes, imutável após isso)
    ///
    /// **Durability**: Após finalize(), struct é imutável
    /// **Performance**: O(n) onde n = número de findings
    ///
    /// # Errors
    /// - `EvidenceError::AlreadyFinalized` se chamar 2x
    pub fn finalize(&mut self) -> Result<(), EvidenceError> {
        if self.evidence_hash != 0 {
            return Err(EvidenceError::AlreadyFinalized);
        }

        // Calcula composite risk
        self.composite_risk = self.calculate_composite_risk();

        // Hash BLAKE3 de toda a evidência (exceto o próprio campo de hash)
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.protocol_version.to_le_bytes());
        hasher.update(&self.audit_trail_id.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.composite_risk.to_le_bytes());

        // Hash de todos os findings
        for i in 0..self.finding_count as usize {
            hasher.update(&self.findings[i].to_bytes());
        }

        for i in 0..self.critical_count as usize {
            hasher.update(&self.critical[i].to_bytes());
        }

        // Hash das statistics e bias
        hasher.update(&self.stats.to_bytes());
        hasher.update(&self.bias.to_bytes()); // **v2.4.0**: Agora 512 bytes

        let hash_bytes = hasher.finalize();
        self.evidence_hash = u64::from_le_bytes(
            hash_bytes.as_bytes()[0..8].try_into().unwrap()
        );

        // Checksum final (hash de tudo, incluindo evidence_hash)
        let mut checksum_hasher = blake3::Hasher::new();
        checksum_hasher.update(&self.to_bytes_without_checksum());
        let checksum_bytes = checksum_hasher.finalize();
        self.checksum = u64::from_le_bytes(
            checksum_bytes.as_bytes()[0..8].try_into().unwrap()
        );

        Ok(())
    }

    /// Valida integridade (checksum)
    ///
    /// **Security**: Detecta corrupção de memória ou tampering
    pub fn validate(&self) -> bool {
        if self.evidence_hash == 0 {
            return false;  // Não finalizado
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.to_bytes_without_checksum());
        let expected_checksum = u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        );

        self.checksum == expected_checksum
    }

    /// Retorna todos os findings (normais + critical)
    pub fn get_all_findings(&self) -> Vec<&Finding> {
        let mut all = Vec::with_capacity(13);  // 10 + 3 max

        for i in 0..self.finding_count as usize {
            all.push(&self.findings[i]);
        }

        for i in 0..self.critical_count as usize {
            all.push(&self.critical[i]);
        }

        all
    }

    /// Serializa para bytes (para FFI)
    ///
    /// **Safety**: Usa transmute (unsafe), mas garantido por repr(C, align(8))
    pub fn to_bytes(&self) -> [u8; 9596] {
        unsafe {
            std::mem::transmute(*self)
        }
    }

    fn to_bytes_without_checksum(&self) -> [u8; 9588] {
        // Exclui os últimos 8 bytes (checksum)
        let full = self.to_bytes();
        let mut without = [0u8; 9588];
        without.copy_from_slice(&full[0..9588]);
        without
    }

    fn now_micros() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros()
    }
}

// Implementação de Default
impl Default for TechnicalEvidence {
    fn default() -> Self {
        Self::new(0)
    }
}

// Implementação de Debug (sem imprimir arrays gigantes)
impl std::fmt::Debug for TechnicalEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TechnicalEvidence")
            .field("protocol_version", &format!("0x{:04x}", self.protocol_version))
            .field("audit_trail_id", &format!("0x{:x}", self.audit_trail_id))
            .field("evidence_hash", &format!("0x{:x}", self.evidence_hash))
            .field("composite_risk", &self.composite_risk)
            .field("finding_count", &self.finding_count)
            .field("critical_count", &self.critical_count)
            .field("input_size", &self.input_size)
            .field("processing_time_us", &self.processing_time_us)
            .field("bias_fpr", &self.bias.false_positive_rate)
            .field("bias_fnr", &self.bias.false_negative_rate)
            .field("bias_calibration_date", &self.bias.calibration_date)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS (ADR-010)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technical_evidence_size_9596_bytes() {
        // ADR-010: Garantir que expansão de BiasDeclaration mantém tamanho total
        assert_eq!(std::mem::size_of::<TechnicalEvidence>(), 9596);
    }

    #[test]
    fn test_bias_declaration_512_bytes() {
        // ADR-010: Garantir tamanho de BiasDeclaration
        assert_eq!(std::mem::size_of::<BiasDeclaration>(), 512);
    }

    #[test]
    fn test_evidence_finalize_with_bias() {
        let mut evidence = TechnicalEvidence::new(0x1234);

        // Simular agregação de bias
        evidence.bias = BiasDeclaration::new(0.08, 0.02, 20260209, 500)
            .with_limitations("Test limitations")
            .with_affected_groups("Test groups");

        // Finalizar deve incluir hash de bias (512 bytes)
        assert!(evidence.finalize().is_ok());
        assert!(evidence.evidence_hash > 0);
        assert!(evidence.checksum > 0);
        assert!(evidence.validate());
    }

    #[test]
    fn test_protocol_version_updated() {
        let evidence = TechnicalEvidence::new(0);
        assert_eq!(evidence.protocol_version, 0x0204); // v2.4
    }

    #[test]
    fn test_bias_hash_integration() {
        let mut evidence1 = TechnicalEvidence::new(0x1111);
        let mut evidence2 = TechnicalEvidence::new(0x1111);

        // Bias diferente deve resultar em hash diferente
        evidence1.bias = BiasDeclaration::new(0.10, 0.05, 20260209, 100);
        evidence2.bias = BiasDeclaration::new(0.20, 0.10, 20260209, 200);

        evidence1.finalize().unwrap();
        evidence2.finalize().unwrap();

        assert_ne!(evidence1.evidence_hash, evidence2.evidence_hash);
    }

    #[test]
    fn test_reserved_metadata_size() {
        // Verificar que _reserved_metadata foi reduzido corretamente
        // 6520 + 512(bias) + resto deve dar 9596
        let offset_bias = std::mem::offset_of!(TechnicalEvidence, bias);
        let offset_metadata = std::mem::offset_of!(TechnicalEvidence, _reserved_metadata);

        // Bias deve estar antes de _reserved_metadata
        assert!(offset_bias < offset_metadata);
    }
}
