
use std::mem;
use blake3;

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
#[repr(C, align(8))]
pub struct TechnicalEvidence {
    // === HEADER (64 bytes) ===
    /// Versão do protocolo (para compatibilidade futura)
    pub protocol_version: u16,
    
    /// ID único desta evidência (correlação com ledger)
    pub audit_trail_id: u128,
    
    /// Timestamp de criação (microssegundos desde epoch)
    pub timestamp: u128,
    
    /// Hash BLAKE3 de toda a evidência (setado em finalize())
    pub evidence_hash: u64,
    
    /// Risco composto final (0-255)
    pub composite_risk: u8,
    
    /// Reserved para alinhamento
    pub _reserved: [u8; 7],
    
    // === FINDINGS NORMAIS (1280 bytes) ===
    /// Ring buffer de findings (10 slots de 128 bytes cada)
    pub findings: [Finding; 10],
    
    /// Número de findings válidos (0-10)
    pub finding_count: u8,
    
    /// Posição atual no ring buffer
    pub finding_position: u8,
    
    /// Padding
    pub _padding1: [u8; 6],
    
    // === FINDINGS CRÍTICOS (384 bytes) ===
    /// Critical findings preservados (não sobrescritos)
    pub critical: [Finding; 3],
    
    /// Número de critical findings (0-3)
    pub critical_count: u8,
    
    /// Padding
    pub _padding2: [u8; 7],
    
    // === STATISTICS (256 bytes) ===
    /// Estatísticas agregadas do input
    pub stats: InputStatistics,
    
    // === BIAS DECLARATION (512 bytes) ===
    /// Transparência sobre limitações do sistema
    pub bias: BiasDeclaration,
    
    // === METADATA (7040 bytes) ===
    /// Request original (hash)
    pub original_request_hash: u64,
    
    /// Tamanho do input processado
    pub input_size: u32,
    
    /// Flags de processamento
    pub processing_flags: u32,
    
    /// Módulos que executaram (bitmap)
    pub executed_modules: u64,
    
    /// Tempo total de processamento (microssegundos)
    pub processing_time_us: u64,
    
    /// Reserved para expansão futura
    pub _reserved_metadata: [u8; 7000],
    
    // === CHECKSUM FINAL (8 bytes) ===
    /// Checksum BLAKE3 de toda a estrutura
    pub checksum: u64,
}

// Garantia de tamanho em compile-time
static_assertions::const_assert_eq!(
    mem::size_of::<TechnicalEvidence>(),
    9596  // 9.4KB exatos
);

impl TechnicalEvidence {
    /// Cria nova evidência (inicializada com zeros)
    pub fn new(audit_trail_id: u128) -> Self {
        Self {
            protocol_version: 0x0201,  // v2.1
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
            _reserved_metadata: [0; 7000],
            checksum: 0,
        }
    }
    
    /// Adiciona finding (ring buffer para normais, preserva critical)
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
    pub fn calculate_composite_risk(&self) -> u8 {
        if self.finding_count == 0 && self.critical_count == 0 {
            return 0;
        }
        
        let mut total_severity: u32 = 0;
        let mut total_confidence: u32 = 0;
        
        // Findings normais
        for i in 0..self.finding_count as usize {
            let f = &self.findings[i];
            let severity_score = f.severity.to_score();
            total_severity += (severity_score as u32) * (f.confidence as u32);
            total_confidence += f.confidence as u32;
        }
        
        // Critical findings (peso dobrado)
        for i in 0..self.critical_count as usize {
            let f = &self.critical[i];
            let severity_score = f.severity.to_score();
            total_severity += (severity_score as u32) * (f.confidence as u32) * 2;
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
        hasher.update(&self.bias.to_bytes());
        
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
            .field("protocol_version", &self.protocol_version)
            .field("audit_trail_id", &format!("0x{:x}", self.audit_trail_id))
            .field("evidence_hash", &format!("0x{:x}", self.evidence_hash))
            .field("composite_risk", &self.composite_risk)
            .field("finding_count", &self.finding_count)
            .field("critical_count", &self.critical_count)
            .field("input_size", &self.input_size)
            .field("processing_time_us", &self.processing_time_us)
            .finish()
    }
}