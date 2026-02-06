use crate::core::types::{ValidatorModule, TechnicalSeverity};
use blake3;
/// Finding individual (128 bytes fixos)
/// 
/// Representa uma violação detectada por um módulo específico.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Finding {
    // === IDENTIFICAÇÃO (32 bytes) ===
    /// Módulo que gerou o finding
    pub module: ValidatorModule,
    
    /// Severidade técnica
    pub severity: TechnicalSeverity,
    
    /// ID da regra violada (ex: "VALIDATORS_CPF_001")
    pub rule_id: [u8; 24],
    
    /// Reserved
    pub _padding1: [u8; 4],
    
    // === DETALHES (64 bytes) ===
    /// Título curto (ex: "CPF_PATTERN_DETECTED")
    pub title: [u8; 32],
    
    /// Descrição (ex: "Valid CPF pattern found in input")
    pub description: [u8; 32],
    
    // === CONTEXTO (24 bytes) ===
    /// Hash do texto que matchou (BLAKE3)
    pub matched_text_hash: u64,
    
    /// Confiança da detecção (0-255 = 0%-100%)
    pub confidence: u8,
    
    /// Posição no input onde foi encontrado
    pub position_start: u16,
    pub position_end: u16,
    
    /// Reserved
    pub _padding2: [u8; 9],
    
    // === CHECKSUM (8 bytes) ===
    pub checksum: u64,
}

static_assertions::const_assert_eq!(
    std::mem::size_of::<Finding>(),
    128
);

impl Finding {
    /// Cria finding vazio (para inicialização de arrays)
    pub const fn empty() -> Self {
        Self {
            module: ValidatorModule::Unknown,
            severity: TechnicalSeverity::Info,
            rule_id: [0; 24],
            _padding1: [0; 4],
            title: [0; 32],
            description: [0; 32],
            matched_text_hash: 0,
            confidence: 0,
            position_start: 0,
            position_end: 0,
            _padding2: [0; 9],
            checksum: 0,
        }
    }
    
    /// Cria novo finding
    pub fn new(
        module: ValidatorModule,
        severity: TechnicalSeverity,
        rule_id: &str,
        title: &str,
        description: &str,
    ) -> Self {
        let mut finding = Self::empty();
        finding.module = module;
        finding.severity = severity;
        
        // Copia strings com limite de tamanho
        Self::copy_str_to_array(&mut finding.rule_id, rule_id);
        Self::copy_str_to_array(&mut finding.title, title);
        Self::copy_str_to_array(&mut finding.description, description);
        
        finding.confidence = 255;  // 100% por padrão
        
        // Calcula checksum
        finding.checksum = finding.calculate_checksum();
        
        finding
    }
    
    /// Define texto matchado
    pub fn with_matched_text(mut self, text: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(text.as_bytes());
        self.matched_text_hash = u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        );
        self.checksum = self.calculate_checksum();
        self
    }
    
    /// Define posição
    pub fn with_position(mut self, start: u16, end: u16) -> Self {
        self.position_start = start;
        self.position_end = end;
        self.checksum = self.calculate_checksum();
        self
    }
    
    /// Define confiança
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence;
        self.checksum = self.calculate_checksum();
        self
    }
    
    /// Retorna confiança como float (0.0-1.0)
    pub fn get_confidence_f32(&self) -> f32 {
        self.confidence as f32 / 255.0
    }
    
    /// Serializa para bytes
    pub fn to_bytes(&self) -> [u8; 128] {
        unsafe {
            std::mem::transmute(*self)
        }
    }
    
    fn calculate_checksum(&self) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(self.module as u8).to_le_bytes());
        hasher.update(&(self.severity as u8).to_le_bytes());
        hasher.update(&self.rule_id);
        hasher.update(&self.title);
        hasher.update(&self.description);
        hasher.update(&self.matched_text_hash.to_le_bytes());
        hasher.update(&self.confidence.to_le_bytes());
        hasher.update(&self.position_start.to_le_bytes());
        hasher.update(&self.position_end.to_le_bytes());
        
        u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        )
    }
    
    fn copy_str_to_array(dest: &mut [u8], src: &str) {
        let bytes = src.as_bytes();
        let len = bytes.len().min(dest.len());
        dest[0..len].copy_from_slice(&bytes[0..len]);
    }
}

impl std::fmt::Debug for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rule_id = std::str::from_utf8(&self.rule_id)
            .unwrap_or("INVALID_UTF8")
            .trim_end_matches('\0');
        let title = std::str::from_utf8(&self.title)
            .unwrap_or("INVALID_UTF8")
            .trim_end_matches('\0');
        
        f.debug_struct("Finding")
            .field("module", &self.module)
            .field("severity", &self.severity)
            .field("rule_id", &rule_id)
            .field("title", &title)
            .field("confidence", &format!("{}%", self.confidence * 100 / 255))
            .finish()
    }
}