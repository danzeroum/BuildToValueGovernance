//! Core types for BuildToValue Kernel v2.1
//!
//! TechnicalEvidence v2.1 Specification:
//! - Fixed-size: 9.4KB (9600 bytes)
//! - Ring buffer: 10 findings + 3 critical
//! - BLAKE3 hash: 32 bytes
//! - Zero heap allocations in hot path
//!
//! Gate: Week 2 - Evidence Protocol

use serde::{Deserialize, Serialize};
use blake3::Hash;
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Tamanho máximo de findings normais (ring buffer)
pub const MAX_FINDINGS: usize = 10;

/// Tamanho máximo de findings críticos (sempre preservados)
pub const MAX_CRITICAL_FINDINGS: usize = 3;

/// Tamanho do hash BLAKE3 (256 bits)
pub const HASH_SIZE: usize = 32;

/// Tamanho máximo de cada finding (bytes)
pub const MAX_FINDING_SIZE: usize = 512;

/// Tamanho total do TechnicalEvidence (9.4KB)
pub const EVIDENCE_SIZE: usize = 9600;

// ═══════════════════════════════════════════════════════════════════════════
// RISK LEVEL
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RiskLevel {
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl RiskLevel {
    /// Converte float para RiskLevel
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s < 0.2 => RiskLevel::Safe,
            s if s < 0.4 => RiskLevel::Low,
            s if s < 0.6 => RiskLevel::Medium,
            s if s < 0.8 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
    
    /// Converte para float
    pub fn to_score(&self) -> f32 {
        match self {
            RiskLevel::Safe => 0.0,
            RiskLevel::Low => 0.3,
            RiskLevel::Medium => 0.5,
            RiskLevel::High => 0.7,
            RiskLevel::Critical => 0.95,
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Safe => write!(f, "SAFE"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING (Fixed-size)
// ═══════════════════════════════════════════════════════════════════════════

/// Finding de segurança (fixed-size: 512 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C, align(64))]  // Cache-line aligned
pub struct Finding {
    /// Título (64 bytes)
    pub title: [u8; 64],
    
    /// Descrição (256 bytes)
    pub description: [u8; 256],
    
    /// Categoria (32 bytes)
    pub category: [u8; 32],
    
    /// Localização (64 bytes)
    pub location: [u8; 64],
    
    /// Evidência (64 bytes)
    pub evidence: [u8; 64],
    
    /// Severidade (0.0-1.0)
    pub severity: f32,
    
    /// Confiança (0.0-1.0)
    pub confidence: f32,
    
    /// Timestamp (Unix epoch)
    pub timestamp: u64,
    
    /// Padding para chegar a 512 bytes
    _padding: [u8; 16],
}

impl Finding {
    /// Cria finding vazio
    pub fn empty() -> Self {
        Self {
            title: [0u8; 64],
            description: [0u8; 256],
            category: [0u8; 32],
            location: [0u8; 64],
            evidence: [0u8; 64],
            severity: 0.0,
            confidence: 0.0,
            timestamp: 0,
            _padding: [0u8; 16],
        }
    }
    
    /// Cria finding a partir de strings
    pub fn new(
        title: &str,
        description: &str,
        category: &str,
        location: &str,
        evidence: &str,
        severity: f32,
        confidence: f32,
    ) -> Self {
        let mut finding = Self::empty();
        
        // Copia strings (trunca se necessário)
        Self::copy_str(&mut finding.title, title);
        Self::copy_str(&mut finding.description, description);
        Self::copy_str(&mut finding.category, category);
        Self::copy_str(&mut finding.location, location);
        Self::copy_str(&mut finding.evidence, evidence);
        
        finding.severity = severity.clamp(0.0, 1.0);
        finding.confidence = confidence.clamp(0.0, 1.0);
        finding.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        finding
    }
    
    /// Helper para copiar string para array fixo
    fn copy_str(dest: &mut [u8], src: &str) {
        let bytes = src.as_bytes();
        let len = bytes.len().min(dest.len() - 1); // -1 para null terminator
        dest[..len].copy_from_slice(&bytes[..len]);
        dest[len] = 0; // Null terminator
    }
    
    /// Extrai string de array fixo
    pub fn get_str(bytes: &[u8]) -> &str {
        // Encontra null terminator
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..len]).unwrap_or("<invalid utf8>")
    }
    
    /// Verifica se finding está vazio
    pub fn is_empty(&self) -> bool {
        self.timestamp == 0
    }
    
    /// Calcula risk score
    pub fn risk_score(&self) -> f32 {
        self.severity * self.confidence
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// STATISTICS (Fixed-size)
// ═══════════════════════════════════════════════════════════════════════════

/// Estatísticas de entrada (fixed-size: 256 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C, align(64))]
pub struct Statistics {
    /// Entropia Shannon (0.0-8.0 bits)
    pub entropy: f32,
    
    /// Z-Score (desvio padrão)
    pub z_score: f32,
    
    /// Tamanho do input (bytes)
    pub input_size: u32,
    
    /// Contadores de caracteres especiais
    pub digit_count: u32,
    pub upper_count: u32,
    pub lower_count: u32,
    pub special_count: u32,
    pub whitespace_count: u32,
    
    /// Padrões detectados
    pub has_email: bool,
    pub has_url: bool,
    pub has_ip: bool,
    pub has_cpf: bool,
    pub has_cnpj: bool,
    pub has_credit_card: bool,
    
    /// Timestamp de cálculo
    pub computed_at: u64,
    
    /// Padding para 256 bytes
    _padding: [u8; 198],
}

impl Statistics {
    /// Cria statistics vazio
    pub fn empty() -> Self {
        Self {
            entropy: 0.0,
            z_score: 0.0,
            input_size: 0,
            digit_count: 0,
            upper_count: 0,
            lower_count: 0,
            special_count: 0,
            whitespace_count: 0,
            has_email: false,
            has_url: false,
            has_ip: false,
            has_cpf: false,
            has_cnpj: false,
            has_credit_card: false,
            computed_at: 0,
            _padding: [0u8; 198],
        }
    }
    
    /// Calcula statistics de texto
    pub fn from_text(text: &str) -> Self {
        let mut stats = Self::empty();
        
        stats.input_size = text.len() as u32;
        stats.computed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Conta caracteres
        for ch in text.chars() {
            if ch.is_ascii_digit() {
                stats.digit_count += 1;
            } else if ch.is_ascii_uppercase() {
                stats.upper_count += 1;
            } else if ch.is_ascii_lowercase() {
                stats.lower_count += 1;
            } else if ch.is_ascii_whitespace() {
                stats.whitespace_count += 1;
            } else {
                stats.special_count += 1;
            }
        }
        
        // Calcula entropia (Shannon)
        stats.entropy = Self::calculate_entropy(text);
        
        // Calcula Z-Score (normalizado)
        stats.z_score = Self::calculate_z_score(text);
        
        // Detecta padrões (regex básico)
        stats.has_email = text.contains('@') && text.contains('.');
        stats.has_url = text.contains("http://") || text.contains("https://");
        stats.has_ip = text.matches('.').count() == 3 && text.chars().filter(|c| c.is_ascii_digit()).count() > 6;
        
        stats
    }
    
    /// Calcula entropia de Shannon (bits)
    fn calculate_entropy(text: &str) -> f32 {
        if text.is_empty() {
            return 0.0;
        }
        
        // Conta frequências
        let mut freq = [0u32; 256];
        for byte in text.as_bytes() {
            freq[*byte as usize] += 1;
        }
        
        let len = text.len() as f32;
        let mut entropy = 0.0;
        
        for &count in freq.iter() {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
    
    /// Calcula Z-Score (desvio padrão normalizado)
    fn calculate_z_score(text: &str) -> f32 {
        if text.is_empty() {
            return 0.0;
        }
        
        // Média dos valores ASCII
        let sum: u32 = text.as_bytes().iter().map(|&b| b as u32).sum();
        let mean = sum as f32 / text.len() as f32;
        
        // Desvio padrão
        let variance: f32 = text.as_bytes()
            .iter()
            .map(|&b| {
                let diff = b as f32 - mean;
                diff * diff
            })
            .sum::<f32>() / text.len() as f32;
        
        let std_dev = variance.sqrt();
        
        // Z-Score (normalizado)
        if std_dev > 0.0 {
            (mean - 64.0) / std_dev  // 64 é média esperada de ASCII printable
        } else {
            0.0
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TECHNICAL EVIDENCE v2.1 (Fixed-size: 9.4KB)
// ═══════════════════════════════════════════════════════════════════════════

/// TechnicalEvidence v2.1 - Fixed-size structure
///
/// Layout:
/// - Header: 128 bytes
/// - Findings ring buffer: 10 × 512 = 5120 bytes
/// - Critical findings: 3 × 512 = 1536 bytes
/// - Statistics: 256 bytes
/// - Hash: 32 bytes
/// - Metadata: 64 bytes
/// - Padding: 2464 bytes
/// TOTAL: 9600 bytes (9.4KB)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C, align(4096))]  // Page-aligned
pub struct TechnicalEvidence {
    // ═══ HEADER (128 bytes) ═══
    /// Versão do protocolo
    pub version: u32,
    
    /// Timestamp de criação (Unix epoch)
    pub timestamp: u64,
    
    /// Composite risk score (0.0-1.0)
    pub composite_risk: f32,
    
    /// Risk level enum
    pub risk_level: RiskLevel,
    
    /// Número de findings ativos
    pub finding_count: u8,
    
    /// Número de findings críticos ativos
    pub critical_count: u8,
    
    /// Índice do próximo finding no ring buffer
    pub ring_index: u8,
    
    /// Flags de status
    pub flags: u32,
    
    /// Padding do header
    _header_padding: [u8; 99],
    
    // ═══ FINDINGS (10 × 512 = 5120 bytes) ═══
    /// Ring buffer de findings (10 slots)
    pub findings: [Finding; MAX_FINDINGS],
    
    // ═══ CRITICAL FINDINGS (3 × 512 = 1536 bytes) ═══
    /// Findings críticos (sempre preservados)
    pub critical: [Finding; MAX_CRITICAL_FINDINGS],
    
    // ═══ STATISTICS (256 bytes) ═══
    /// Estatísticas do input
    pub stats: Statistics,
    
    // ═══ HASH (32 bytes) ═══
    /// Hash BLAKE3 do conteúdo (integridade)
    pub hash: [u8; HASH_SIZE],
    
    // ═══ METADATA (64 bytes) ═══
    /// ID da sessão
    pub session_id: [u8; 16],
    
    /// ID do request
    pub request_id: [u8; 16],
    
    /// Reserved para futuro uso
    _reserved: [u8; 32],
    
    // ═══ PADDING (2464 bytes para completar 9.4KB) ═══
    _padding: [u8; 2464],
}

impl TechnicalEvidence {
    /// Versão atual do protocolo
    pub const VERSION: u32 = 2;
    
    /// Tamanho fixo (9.4KB)
    pub const SIZE: usize = EVIDENCE_SIZE;
    
    /// Cria evidence vazio
    pub fn new() -> Self {
        Self {
            version: Self::VERSION,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            composite_risk: 0.0,
            risk_level: RiskLevel::Safe,
            finding_count: 0,
            critical_count: 0,
            ring_index: 0,
            flags: 0,
            _header_padding: [0u8; 99],
            findings: [Finding::empty(); MAX_FINDINGS],
            critical: [Finding::empty(); MAX_CRITICAL_FINDINGS],
            stats: Statistics::empty(),
            hash: [0u8; HASH_SIZE],
            session_id: [0u8; 16],
            request_id: [0u8; 16],
            _reserved: [0u8; 32],
            _padding: [0u8; 2464],
        }
    }
    
    /// Adiciona finding (ring buffer)
    pub fn add_finding(&mut self, finding: Finding) {
        // Se crítico, adiciona ao array de críticos
        if finding.severity >= 0.8 && self.critical_count < MAX_CRITICAL_FINDINGS as u8 {
            self.critical[self.critical_count as usize] = finding.clone();
            self.critical_count += 1;
        }
        
        // Adiciona ao ring buffer
        let idx = self.ring_index as usize;
        self.findings[idx] = finding;
        
        // Avança índice (circular)
        self.ring_index = ((self.ring_index as usize + 1) % MAX_FINDINGS) as u8;
        
        // Atualiza contador (max 10)
        if self.finding_count < MAX_FINDINGS as u8 {
            self.finding_count += 1;
        }
        
        // Recalcula risk
        self.recalculate_risk();
    }
    
    /// Recalcula composite risk score
    pub fn recalculate_risk(&mut self) {
        let mut total_risk = 0.0;
        let mut count = 0;
        
        // Risk dos findings normais
        for finding in &self.findings {
            if !finding.is_empty() {
                total_risk += finding.risk_score();
                count += 1;
            }
        }
        
        // Risk dos críticos (peso 2x)
        for finding in &self.critical {
            if !finding.is_empty() {
                total_risk += finding.risk_score() * 2.0;
                count += 2;
            }
        }
        
        // Média ponderada
        if count > 0 {
            self.composite_risk = (total_risk / count as f32).clamp(0.0, 1.0);
        } else {
            self.composite_risk = 0.0;
        }
        
        self.risk_level = RiskLevel::from_score(self.composite_risk);
    }
    
    /// Calcula hash BLAKE3 do conteúdo
    pub fn calculate_hash(&mut self) {
        let mut hasher = blake3::Hasher::new();
        
        // Hash do header (exceto o próprio hash)
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.composite_risk.to_le_bytes());
        
        // Hash dos findings
        for finding in &self.findings {
            if !finding.is_empty() {
                hasher.update(&finding.title);
                hasher.update(&finding.description);
                hasher.update(&finding.severity.to_le_bytes());
            }
        }
        
        // Hash dos críticos
        for finding in &self.critical {
            if !finding.is_empty() {
                hasher.update(&finding.title);
                hasher.update(&finding.severity.to_le_bytes());
            }
        }
        
        // Hash das stats
        hasher.update(&self.stats.entropy.to_le_bytes());
        hasher.update(&self.stats.input_size.to_le_bytes());
        
        let hash = hasher.finalize();
        self.hash.copy_from_slice(hash.as_bytes());
    }
    
    /// Valida integridade via hash
    pub fn validate_hash(&self) -> bool {
        let mut temp = self.clone();
        temp.hash = [0u8; HASH_SIZE];
        temp.calculate_hash();
        
        // Constant-time comparison
        let mut result = 0u8;
        for (a, b) in self.hash.iter().zip(temp.hash.iter()) {
            result |= a ^ b;
        }
        
        result == 0
    }
    
    /// Retorna findings ativos (não vazios)
    pub fn active_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| !f.is_empty())
            .collect()
    }
    
    /// Retorna findings críticos ativos
    pub fn active_critical(&self) -> Vec<&Finding> {
        self.critical
            .iter()
            .filter(|f| !f.is_empty())
            .collect()
    }
}

impl Default for TechnicalEvidence {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPILE-TIME SIZE VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

// Garante que TechnicalEvidence tem exatamente 9.4KB
const _: () = assert!(
    std::mem::size_of::<TechnicalEvidence>() == EVIDENCE_SIZE,
    "TechnicalEvidence must be exactly 9.4KB (9600 bytes)"
);

// Garante que Finding tem 512 bytes
const _: () = assert!(
    std::mem::size_of::<Finding>() == MAX_FINDING_SIZE,
    "Finding must be exactly 512 bytes"
);

// Garante que Statistics tem 256 bytes
const _: () = assert!(
    std::mem::size_of::<Statistics>() == 256,
    "Statistics must be exactly 256 bytes"
);
