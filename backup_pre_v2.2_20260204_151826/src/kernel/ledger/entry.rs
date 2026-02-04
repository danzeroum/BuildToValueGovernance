
use blake3;
use std::time::{SystemTime, UNIX_EPOCH};

/// Entrada do ledger imutável (384 bytes fixos)
/// 
/// Cada entrada é ligada à anterior via hash (blockchain-like).
/// Não pode ser deletada ou modificada sem quebrar a cadeia.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct LedgerEntry {
    // === IDENTIFICAÇÃO (48 bytes) ===
    /// ID único da entrada (sequencial)
    pub entry_id: u64,
    
    /// ID do audit trail (correlação com TechnicalEvidence)
    pub audit_trail_id: u128,
    
    /// Timestamp (microssegundos desde epoch)
    pub timestamp: u128,
    
    // === CHAIN INTEGRITY (32 bytes) ===
    /// Hash da entrada anterior (chain-of-hashes)
    pub previous_entry_hash: u64,
    
    /// Hash do TechnicalEvidence
    pub evidence_hash: u64,
    
    /// Merkle root acumulado (todas entradas até aqui)
    pub merkle_root: u64,
    
    /// Reserved
    pub _padding1: [u8; 8],
    
    // === DECISÃO (64 bytes) ===
    /// Risco composto do evidence (0-255)
    pub composite_risk: u8,
    
    /// Ação executada
    pub action: ActionType,
    
    /// Confiança da decisão (0-255 = 0%-100%)
    pub decision_confidence: u8,
    
    /// Reserved
    pub _padding2: [u8; 5],
    
    /// Rationale (truncado para 128 bytes)
    /// Nota: Rationale completo fica no ExplanationStore
    pub rationale: [u8; 48],
    
    // === METADATA (128 bytes) ===
    /// Quem executou (ex: "rust_kernel_v1.5.0")
    pub executor: [u8; 32],
    
    /// Quem decidiu (ex: "python_gov_v2.0.0")
    pub decider: [u8; 32],
    
    /// Context domain (ex: "medical", "general")
    pub context_domain: [u8; 32],
    
    /// User role (ex: "patient", "anonymous")
    pub user_role: [u8; 32],
    
    // === ASSINATURA (64 bytes) ===
    /// HMAC-SHA256 da decisão
    pub signature: [u8; 32],
    
    /// Key version usado para assinar
    pub key_version: u32,
    
    /// Reserved
    pub _padding3: [u8; 28],
    
    // === CHECKSUM (48 bytes) ===
    /// BLAKE3 de toda a entrada (exceto este campo)
    pub entry_checksum: u64,
    
    /// Reserved para expansão
    pub _reserved: [u8; 40],
}

static_assertions::const_assert_eq!(
    std::mem::size_of::<LedgerEntry>(),
    384
);

impl LedgerEntry {
    /// Cria nova entrada do ledger
    pub fn new(
        entry_id: u64,
        audit_trail_id: u128,
        evidence: &TechnicalEvidence,
        verdict: &EthicalVerdict,
        previous_hash: u64,
    ) -> Self {
        let mut entry = Self {
            entry_id,
            audit_trail_id,
            timestamp: Self::now_micros(),
            previous_entry_hash: previous_hash,
            evidence_hash: evidence.evidence_hash,
            merkle_root: 0,  // Calculado depois
            _padding1: [0; 8],
            composite_risk: evidence.composite_risk,
            action: verdict.action,
            decision_confidence: (verdict.confidence * 255.0) as u8,
            _padding2: [0; 5],
            rationale: [0; 48],
            executor: [0; 32],
            decider: [0; 32],
            context_domain: [0; 32],
            user_role: [0; 32],
            signature: [0; 32],
            key_version: 1,
            _padding3: [0; 28],
            entry_checksum: 0,
            _reserved: [0; 40],
        };
        
        // Copia strings (truncadas se necessário)
        Self::copy_str_to_array(&mut entry.rationale, &verdict.rationale);
        Self::copy_str_to_array(&mut entry.executor, "rust_kernel_v1.5.0");
        Self::copy_str_to_array(&mut entry.decider, "python_gov_v2.0.0");
        Self::copy_str_to_array(&mut entry.context_domain, &verdict.context_domain);
        Self::copy_str_to_array(&mut entry.user_role, &verdict.user_role);
        
        // Copia assinatura
        entry.signature.copy_from_slice(&verdict.signature);
        
        entry
    }
    
    /// Calcula hash desta entrada (para chain)
    pub fn calculate_hash(&self) -> u64 {
        let mut hasher = blake3::Hasher::new();
        
        hasher.update(&self.entry_id.to_le_bytes());
        hasher.update(&self.audit_trail_id.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.previous_entry_hash.to_le_bytes());
        hasher.update(&self.evidence_hash.to_le_bytes());
        hasher.update(&self.composite_risk.to_le_bytes());
        hasher.update(&(self.action as u8).to_le_bytes());
        hasher.update(&self.signature);
        
        u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        )
    }
    
    /// Calcula Merkle root (hash acumulado)
    pub fn calculate_merkle_root(&mut self, previous_merkle: u64) {
        let current_hash = self.calculate_hash();
        
        let mut hasher = blake3::Hasher::new();
        hasher.update(&previous_merkle.to_le_bytes());
        hasher.update(&current_hash.to_le_bytes());
        
        self.merkle_root = u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        );
    }
    
    /// Finaliza entrada (calcula checksum)
    pub fn finalize(&mut self) {
        let mut hasher = blake3::Hasher::new();
        
        // Hash de tudo exceto entry_checksum e _reserved
        let bytes = self.to_bytes_without_checksum();
        hasher.update(&bytes);
        
        self.entry_checksum = u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        );
    }
    
    /// Valida integridade da entrada
    pub fn validate(&self) -> bool {
        let mut hasher = blake3::Hasher::new();
        let bytes = self.to_bytes_without_checksum();
        hasher.update(&bytes);
        
        let expected = u64::from_le_bytes(
            hasher.finalize().as_bytes()[0..8].try_into().unwrap()
        );
        
        self.entry_checksum == expected
    }
    
    /// Valida chain (hash anterior corresponde?)
    pub fn validate_chain(&self, previous: &LedgerEntry) -> bool {
        self.previous_entry_hash == previous.calculate_hash()
    }
    
    pub fn to_bytes(&self) -> [u8; 384] {
        unsafe {
            std::mem::transmute(*self)
        }
    }
    
    fn to_bytes_without_checksum(&self) -> [u8; 336] {
        let full = self.to_bytes();
        let mut without = [0u8; 336];
        without.copy_from_slice(&full[0..336]);
        without
    }
    
    fn copy_str_to_array(dest: &mut [u8], src: &str) {
        let bytes = src.as_bytes();
        let len = bytes.len().min(dest.len());
        dest[0..len].copy_from_slice(&bytes[0..len]);
    }
    
    fn now_micros() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros()
    }
}

/// ActionType (5 níveis de severidade)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    /// Permitir sem restrições
    ALLOW = 0,
    
    /// Permitir mas registrar
    LOG = 1,
    
    /// Permitir com aviso educativo
    EDUCATE = 2,
    
    /// Permitir mas reduzir resposta
    REDACT = 3,
    
    /// Bloquear completamente
    BLOCK = 4,
}

impl std::fmt::Debug for LedgerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rationale = std::str::from_utf8(&self.rationale)
            .unwrap_or("INVALID_UTF8")
            .trim_end_matches('\0');
        
        f.debug_struct("LedgerEntry")
            .field("entry_id", &format!("0x{:x}", self.entry_id))
            .field("audit_trail_id", &format!("0x{:x}", self.audit_trail_id))
            .field("action", &self.action)
            .field("composite_risk", &self.composite_risk)
            .field("rationale", &rationale)
            .finish()
    }
}