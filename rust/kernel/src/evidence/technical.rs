//! Technical Evidence v2.5.1 – 9632 bytes fixos (EVIDENCE_SIZE, ADR-044).
//! ADR-017: executed_modules expandido de u8 para u32.
//! Wire 4: _reserved_metadata[41..73] = skill_mac_tag (PROP-031/supply_guard).

use serde::{Deserialize, Serialize};
use std::mem::size_of;
use crate::core::types::{
    BiasDeclaration, InputStatistics, RiskLevel,
    MAX_CRITICAL_FINDINGS, MAX_FINDINGS, HASH_SIZE, EVIDENCE_SIZE,
};
use crate::evidence::Finding;

mod serde_reserved {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(arr: &[u8; 7072], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(arr)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 7072], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let mut arr = [0u8; 7072];
        let len = bytes.len().min(7072);
        arr[..len].copy_from_slice(&bytes[..len]);
        Ok(arr)
    }
}

#[must_use = "TechnicalEvidence must be used or logged — do not discard audit data"]
#[derive(Debug, Serialize, Deserialize)]
#[repr(C, align(8))]
pub struct TechnicalEvidence {
    // === METADADOS (64 bytes) ===
    pub version: u32,
    pub timestamp: u128,
    pub audit_trail_id: u128,
    pub processing_time_us: u64,
    pub input_size: u32,
    pub original_request_hash: u64,
    pub _pad_metadata: [u8; 8],

    // === ESTATÍSTICAS (32 bytes) ===
    pub stats: InputStatistics,

    // === VIÉS (512 bytes) ===
    pub bias: BiasDeclaration,

    // === FINDINGS (1440 + 432 = 1872 bytes) ===
    pub findings: [Finding; MAX_FINDINGS],
    pub critical_findings: [Finding; MAX_CRITICAL_FINDINGS],

    // === CONTAGENS E NÍVEIS (16 bytes) ===
    pub finding_count: u8,
    pub critical_count: u8,
    pub risk_level: RiskLevel,
    pub composite_risk: f32,
    pub executed_modules: u32,  // ADR-017: era u8, agora u32 (+3 bytes)
    pub _reserved: [u8; 5],    // ADR-017: era [u8; 8], agora [u8; 5] (-3 bytes)

    // === METADADOS RESERVADOS (7072 bytes) ===
    #[serde(with = "serde_reserved")]
    pub _reserved_metadata: [u8; 7072],

    // === INTEGRIDADE (32 bytes) ===
    pub hash: [u8; HASH_SIZE],
}

static_assertions::const_assert_eq!(size_of::<TechnicalEvidence>(), EVIDENCE_SIZE);

impl TechnicalEvidence {
    pub fn new(audit_trail_id: u128) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|e| panic!("BTV invariant violation: system clock before UNIX_EPOCH: {e}"))
            .as_micros();

        Self {
            version: 2,
            timestamp: now,
            audit_trail_id,
            processing_time_us: 0,
            input_size: 0,
            original_request_hash: 0,
            _pad_metadata: [0; 8],
            stats: InputStatistics::empty(),
            bias: BiasDeclaration::default(),
            findings: [Finding::empty(); MAX_FINDINGS],
            critical_findings: [Finding::empty(); MAX_CRITICAL_FINDINGS],
            finding_count: 0,
            critical_count: 0,
            risk_level: RiskLevel::Safe,
            composite_risk: 0.0,
            executed_modules: 0,
            _reserved: [0; 5],
            _reserved_metadata: [0; 7072],
            hash: [0; HASH_SIZE],
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        if finding.severity.is_critical() {
            let idx = self.critical_count as usize;
            if idx < MAX_CRITICAL_FINDINGS {
                self.critical_findings[idx] = finding;
                self.critical_count += 1;
            } else {
                self.critical_findings.rotate_left(1);
                self.critical_findings[MAX_CRITICAL_FINDINGS - 1] = finding;
            }
        } else {
            let idx = self.finding_count as usize;
            if idx < MAX_FINDINGS {
                self.findings[idx] = finding;
                self.finding_count += 1;
            } else {
                self.findings.rotate_left(1);
                self.findings[MAX_FINDINGS - 1] = finding;
            }
        }
        self.update_risk_score();
    }

    fn update_risk_score(&mut self) {
        let mut total = 0.0;
        let mut count = 0;
        for i in 0..self.finding_count as usize {
            total += self.findings[i].severity.to_score();
            count += 1;
        }
        for i in 0..self.critical_count as usize {
            total += self.critical_findings[i].severity.to_score();
            count += 1;
        }
        self.composite_risk = if count > 0 { total / count as f32 } else { 0.0 };
        self.risk_level = RiskLevel::from_score(self.composite_risk);
    }

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

    pub fn calculate_hash(&self) -> [u8; HASH_SIZE] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.audit_trail_id.to_le_bytes());
        hasher.update(&self.processing_time_us.to_le_bytes());
        hasher.update(&self.input_size.to_le_bytes());
        hasher.update(&self.original_request_hash.to_le_bytes());
        hasher.update(&self._pad_metadata);
        hasher.update(&self.stats.to_bytes());
        hasher.update(&self.bias.to_bytes());
        for i in 0..self.finding_count as usize {
            hasher.update(&self.findings[i].to_bytes());
        }
        for i in 0..self.critical_count as usize {
            hasher.update(&self.critical_findings[i].to_bytes());
        }
        hasher.update(&[self.finding_count]);
        hasher.update(&[self.critical_count]);
        hasher.update(&[self.risk_level as u8]);
        hasher.update(&self.composite_risk.to_le_bytes());
        hasher.update(&self.executed_modules.to_le_bytes());
        hasher.update(&self._reserved);
        hasher.update(&self._reserved_metadata);
        *hasher.finalize().as_bytes()
    }

    pub fn finalize(&mut self) -> Result<(), crate::core::errors::EvidenceError> {
        self.hash = self.calculate_hash();
        Ok(())
    }

    pub fn validate_hash(&self) -> bool {
        self.calculate_hash() == self.hash
    }

    // ── PROP-031: Skill Hash (reserved_metadata[8..40]) ────────────────────────────

    pub fn get_skill_hash(&self) -> &[u8; 32] {
        self._reserved_metadata[8..40]
            .try_into()
            .unwrap_or_else(|_| panic!("BTV invariant violation: skill_hash slice [8..40] must be exactly 32 bytes"))
    }

    pub fn set_skill_hash(&mut self, hash: &[u8; 32]) {
        self._reserved_metadata[8..40].copy_from_slice(hash);
    }

    pub fn has_skill_hash(&self) -> bool {
        self._reserved_metadata[8..40].iter().any(|&b| b != 0)
    }

    // ── PROP-031: Skill MAC Tag (reserved_metadata[41..73]) ───────────────────────

    pub fn get_skill_mac_tag(&self) -> &[u8; 32] {
        self._reserved_metadata[41..73]
            .try_into()
            .unwrap_or_else(|_| panic!("BTV invariant violation: skill_mac_tag slice [41..73] must be exactly 32 bytes"))
    }

    pub fn set_skill_mac_tag(&mut self, tag: &[u8; 32]) {
        self._reserved_metadata[41..73].copy_from_slice(tag);
    }

    pub fn has_skill_mac_tag(&self) -> bool {
        self._reserved_metadata[41..73].iter().any(|&b| b != 0)
    }

    // ── C8: Hardware Attestation (reserved_metadata[73..202]) ────────────────────

    pub fn set_hw_attestation(&mut self, sig: &[u8; 64], hash: &[u8; 32], tee_pubkey: &[u8; 32]) {
        self._reserved_metadata[73] = 1;
        self._reserved_metadata[74..138].copy_from_slice(sig);
        self._reserved_metadata[138..170].copy_from_slice(hash);
        self._reserved_metadata[170..202].copy_from_slice(tee_pubkey);
    }

    pub fn has_hw_attestation(&self) -> bool {
        self._reserved_metadata[73] == 1
    }

    pub fn get_hw_attestation_sig(&self) -> &[u8; 64] {
        self._reserved_metadata[74..138]
            .try_into()
            .unwrap_or_else(|_| panic!("BTV invariant violation: hw_attestation_sig slice [74..138] must be exactly 64 bytes"))
    }

    pub fn get_hw_attestation_hash(&self) -> &[u8; 32] {
        self._reserved_metadata[138..170]
            .try_into()
            .unwrap_or_else(|_| panic!("BTV invariant violation: hw_attestation_hash slice [138..170] must be exactly 32 bytes"))
    }

    pub fn get_trusted_tee_pubkey(&self) -> &[u8; 32] {
        self._reserved_metadata[170..202]
            .try_into()
            .unwrap_or_else(|_| panic!("BTV invariant violation: trusted_tee_pubkey slice [170..202] must be exactly 32 bytes"))
    }

    /// Serializes to a fixed [u8; EVIDENCE_SIZE] buffer by copying the repr(C) memory layout.
    #[allow(unsafe_code)]
    pub fn to_bytes(&self) -> [u8; EVIDENCE_SIZE] {
        let mut bytes = [0u8; EVIDENCE_SIZE];
        unsafe {
            let ptr = self as *const TechnicalEvidence as *const u8;
            std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), size_of::<TechnicalEvidence>());
        }
        bytes
    }

    /// Deserializes from a fixed [u8; EVIDENCE_SIZE] buffer produced by `to_bytes`.
    #[allow(unsafe_code)]
    pub fn from_bytes(bytes: &[u8; EVIDENCE_SIZE]) -> Option<Self> {
        unsafe {
            let ptr = bytes.as_ptr() as *const TechnicalEvidence;
            Some(std::ptr::read_unaligned(ptr))
        }
    }
}
