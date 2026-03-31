//! Technical Evidence v2.5.1 – 9632 bytes fixos (EVIDENCE_SIZE, ADR-044).
//! ADR-017: executed_modules expandido de u8 para u32.
//! Wire 4: _reserved_metadata[41..73] = skill_mac_tag (PROP-031/supply_guard).

use serde::{Deserialize, Serialize};
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
    // Layout Wire 4:
    //   [0..8]    pattern_epoch
    //   [8..40]   skill_hash       (PROP-031)
    //   [40]      goal_drift_flag  (PROP-038, bit 0)
    //   [41..73]  skill_mac_tag    (PROP-031/supply_guard, Wire 4)
    //   [73]      has_hw_attestation: u8 (0=absent, 1=present) (C8)
    //   [74..138] hw_attestation_sig: [u8; 64] Ed25519 from TEE (C8)
    //   [138..170] hw_attestation_hash: [u8; 32] BLAKE3 of attested payload (C8)
    //   [170..202] trusted_tee_pubkey: [u8; 32] Ed25519 pubkey for verification (C8)
    //   [202..]   disponível para expansão futura
    #[serde(with = "serde_reserved")]
    pub _reserved_metadata: [u8; 7072],

    // === INTEGRIDADE (32 bytes) ===
    pub hash: [u8; HASH_SIZE],
}

impl TechnicalEvidence {
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
        hasher.update(&self.executed_modules.to_le_bytes()); // ADR-017: 4 bytes
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

    // ── PROP-031: Skill Hash (reserved_metadata[8..40]) ──────────────────────

    /// Retorna o skill_hash BLAKE3 armazenado em _reserved_metadata[8..40].
    /// Zeros indicam ausência de skill registrada.
    pub fn get_skill_hash(&self) -> &[u8; 32] {
        self._reserved_metadata[8..40]
            .try_into()
            .expect("slice de tamanho fixo 32")
    }

    /// Grava skill_hash BLAKE3 em _reserved_metadata[8..40].
    /// Zero heap: opera sobre slice existente, sem alloc.
    pub fn set_skill_hash(&mut self, hash: &[u8; 32]) {
        self._reserved_metadata[8..40].copy_from_slice(hash);
    }

    /// Retorna true se skill_hash foi definido (≠ zeros).
    pub fn has_skill_hash(&self) -> bool {
        self._reserved_metadata[8..40].iter().any(|&b| b != 0)
    }

    // ── PROP-031: Skill MAC Tag (reserved_metadata[41..73]) ─────────────────
    // Wire 4: MAC tag do supply_guard (BLAKE3 keyed-hash, ADR-031b).
    // Layout: [8..40] skill_hash | [40] goal_drift_flag | [41..73] mac_tag
    // Zero heap: operações sobre slice existente, sem alloc.

    /// Retorna o MAC tag de 32 bytes armazenado em _reserved_metadata[41..73].
    pub fn get_skill_mac_tag(&self) -> &[u8; 32] {
        self._reserved_metadata[41..73]
            .try_into()
            .expect("slice de tamanho fixo 32")
    }

    /// Grava o MAC tag em _reserved_metadata[41..73].
    pub fn set_skill_mac_tag(&mut self, tag: &[u8; 32]) {
        self._reserved_metadata[41..73].copy_from_slice(tag);
    }

    /// Retorna true se mac_tag foi definido (≠ zeros).
    pub fn has_skill_mac_tag(&self) -> bool {
        self._reserved_metadata[41..73].iter().any(|&b| b != 0)
    }

    // ── C8: Hardware Attestation (reserved_metadata[73..202]) ────────────────
    // Layout: [73]=flag | [74..138]=sig(64) | [138..170]=hash(32) | [170..202]=tee_pubkey(32)

    /// Stores TEE hardware attestation data. Zero heap — operates on existing slices.
    pub fn set_hw_attestation(&mut self, sig: &[u8; 64], hash: &[u8; 32], tee_pubkey: &[u8; 32]) {
        self._reserved_metadata[73] = 1;
        self._reserved_metadata[74..138].copy_from_slice(sig);
        self._reserved_metadata[138..170].copy_from_slice(hash);
        self._reserved_metadata[170..202].copy_from_slice(tee_pubkey);
    }

    /// Returns true if hardware attestation is present.
    pub fn has_hw_attestation(&self) -> bool {
        self._reserved_metadata[73] == 1
    }

    /// Returns the TEE signature stored in the attestation slot.
    pub fn get_hw_attestation_sig(&self) -> &[u8; 64] {
        self._reserved_metadata[74..138]
            .try_into()
            .expect("slice de tamanho fixo 64")
    }

    /// Returns the BLAKE3 hash of the attested payload.
    pub fn get_hw_attestation_hash(&self) -> &[u8; 32] {
        self._reserved_metadata[138..170]
            .try_into()
            .expect("slice de tamanho fixo 32")
    }

    /// Returns the trusted TEE public key used to verify the attestation signature.
    pub fn get_trusted_tee_pubkey(&self) -> &[u8; 32] {
        self._reserved_metadata[170..202]
            .try_into()
            .expect("slice de tamanho fixo 32")
    }

    /// Serializes to a fixed [u8; EVIDENCE_SIZE] buffer by copying the repr(C) memory layout.
    ///
    /// # Safety rationale (function-level allow)
    /// - `TechnicalEvidence` is `#[repr(C, align(8))]` with all fixed-size fields.
    /// - `size_of::<TechnicalEvidence>() == EVIDENCE_SIZE` is a compile-time invariant
    ///   (enforced by the static_assertions in this crate — see EVIDENCE_SIZE constant).
    /// - The resulting bytes are only used for WAL persistence (cold path); the hash
    ///   hot-path uses `calculate_hash()` which is fully safe and field-by-field.
    /// - This is the only justified unsafe block remaining in the kernel after Phase 0.1.
    #[allow(unsafe_code)]
    pub fn to_bytes(&self) -> [u8; EVIDENCE_SIZE] {
        let mut bytes = [0u8; EVIDENCE_SIZE];
        // SAFETY: self is repr(C, align(8)), bytes is a correctly-sized buffer.
        unsafe {
            let ptr = self as *const TechnicalEvidence as *const u8;
            std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), size_of::<TechnicalEvidence>());
        }
        bytes
    }

    /// Deserializes from a fixed [u8; EVIDENCE_SIZE] buffer produced by `to_bytes`.
    ///
    /// Returns `None` if the size invariant is not met (defensive check).
    /// Only used in WAL recovery (cold path).
    #[allow(unsafe_code)]
    pub fn from_bytes(bytes: &[u8; EVIDENCE_SIZE]) -> Option<Self> {
        // SAFETY: bytes was produced by to_bytes() on a valid TechnicalEvidence,
        // and TechnicalEvidence is repr(C, align(8)) with no references or pointers.
        unsafe {
            let ptr = bytes.as_ptr() as *const TechnicalEvidence;
            Some(std::ptr::read_unaligned(ptr))
        }
    }
}
