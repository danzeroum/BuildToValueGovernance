//! Model Integrity Verifier v1.1.0 (ADR-051 Fase 1)
//!
//! Verifica integridade estrutural de modelos via BLAKE3 hash de manifesto.
//! Detecta: abliteration, weight tampering, LoRA rank-1 injection.
//!
//! CHANGELOG v1.0 → v1.1:
//!   - struct: +manifest_path, +model_id (interface ADR-051 §2)
//!   - ring buffer: `static mut` UB → Mutex<RingState> (corretude)
//!   - HMAC-SHA256: ViolationFinding + sign_violation() + verify_finding()
//!   - fail-secure: Mutex envenenado → evento perdido, verificação não para
//!
//! Fail-secure: manifesto ausente ou hash divergente → Violated (Jonas).
//! Zero heap no hot path: verify() usa apenas stack ([u8; 32]).
//! Ring buffer: últimos 256 eventos em memória (observabilidade ADR-041).
//! HMAC-SHA256: ViolationFinding assinado para contestabilidade (ADR-017).

use blake3;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

// ═══ TIPOS PÚBLICOS ════════════════════════════════════════════════════════════════════════════

/// Resultado da verificação de integridade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityResult {
    Verified,
    Violated(IntegrityViolation),
}

/// Motivo da violação — auditável via TechnicalEvidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityViolation {
    /// Hash BLAKE3 do manifesto diverge do esperado.
    HashMismatch,
    /// Manifesto ausente ou ilegível — fail-secure → BLOCK.
    ManifestUnavailable,
    /// Input inválido (manifest_bytes vazio).
    InvalidInput,
}

// ═══ RING BUFFER ═════════════════════════════════════════════════════════════════════════════

const RING_CAPACITY: usize = 256;

/// Evento de violação registrado no ring buffer (copiável, sem heap).
#[derive(Debug, Clone, Copy)]
pub struct IntegrityEvent {
    pub violation: IntegrityViolationKind,
    pub timestamp_ms: u64,
}

/// Variante Copy para o ring buffer (sem String/Vec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityViolationKind {
    HashMismatch,
    ManifestUnavailable,
    InvalidInput,
}

struct RingState {
    buf:  [Option<IntegrityEvent>; RING_CAPACITY],
    head: usize,
}

impl RingState {
    const fn new() -> Self {
        Self { buf: [None; RING_CAPACITY], head: 0 }
    }

    fn push(&mut self, ev: IntegrityEvent) {
        self.buf[self.head % RING_CAPACITY] = Some(ev);
        self.head = self.head.wrapping_add(1);
    }

    fn recent(&self, count: usize) -> Vec<IntegrityEvent> {
        let n = count.min(RING_CAPACITY);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let idx = self.head.wrapping_sub(i + 1) % RING_CAPACITY;
            if let Some(ev) = self.buf[idx] {
                out.push(ev);
            }
        }
        out
    }
}

// Mutex::new() é const desde Rust 1.63.
static RING: Mutex<RingState> = Mutex::new(RingState::new());

fn ring_push(ev: IntegrityEvent) {
    // Fail-secure: lock envenenado → evento perdido, verificação continua.
    if let Ok(mut r) = RING.lock() {
        r.push(ev);
    }
}

// ═══ HMAC-SHA256 — ADR-017 CONTESTABILIDADE ══════════════════════════════════════════════

/// Finding HMAC-assinado para bridge com TechnicalEvidence.
/// Tamanho fixo na stack: sem heap, sem String.
#[derive(Debug, Clone)]
pub struct ViolationFinding {
    pub violation:      IntegrityViolationKind,
    pub timestamp_ms:   u64,
    /// HMAC-SHA256(kind_byte || timestamp_ms_le || model_id_bytes)
    pub hmac_signature: [u8; 32],
}

/// Assina uma violação com chave de 32 bytes (ADR-017).
/// Retorna `None` apenas se HMAC falhar internamente (não deve ocorrer).
pub fn sign_violation(
    violation:   IntegrityViolationKind,
    timestamp_ms: u64,
    model_id:    &str,
    signing_key: &[u8; 32],
) -> Option<ViolationFinding> {
    let mut mac = HmacSha256::new_from_slice(signing_key).ok()?;
    let kind_byte: u8 = match violation {
        IntegrityViolationKind::HashMismatch        => 0x01,
        IntegrityViolationKind::ManifestUnavailable => 0x02,
        IntegrityViolationKind::InvalidInput        => 0x03,
    };
    mac.update(&[kind_byte]);
    mac.update(&timestamp_ms.to_le_bytes());
    mac.update(model_id.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut sig = [0u8; 32];
    sig.copy_from_slice(&result[..32]);
    Some(ViolationFinding { violation, timestamp_ms, hmac_signature: sig })
}

/// Verifica assinatura de um `ViolationFinding` em tempo constante.
pub fn verify_finding(
    finding:     &ViolationFinding,
    model_id:    &str,
    signing_key: &[u8; 32],
) -> bool {
    match sign_violation(finding.violation, finding.timestamp_ms, model_id, signing_key) {
        Some(expected) => constant_time_eq(&expected.hmac_signature, &finding.hmac_signature),
        None           => false,
    }
}

// ═══ VERIFICADOR PRINCIPAL ═══════════════════════════════════════════════════════════════════

/// Verifica integridade de modelo via BLAKE3 hash de manifesto.
///
/// Campos ADR-051 §2:
///   `expected_hash`  — BLAKE3 [u8; 32] assinado pelo operador no deploy.
///   `manifest_path`  — caminho do `.manifest.json` (configurável por Policy, ADR-042).
///   `model_id`       — identificador do modelo para contestabilidade.
pub struct ModelIntegrityVerifier {
    expected_hash:  [u8; 32],
    pub manifest_path: &'static str,
    pub model_id:      &'static str,
}

impl ModelIntegrityVerifier {
    /// Constrói verifier. Hash definido em Policy YAML, lido no startup (ADR-042).
    pub fn new(
        expected_hash:  [u8; 32],
        manifest_path:  &'static str,
        model_id:       &'static str,
    ) -> Self {
        Self { expected_hash, manifest_path, model_id }
    }

    /// Hot path. Zero heap: hash computado sobre slice, resultado em stack.
    /// Meta: <5ms p99 (ADR-051 §2).
    pub fn verify(&self, manifest_bytes: &[u8]) -> IntegrityResult {
        if manifest_bytes.is_empty() {
            ring_push(IntegrityEvent {
                violation:    IntegrityViolationKind::InvalidInput,
                timestamp_ms: monotonic_ms(),
            });
            return IntegrityResult::Violated(IntegrityViolation::InvalidInput);
        }
        let actual = *blake3::hash(manifest_bytes).as_bytes();
        if !constant_time_eq(&actual, &self.expected_hash) {
            ring_push(IntegrityEvent {
                violation:    IntegrityViolationKind::HashMismatch,
                timestamp_ms: monotonic_ms(),
            });
            return IntegrityResult::Violated(IntegrityViolation::HashMismatch);
        }
        IntegrityResult::Verified
    }

    /// Fail-secure: caller não conseguiu ler manifesto → BLOCK (Jonas).
    pub fn manifest_unavailable(&self) -> IntegrityResult {
        ring_push(IntegrityEvent {
            violation:    IntegrityViolationKind::ManifestUnavailable,
            timestamp_ms: monotonic_ms(),
        });
        IntegrityResult::Violated(IntegrityViolation::ManifestUnavailable)
    }

    /// Observabilidade: snapshot dos últimos N eventos do ring buffer.
    pub fn recent_violations(count: usize) -> Vec<IntegrityEvent> {
        RING.lock().map(|r| r.recent(count)).unwrap_or_default()
    }
}

// ═══ UTILITÁRIOS INTERNOS ═══════════════════════════════════════════════════════════════════

/// Comparação em tempo constante — anti-timing-attack.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Timestamp monotônico em ms (sem heap, sem syscall pesada no hot path).
fn monotonic_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ═══ TESTS ════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PATH: &str = "/models/phi-3-mini/.manifest.json";
    const TEST_MODEL: &str = "phi-3-mini-v1";
    const TEST_KEY:   [u8; 32] = [0x42u8; 32];

    fn verifier_for(content: &[u8]) -> ModelIntegrityVerifier {
        let hash = *blake3::hash(content).as_bytes();
        ModelIntegrityVerifier::new(hash, TEST_PATH, TEST_MODEL)
    }

    // ── Testes v1.0 (legados) ────────────────────────────────────────

    #[test]
    fn valid_manifest_verifies() {
        let m = br#"{"model":"phi-3-mini","tensors_sha256":"abc"}"#;
        assert_eq!(verifier_for(m).verify(m), IntegrityResult::Verified);
    }

    #[test]
    fn tampered_manifest_blocks() {
        let original = br#"{"model":"phi-3-mini","tensors_sha256":"abc"}"#;
        let tampered  = br#"{"model":"phi-3-mini","tensors_sha256":"xyz"}"#;
        assert_eq!(
            verifier_for(original).verify(tampered),
            IntegrityResult::Violated(IntegrityViolation::HashMismatch),
        );
    }

    #[test]
    fn empty_input_blocks() {
        assert_eq!(
            verifier_for(b"content").verify(b""),
            IntegrityResult::Violated(IntegrityViolation::InvalidInput),
        );
    }

    #[test]
    fn manifest_unavailable_blocks() {
        assert_eq!(
            verifier_for(b"x").manifest_unavailable(),
            IntegrityResult::Violated(IntegrityViolation::ManifestUnavailable),
        );
    }

    #[test]
    fn wrong_expected_hash_blocks() {
        let v = ModelIntegrityVerifier::new([0xFFu8; 32], TEST_PATH, TEST_MODEL);
        assert_eq!(
            v.verify(b"any content"),
            IntegrityResult::Violated(IntegrityViolation::HashMismatch),
        );
    }

    #[test]
    fn constant_time_eq_identical() {
        assert!(constant_time_eq(&[0x42u8; 32], &[0x42u8; 32]));
    }

    #[test]
    fn constant_time_eq_differs() {
        let mut b = [0x42u8; 32];
        b[31] = 0x00;
        assert!(!constant_time_eq(&[0x42u8; 32], &b));
    }

    // ── Testes v1.1 (novos) ────────────────────────────────────────

    #[test]
    fn manifest_path_and_model_id_exposed() {
        let v = verifier_for(b"data");
        assert_eq!(v.manifest_path, TEST_PATH);
        assert_eq!(v.model_id,      TEST_MODEL);
    }

    #[test]
    fn sign_and_verify_finding_roundtrip() {
        let finding = sign_violation(
            IntegrityViolationKind::HashMismatch,
            1_000_000,
            TEST_MODEL,
            &TEST_KEY,
        ).unwrap_or_else(|| panic!("BTV invariant violation: HMAC deve funcionar"));
        assert!(verify_finding(&finding, TEST_MODEL, &TEST_KEY));
    }

    #[test]
    fn tampered_finding_rejected() {
        let mut finding = sign_violation(
            IntegrityViolationKind::HashMismatch,
            1_000_000,
            TEST_MODEL,
            &TEST_KEY,
        ).unwrap_or_else(|| panic!("BTV invariant violation: HMAC deve funcionar"));
        finding.hmac_signature[0] ^= 0xFF;
        assert!(!verify_finding(&finding, TEST_MODEL, &TEST_KEY));
    }

    #[test]
    fn wrong_model_id_rejects_finding() {
        let finding = sign_violation(
            IntegrityViolationKind::ManifestUnavailable,
            42,
            TEST_MODEL,
            &TEST_KEY,
        ).unwrap_or_else(|| panic!("BTV invariant violation: HMAC deve funcionar"));
        assert!(!verify_finding(&finding, "outro-modelo", &TEST_KEY));
    }

    #[test]
    fn ring_buffer_records_violations() {
        let v = verifier_for(b"ref");
        let _ = v.verify(b"");
        let _ = v.verify(b"tampered");
        let events = ModelIntegrityVerifier::recent_violations(5);
        assert!(!events.is_empty());
    }
}
