//! Model Integrity Verifier v1.0.0
//! Verifica integridade estrutural de modelos via BLAKE3 hash de manifesto.
//! ADR-051: Fase 1 — detecção de adulteração pós-deploy (abliteration, weight tampering).
//!
//! Fail-secure: manifesto ausente ou hash divergente → IntegrityViolation::Blocked.
//! Zero heap no hot path: verificação sobre arrays fixos [u8; 32] na stack.
//! Ring buffer de alertas: últimos 256 eventos em memória (observabilidade ADR-041).

use blake3;
use std::sync::atomic::{AtomicUsize, Ordering};

// ═══════════════════════════════════════════════════════════════════════════
// TIPOS PÚBLICOS
// ═══════════════════════════════════════════════════════════════════════════

/// Resultado da verificação de integridade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityResult {
    Verified,
    Violated(IntegrityViolation),
}

/// Motivo da violação — auditável via TechnicalEvidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityViolation {
    /// Hash do manifesto diverge do esperado.
    HashMismatch,
    /// Manifesto ausente ou ilegível — fail-secure → BLOCK.
    ManifestUnavailable,
    /// Input inválido (manifest_bytes vazio).
    InvalidInput,
}

// ═══════════════════════════════════════════════════════════════════════════
// RING BUFFER DE ALERTAS (observabilidade, zero heap no hot path)
// ═══════════════════════════════════════════════════════════════════════════

const RING_CAPACITY: usize = 256;

/// Evento de violação registrado no ring buffer.
#[derive(Debug, Clone, Copy)]
pub struct IntegrityEvent {
    pub violation: IntegrityViolationKind,
    pub timestamp_ms: u64,
}

/// Variante copiável para o ring buffer (sem String).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityViolationKind {
    HashMismatch,
    ManifestUnavailable,
    InvalidInput,
}

/// Ring buffer estático — sem alocação dinâmica.
static RING_HEAD: AtomicUsize = AtomicUsize::new(0);
static mut RING_BUFFER: [Option<IntegrityEvent>; RING_CAPACITY] =
    [None; RING_CAPACITY];

fn ring_push(event: IntegrityEvent) {
    let idx = RING_HEAD.fetch_add(1, Ordering::Relaxed) % RING_CAPACITY;
    // SAFETY: acesso exclusivo garantido por fetch_add como sequenciador lógico.
    // Em produção substituir por Mutex ou estrutura lock-free formal.
    unsafe {
        RING_BUFFER[idx] = Some(event);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VERIFICADOR
// ═══════════════════════════════════════════════════════════════════════════

/// Verifica integridade de modelo via BLAKE3 hash de manifesto.
///
/// `manifest_bytes`: conteúdo bruto do `.manifest.json` lido pelo caller.
/// `expected_hash`: hash BLAKE3 de 32 bytes pré-computado no deploy, assinado pelo operador.
///
/// Fail-secure: qualquer caminho de erro retorna `Violated`.
pub struct ModelIntegrityVerifier {
    expected_hash: [u8; 32],
}

impl ModelIntegrityVerifier {
    /// Constrói verifier com hash esperado fixo (definido em Policy, ADR-042).
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self { expected_hash }
    }

    /// Verifica manifesto. Zero heap: hash computado sobre slice, resultado em stack.
    pub fn verify(&self, manifest_bytes: &[u8]) -> IntegrityResult {
        if manifest_bytes.is_empty() {
            ring_push(IntegrityEvent {
                violation: IntegrityViolationKind::InvalidInput,
                timestamp_ms: monotonic_ms(),
            });
            return IntegrityResult::Violated(IntegrityViolation::InvalidInput);
        }

        let actual = *blake3::hash(manifest_bytes).as_bytes();

        if !constant_time_eq(&actual, &self.expected_hash) {
            ring_push(IntegrityEvent {
                violation: IntegrityViolationKind::HashMismatch,
                timestamp_ms: monotonic_ms(),
            });
            return IntegrityResult::Violated(IntegrityViolation::HashMismatch);
        }

        IntegrityResult::Verified
    }

    /// Fail-secure: chama quando manifesto não pôde ser lido pelo caller.
    pub fn manifest_unavailable(&self) -> IntegrityResult {
        ring_push(IntegrityEvent {
            violation: IntegrityViolationKind::ManifestUnavailable,
            timestamp_ms: monotonic_ms(),
        });
        IntegrityResult::Violated(IntegrityViolation::ManifestUnavailable)
    }

    /// Retorna snapshot do ring buffer (para observabilidade).
    pub fn recent_violations(count: usize) -> Vec<IntegrityEvent> {
        let n = count.min(RING_CAPACITY);
        let head = RING_HEAD.load(Ordering::Relaxed);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let idx = head.wrapping_sub(i + 1) % RING_CAPACITY;
            unsafe {
                if let Some(ev) = RING_BUFFER[idx] {
                    out.push(ev);
                }
            }
        }
        out
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITÁRIOS INTERNOS
// ═══════════════════════════════════════════════════════════════════════════

/// Comparação em tempo constante (anti-timing-attack).
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Timestamp monotônico em ms — sem heap, sem syscall pesada em hot path.
fn monotonic_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier_for(content: &[u8]) -> ModelIntegrityVerifier {
        let hash = *blake3::hash(content).as_bytes();
        ModelIntegrityVerifier::new(hash)
    }

    #[test]
    fn valid_manifest_verifies() {
        let manifest = b r#"{"model":"phi-3-mini","tensors_sha256":"abc"}"#;
        let v = verifier_for(manifest);
        assert_eq!(v.verify(manifest), IntegrityResult::Verified);
    }

    #[test]
    fn tampered_manifest_blocks() {
        let original = b r#"{"model":"phi-3-mini","tensors_sha256":"abc"}"#;
        let tampered = b r#"{"model":"phi-3-mini","tensors_sha256":"xyz"}"#;
        let v = verifier_for(original);
        assert_eq!(
            v.verify(tampered),
            IntegrityResult::Violated(IntegrityViolation::HashMismatch)
        );
    }

    #[test]
    fn empty_input_blocks() {
        let v = verifier_for(b"content");
        assert_eq!(
            v.verify(b""),
            IntegrityResult::Violated(IntegrityViolation::InvalidInput)
        );
    }

    #[test]
    fn manifest_unavailable_blocks() {
        let v = verifier_for(b"content");
        assert_eq!(
            v.manifest_unavailable(),
            IntegrityResult::Violated(IntegrityViolation::ManifestUnavailable)
        );
    }

    #[test]
    fn wrong_expected_hash_blocks() {
        let v = ModelIntegrityVerifier::new([0xFFu8; 32]);
        let manifest = b"any content";
        assert_eq!(
            v.verify(manifest),
            IntegrityResult::Violated(IntegrityViolation::HashMismatch)
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
}
