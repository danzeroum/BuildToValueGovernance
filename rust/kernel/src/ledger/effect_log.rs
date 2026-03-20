//! EffectLog — PROP-029 (ADR-0048)
//!
//! Ring buffer estático para efeitos de ação de agente.
//!
//! Invariantes:
//! - [EffectEntry; 64] stack-allocated — zero heap no hot path
//! - EffectEntry: Copy + Sized (sem Vec, Box, String)
//! - HMAC-SHA256 em cada EffectEntry (Jonas: responsabilidade individual)
//! - WAL-first: gravado antes do commit da ação
//! - Frontier per-resource em _reserved_metadata[41..164]
//! - Timeout 40ms hard-cap → ABORT (fail-secure)
//! - Funções ≤ 50 linhas
//!
//! Filosofia: Jonas (responsabilidade preventiva), Rawls (ABORT contestável SLA 24h).

use blake3;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

// ─── Constants ────────────────────────────────────────────────────────────────

pub const EFFECT_RING_CAPACITY:  usize = 64;
pub const MAX_FRONTIERS:         usize = 3;
/// Layout: resource_id[32] + epoch_le[8] + confirmed[1] = 41 bytes
pub const FRONTIER_BYTES:        usize = 41;
pub const FRONTIER_REGION_START: usize = 41;
pub const FRONTIER_REGION_END:   usize = FRONTIER_REGION_START + MAX_FRONTIERS * FRONTIER_BYTES;
/// Polling interval dentro do loop de espera de frontier.
pub const FRONTIER_POLL_US:      u64   = 100;

// ─── Enums ────────────────────────────────────────────────────────────────────

/// Dimensão 1 da taxonomia bidimensional (ADR-0048 D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reversibility {
    Reversible         = 0,
    ReversibleWithCost = 1,
    Irreversible       = 2,
}

/// Dimensão 2 da taxonomia bidimensional (ADR-0048 D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Temporality {
    Bufferable   = 0,
    Externalized = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    WalWriteFailed,
    FrontierTimeout,
    HandlerFailed,
    RingFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectResult {
    Committed,
    Abort { reason: AbortReason },
}

// ─── EffectEntry ─────────────────────────────────────────────────────────────

/// Entrada do EffectLog. Copy + Sized — zero heap.
///
/// Layout (108 bytes):
/// action_id[32] + resource_id[32] + rev[1] + temp[1] + pad[2] + ts[8] + hmac[32]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct EffectEntry {
    pub action_id:     [u8; 32],
    pub resource_id:   [u8; 32],
    pub reversibility: Reversibility,
    pub temporality:   Temporality,
    _pad:              [u8; 2],
    pub timestamp_ns:  u64,
    pub hmac:          [u8; 32],
}

const ZERO_ENTRY: EffectEntry = EffectEntry {
    action_id: [0u8; 32], resource_id: [0u8; 32],
    reversibility: Reversibility::Reversible,
    temporality:   Temporality::Bufferable,
    _pad: [0u8; 2], timestamp_ns: 0, hmac: [0u8; 32],
};

impl EffectEntry {
    pub fn new(
        action_id:     [u8; 32],
        resource_id:   [u8; 32],
        reversibility: Reversibility,
        temporality:   Temporality,
        timestamp_ns:  u64,
        hmac_key:      &[u8],
    ) -> Self {
        let hmac = compute_entry_hmac(
            &action_id, &resource_id, reversibility, temporality, timestamp_ns, hmac_key,
        );
        Self { action_id, resource_id, reversibility, temporality, _pad: [0; 2], timestamp_ns, hmac }
    }

    pub fn verify_hmac(&self, key: &[u8]) -> bool {
        let expected = compute_entry_hmac(
            &self.action_id, &self.resource_id,
            self.reversibility, self.temporality, self.timestamp_ns, key,
        );
        constant_time_eq(&self.hmac, &expected)
    }

    /// Deriva resource_id canônico via BLAKE3.
    pub fn resource_id_from(resource_path: &[u8]) -> [u8; 32] {
        *blake3::hash(resource_path).as_bytes()
    }
}

impl std::fmt::Debug for EffectEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectEntry")
            .field("action_id",     &hex_short(&self.action_id))
            .field("resource_id",   &hex_short(&self.resource_id))
            .field("reversibility", &self.reversibility)
            .field("temporality",   &self.temporality)
            .field("timestamp_ns",  &self.timestamp_ns)
            .finish()
    }
}

// ─── WAL trait ───────────────────────────────────────────────────────────────

/// Contrato mínimo para integração WAL. Impl concreta: WriteAheadLog (wal.rs).
#[allow(clippy::result_unit_err)]
pub trait WalWriter {
    fn append_effect(&mut self, entry: &EffectEntry) -> Result<(), ()>;
}

// ─── FrontierSet ─────────────────────────────────────────────────────────────

struct FrontierInner {
    resource_ids: [[u8; 32]; MAX_FRONTIERS],
    epochs:       [u64; MAX_FRONTIERS],
    count:        usize,
}

/// Conjunto de fronteiras per-resource. Confirmação lock-free via AtomicBool.
/// Escrita de resource_id/epoch sob Mutex — chamado apenas na criação.
pub struct FrontierSet {
    inner:     Mutex<FrontierInner>,
    confirmed: [AtomicBool; MAX_FRONTIERS],
}

impl Default for FrontierSet {
    fn default() -> Self { Self::new() }
}

impl FrontierSet {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(FrontierInner {
                resource_ids: [[0u8; 32]; MAX_FRONTIERS],
                epochs:       [0u64; MAX_FRONTIERS],
                count:        0,
            }),
            confirmed: [
                AtomicBool::new(false),
                AtomicBool::new(false),
                AtomicBool::new(false),
            ],
        }
    }

    /// Retorna índice da frontier para resource_id, criando se não existir.
    /// Retorna None se MAX_FRONTIERS atingido (→ ABORT HandlerFailed).
    pub fn get_or_create(&self, resource_id: &[u8; 32], epoch: u64) -> Option<usize> {
        let mut inner = self.inner.lock().ok()?;
        for i in 0..inner.count {
            if &inner.resource_ids[i] == resource_id {
                return Some(i);
            }
        }
        if inner.count >= MAX_FRONTIERS { return None; }
        let idx = inner.count;
        inner.resource_ids[idx] = *resource_id;
        inner.epochs[idx]       = epoch;
        self.confirmed[idx].store(false, Ordering::Release);
        inner.count += 1;
        Some(idx)
    }

    /// Confirma frontier em idx. Chamado pelo Gatekeeper após execução bem-sucedida.
    pub fn confirm(&self, idx: usize) {
        if idx < MAX_FRONTIERS {
            self.confirmed[idx].store(true, Ordering::Release);
        }
    }

    pub fn is_confirmed(&self, idx: usize) -> bool {
        idx < MAX_FRONTIERS && self.confirmed[idx].load(Ordering::Acquire)
    }

    /// Serializa estado para _reserved_metadata[41..164]. Não-hot-path (auditoria).
    pub fn encode_to(&self, meta: &mut [u8]) {
        if meta.len() < FRONTIER_REGION_END { return; }
        let inner = match self.inner.lock() {
            Ok(g)  => g,
            Err(_) => return,   // fail-secure: não corrompe metadados
        };
        for i in 0..inner.count.min(MAX_FRONTIERS) {
            let off = FRONTIER_REGION_START + i * FRONTIER_BYTES;
            meta[off..off + 32].copy_from_slice(&inner.resource_ids[i]);
            meta[off + 32..off + 40].copy_from_slice(&inner.epochs[i].to_le_bytes());
            meta[off + 40] = if self.confirmed[i].load(Ordering::Acquire) { 1 } else { 0 };
        }
    }

    /// Deserializa de _reserved_metadata para inspeção. Vec: não-hot-path.
    pub fn decode_from(meta: &[u8]) -> Vec<([u8; 32], u64, bool)> {
        let mut result = Vec::with_capacity(MAX_FRONTIERS);
        for i in 0..MAX_FRONTIERS {
            let off = FRONTIER_REGION_START + i * FRONTIER_BYTES;
            if off + FRONTIER_BYTES > meta.len() { break; }
            let mut rid = [0u8; 32];
            rid.copy_from_slice(&meta[off..off + 32]);
            let epoch_bytes: [u8; 8] = meta[off + 32..off + 40]
                .try_into().unwrap_or([0u8; 8]);
            let epoch = u64::from_le_bytes(epoch_bytes);
            result.push((rid, epoch, meta[off + 40] != 0));
        }
        result
    }
}

// ─── EffectLog ────────────────────────────────────────────────────────────────

/// Ring buffer estático de efeitos. Stack-allocated, zero heap.
pub struct EffectLog {
    ring:       [EffectEntry; EFFECT_RING_CAPACITY],
    head:       usize,
    count:      usize,
    pub frontiers: FrontierSet,
}

impl Default for EffectLog {
    fn default() -> Self { Self::new() }
}

impl EffectLog {
    pub fn new() -> Self {
        Self {
            ring:      [ZERO_ENTRY; EFFECT_RING_CAPACITY],
            head:      0,
            count:     0,
            frontiers: FrontierSet::new(),
        }
    }

    pub fn len(&self)     -> usize { self.count }
    pub fn is_empty(&self) -> bool { self.count == 0 }
    pub fn is_full(&self)  -> bool { self.count >= EFFECT_RING_CAPACITY }

    /// Efeito bufferável: WAL-first, aguarda frontier com timeout.
    pub fn buffer_and_await_frontier<W: WalWriter>(
        &mut self,
        entry:   EffectEntry,
        wal:     &mut W,
        timeout: Duration,
    ) -> EffectResult {
        if wal.append_effect(&entry).is_err() {
            return EffectResult::Abort { reason: AbortReason::WalWriteFailed };
        }
        if self.is_full() {
            return EffectResult::Abort { reason: AbortReason::RingFull };
        }
        self.push(entry);

        let epoch = entry.timestamp_ns;
        let idx   = match self.frontiers.get_or_create(&entry.resource_id, epoch) {
            Some(i) => i,
            None    => return EffectResult::Abort { reason: AbortReason::HandlerFailed },
        };

        let deadline = Instant::now() + timeout;
        loop {
            if self.frontiers.is_confirmed(idx) {
                return EffectResult::Committed;
            }
            if Instant::now() >= deadline {
                return EffectResult::Abort { reason: AbortReason::FrontierTimeout };
            }
            std::thread::sleep(Duration::from_micros(FRONTIER_POLL_US));
        }
    }

    /// Efeito já externalizado: WAL-first, commit imediato sem frontier.
    pub fn record_immediate<W: WalWriter>(
        &mut self,
        entry: EffectEntry,
        wal:   &mut W,
    ) -> EffectResult {
        if wal.append_effect(&entry).is_err() {
            return EffectResult::Abort { reason: AbortReason::WalWriteFailed };
        }
        if self.is_full() {
            return EffectResult::Abort { reason: AbortReason::RingFull };
        }
        self.push(entry);
        EffectResult::Committed
    }

    /// Serializa fronteiras para _reserved_metadata (auditoria/TechnicalEvidence).
    pub fn encode_frontiers_to(&self, meta: &mut [u8]) {
        self.frontiers.encode_to(meta);
    }

    fn push(&mut self, entry: EffectEntry) {
        let idx  = self.head % EFFECT_RING_CAPACITY;
        self.ring[idx] = entry;
        self.head = self.head.wrapping_add(1);
        if self.count < EFFECT_RING_CAPACITY { self.count += 1; }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn compute_entry_hmac(
    action_id:    &[u8; 32],
    resource_id:  &[u8; 32],
    reversibility: Reversibility,
    temporality:   Temporality,
    timestamp_ns:  u64,
    key:           &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 aceita qualquer tamanho de chave");
    mac.update(action_id);
    mac.update(resource_id);
    mac.update(&[reversibility as u8, temporality as u8]);
    mac.update(&timestamp_ns.to_le_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Comparação em tempo constante — evita timing oracle.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

/// Representação hexadecimal parcial para Debug (não-hot-path). Vec aceitável.
fn hex_short(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{:02x}", b)).collect::<String>() + ".."
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    const KEY: &[u8] = b"btv-test-key-prop029-effect-log0";

    fn make_entry_with(action: &[u8], resource: &[u8]) -> EffectEntry {
        let action_id   = *blake3::hash(action).as_bytes();
        let resource_id = EffectEntry::resource_id_from(resource);
        EffectEntry::new(action_id, resource_id, Reversibility::Irreversible, Temporality::Bufferable, 9999, KEY)
    }

    fn make_entry() -> EffectEntry { make_entry_with(b"act", b"res") }

    #[derive(Default)]
    struct MockWal { pub calls: usize, pub fail: bool }
    impl WalWriter for MockWal {
        fn append_effect(&mut self, _: &EffectEntry) -> Result<(), ()> {
            if self.fail { return Err(()); }
            self.calls += 1;
            Ok(())
        }
    }

    // ── enums ────────────────────────────────────────────────────────────────

    #[test]
    fn test_reversibility_repr_u8() {
        assert_eq!(Reversibility::Reversible         as u8, 0);
        assert_eq!(Reversibility::ReversibleWithCost as u8, 1);
        assert_eq!(Reversibility::Irreversible       as u8, 2);
    }

    #[test]
    fn test_temporality_repr_u8() {
        assert_eq!(Temporality::Bufferable   as u8, 0);
        assert_eq!(Temporality::Externalized as u8, 1);
    }

    // ── EffectEntry ──────────────────────────────────────────────────────────

    #[test]
    fn test_entry_is_copy() {
        let e = make_entry();
        let _e2 = e; // copia sem mover
        let _e3 = e; // segunda copia — prova que é Copy
    }

    #[test]
    fn test_resource_id_from_deterministic() {
        let a = EffectEntry::resource_id_from(b"path/to/resource");
        let b = EffectEntry::resource_id_from(b"path/to/resource");
        assert_eq!(a, b);
    }

    #[test]
    fn test_resource_id_from_distinct_inputs() {
        let a = EffectEntry::resource_id_from(b"resource_a");
        let b = EffectEntry::resource_id_from(b"resource_b");
        assert_ne!(a, b);
    }

    #[test]
    fn test_entry_hmac_valid() {
        let e = make_entry();
        assert!(e.verify_hmac(KEY));
    }

    #[test]
    fn test_entry_hmac_wrong_key() {
        let e = make_entry();
        assert!(!e.verify_hmac(b"wrong-key-32-bytes-padded-00000"));
    }

    #[test]
    fn test_constant_time_eq_same() {
        let a = [1u8; 32];
        assert!(constant_time_eq(&a, &a));
    }

    #[test]
    fn test_constant_time_eq_diff() {
        let a = [1u8; 32];
        let mut b = [1u8; 32];
        b[31] = 2;
        assert!(!constant_time_eq(&a, &b));
    }

    // ── EffectLog ────────────────────────────────────────────────────────────

    #[test]
    fn test_log_starts_empty() {
        let mut log = EffectLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_record_immediate_committed() {
        let mut log = EffectLog::new();
        let mut wal = MockWal::default();
        let entry = make_entry_with(b"act", b"res_ext");
        let mut e = entry;
        e.temporality = Temporality::Externalized;
        let r = log.record_immediate(e, &mut wal);
        assert_eq!(r, EffectResult::Committed);
        assert_eq!(log.len(), 1);
        assert_eq!(wal.calls, 1);
    }

    #[test]
    fn test_record_immediate_wal_fail() {
        let mut log = EffectLog::new();
        let mut wal = MockWal { fail: true, ..Default::default() };
        let r = log.record_immediate(make_entry(), &mut wal);
        assert_eq!(r, EffectResult::Abort { reason: AbortReason::WalWriteFailed });
        assert_eq!(log.len(), 0); // nada gravado no ring
    }

    #[test]
    fn test_record_immediate_ring_full() {
        let mut log = EffectLog::new();
        let mut wal = MockWal::default();
        // Preenche o ring via record_immediate
        for i in 0..EFFECT_RING_CAPACITY {
            let e = make_entry_with(format!("a{}", i).as_bytes(), b"r");
            let r = log.record_immediate(e, &mut wal);
            assert_eq!(r, EffectResult::Committed);
        }
        // 65ª entrada deve ser RingFull
        let extra = make_entry_with(b"overflow", b"r");
        let r = log.record_immediate(extra, &mut wal);
        assert_eq!(r, EffectResult::Abort { reason: AbortReason::RingFull });
        assert_eq!(log.len(), EFFECT_RING_CAPACITY);
    }

    #[test]
    fn test_buffer_timeout_abort() {
        let mut log = EffectLog::new();
        let mut wal = MockWal::default();
        // timeout=1µs: expira antes da frontier ser confirmada
        let r = log.buffer_and_await_frontier(
            make_entry(), &mut wal, Duration::from_micros(1),
        );
        assert_eq!(r, EffectResult::Abort { reason: AbortReason::FrontierTimeout });
        assert_eq!(wal.calls, 1); // WAL gravado antes do timeout
    }

    #[test]
    fn test_buffer_committed_when_preconfirmed() {
        let mut log = EffectLog::new();
        let mut wal = MockWal::default();
        let entry = make_entry();
        // Pré-confirma a frontier antes da chamada
        let idx = log.frontiers.get_or_create(&entry.resource_id, 1).unwrap();
        log.frontiers.confirm(idx);
        let r = log.buffer_and_await_frontier(entry, &mut wal, Duration::from_millis(40));
        assert_eq!(r, EffectResult::Committed);
    }

    #[test]
    fn test_buffer_wal_fail_aborts_before_push() {
        let mut log = EffectLog::new();
        let mut wal = MockWal { fail: true, ..Default::default() };
        let r = log.buffer_and_await_frontier(
            make_entry(), &mut wal, Duration::from_millis(40),
        );
        assert_eq!(r, EffectResult::Abort { reason: AbortReason::WalWriteFailed });
        assert_eq!(log.len(), 0); // nada no ring — WAL-first respeitado
    }

    // ── FrontierSet ──────────────────────────────────────────────────────────

    #[test]
    fn test_frontier_max_slots_exceeded() {
        let fs = FrontierSet::new();
        for i in 0..MAX_FRONTIERS {
            let rid = EffectEntry::resource_id_from(format!("r{}", i).as_bytes());
            assert!(fs.get_or_create(&rid, i as u64).is_some());
        }
        // 4ª frontier deve retornar None
        let rid4 = EffectEntry::resource_id_from(b"r_overflow");
        assert!(fs.get_or_create(&rid4, 99).is_none());
    }

    #[test]
    fn test_frontier_same_resource_returns_same_idx() {
        let fs  = FrontierSet::new();
        let rid = EffectEntry::resource_id_from(b"same_resource");
        let i1  = fs.get_or_create(&rid, 1).unwrap();
        let i2  = fs.get_or_create(&rid, 2).unwrap();
        assert_eq!(i1, i2);
    }

    // ── _reserved_metadata encode/decode ─────────────────────────────────────

    #[test]
    fn test_encode_decode_reserved_metadata() {
        let mut log = EffectLog::new();
        let mut wal = MockWal::default();
        // Grava duas entradas
        let e1 = make_entry_with(b"act1", b"res1");
        let e2 = make_entry_with(b"act2", b"res2");
        let _ = log.record_immediate(e1, &mut wal);
        let _ = log.record_immediate(e2, &mut wal);
        // Confirma frontier de e1
        let idx = log.frontiers.get_or_create(&e1.resource_id, 1).unwrap();
        log.frontiers.confirm(idx);
        // Serializa para metadados
        let mut meta = [0u8; 200];
        log.encode_frontiers_to(&mut meta);
        // Deserializa e verifica offsets preservados
        let decoded = FrontierSet::decode_from(&meta);
        assert_eq!(decoded.len(), MAX_FRONTIERS);
        // Primeiro slot = e1 (confirmado)
        assert_eq!(decoded[0].0, e1.resource_id);
        assert!(decoded[0].2); // confirmed
    }

    #[test]
    fn test_reserved_metadata_offsets_do_not_overlap_skill_hash() {
        // skill_hash em [8..40], policy_drift_flag em [40]
        // fronteiras em [41..164] — sem sobreposição
        assert!(FRONTIER_REGION_START >= 41);
        assert!(FRONTIER_REGION_END   <= 200);
        // [0..40] intocados após encode
        let mut log = EffectLog::new();
        let mut meta = [0xABu8; 200];
        log.encode_frontiers_to(&mut meta);
        for i in 0..41 { assert_eq!(meta[i], 0xAB, "byte {i} corrompido"); }
    }
}
