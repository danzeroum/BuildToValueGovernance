//! GoalDriftValidator — PROP-038 (Rust Kernel / Validators).
//!
//! Detecta drift de objetivo em tempo de execução, sem heap.
//! Flag `policy_drift_detected` armazenada em `_reserved_metadata[40]` bit 0.
//!
//! Filosofia (Jonas): responsabilidade preventiva — sinalizar antes do ponto
//! de não retorno. Paper 213: drift é assimétrico e 100% dos timesteps finais
//! violam sob pressão Eficiência vs. Segurança.
//!
//! Invariantes:
//! - Zero heap no hot path
//! - Ring buffer pré-alocado [u8; DRIFT_WINDOW_K]
//! - Funções ≤ 50 linhas

/// Tamanho da janela temporal (K timesteps). Fixo em tempo de compilação.
pub const DRIFT_WINDOW_K: usize = 10;

/// Mapeamento de drift_level (string do Python) para score u8.
/// None=0, Low=1, Medium=2, High=3, Critical=4.
/// Valores acima de 4 são tratados como Critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DriftScore {
    None     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
}

impl DriftScore {
    /// Converte string do RequestContext para DriftScore.
    /// Strings desconhecidas → None (conservador, não alarmista).
    pub fn from_str(s: &str) -> Self {
        match s {
            "Low"      => Self::Low,
            "Medium"   => Self::Medium,
            "High"     => Self::High,
            "Critical" => Self::Critical,
            _          => Self::None,
        }
    }

    pub fn as_u8(self) -> u8 { self as u8 }
}

/// Ring buffer pré-alocado de drift scores. Zero heap.
#[derive(Debug)]
pub struct GoalDriftBuffer {
    scores: [u8; DRIFT_WINDOW_K],
    head:   usize,
    count:  usize,
}

impl GoalDriftBuffer {
    pub const fn new() -> Self {
        Self { scores: [0; DRIFT_WINDOW_K], head: 0, count: 0 }
    }

    /// Insere novo score no ring buffer. Sem alloc.
    pub fn push(&mut self, score: DriftScore) {
        self.scores[self.head] = score.as_u8();
        self.head = (self.head + 1) % DRIFT_WINDOW_K;
        if self.count < DRIFT_WINDOW_K { self.count += 1; }
    }

    /// Retorna slice ordenado cronologicamente (oldest → newest).
    /// Zero alloc: opera sobre buffer existente.
    pub fn ordered(&self) -> ([u8; DRIFT_WINDOW_K], usize) {
        let n = self.count;
        let mut out = [0u8; DRIFT_WINDOW_K];
        let start = if n < DRIFT_WINDOW_K {
            0
        } else {
            self.head // oldest = head quando buffer cheio
        };
        for i in 0..n {
            out[i] = self.scores[(start + i) % DRIFT_WINDOW_K];
        }
        (out, n)
    }

    pub fn len(&self) -> usize { self.count }
    pub fn is_empty(&self) -> bool { self.count == 0 }
}

/// Detecta drift crescente numa janela de scores.
///
/// Algoritmo (paper 213):
/// - Drift é assimétrico: pressão Eficiência > Segurança é o vetor crítico.
/// - Critério: ≥ DRIFT_THRESHOLD dos últimos passos são estritamente crescentes
///   E o último score ≥ High (2).
///
/// Retorna `true` se drift detectado.
pub fn detect_drift(scores: &[u8], threshold_pct: u8) -> bool {
    let n = scores.len();
    if n < 2 { return false; }

    // Último score deve ser >= Medium (2) para ser relevante
    if *scores.last().unwrap_or(&0) < DriftScore::Medium.as_u8() {
        return false;
    }

    let mut ascending = 0usize;
    for i in 1..n {
        if scores[i] > scores[i - 1] { ascending += 1; }
    }

    let pct = (ascending * 100) / (n - 1);
    pct >= threshold_pct as usize
}

// ── Extensão de TechnicalEvidence (via _reserved_metadata[40]) ──────────────

/// Offset do flags byte para PROP-038 em _reserved_metadata.
pub const DRIFT_FLAG_OFFSET: usize = 40;
/// Bit 0 do flags byte = policy_drift_detected.
pub const DRIFT_FLAG_BIT: u8 = 0b0000_0001;

/// Define `policy_drift_detected` no flags byte de `_reserved_metadata[40]`.
/// Zero heap: opera sobre slice existente.
pub fn set_policy_drift_flag(reserved_metadata: &mut [u8], detected: bool) {
    if reserved_metadata.len() > DRIFT_FLAG_OFFSET {
        if detected {
            reserved_metadata[DRIFT_FLAG_OFFSET] |= DRIFT_FLAG_BIT;
        } else {
            reserved_metadata[DRIFT_FLAG_OFFSET] &= !DRIFT_FLAG_BIT;
        }
    }
}

/// Lê `policy_drift_detected` de `_reserved_metadata[40]` bit 0.
pub fn get_policy_drift_flag(reserved_metadata: &[u8]) -> bool {
    reserved_metadata
        .get(DRIFT_FLAG_OFFSET)
        .map(|b| b & DRIFT_FLAG_BIT != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DriftScore ────────────────────────────────────────────────────────

    #[test]
    fn test_from_str_known() {
        assert_eq!(DriftScore::from_str("None"),     DriftScore::None);
        assert_eq!(DriftScore::from_str("Low"),      DriftScore::Low);
        assert_eq!(DriftScore::from_str("Medium"),   DriftScore::Medium);
        assert_eq!(DriftScore::from_str("High"),     DriftScore::High);
        assert_eq!(DriftScore::from_str("Critical"), DriftScore::Critical);
    }

    #[test]
    fn test_from_str_unknown_is_none() {
        assert_eq!(DriftScore::from_str("unknown"), DriftScore::None);
        assert_eq!(DriftScore::from_str(""),        DriftScore::None);
    }

    // ── GoalDriftBuffer ───────────────────────────────────────────────────

    #[test]
    fn test_buffer_push_and_len() {
        let mut buf = GoalDriftBuffer::new();
        assert_eq!(buf.len(), 0);
        buf.push(DriftScore::Low);
        assert_eq!(buf.len(), 1);
        buf.push(DriftScore::Medium);
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn test_buffer_wraps_at_capacity() {
        let mut buf = GoalDriftBuffer::new();
        for i in 0..DRIFT_WINDOW_K + 3 {
            buf.push(DriftScore::from_str(match i % 5 {
                0 => "None", 1 => "Low", 2 => "Medium", 3 => "High", _ => "Critical",
            }));
        }
        assert_eq!(buf.len(), DRIFT_WINDOW_K);
    }

    #[test]
    fn test_buffer_ordered_chronological() {
        let mut buf = GoalDriftBuffer::new();
        buf.push(DriftScore::Low);
        buf.push(DriftScore::Medium);
        buf.push(DriftScore::High);
        let (scores, n) = buf.ordered();
        assert_eq!(n, 3);
        assert_eq!(scores[0], DriftScore::Low.as_u8());
        assert_eq!(scores[2], DriftScore::High.as_u8());
    }

    // ── detect_drift ──────────────────────────────────────────────────────

    #[test]
    fn test_no_drift_all_same() {
        let scores = [1u8, 1, 1, 1, 1];
        assert!(!detect_drift(&scores, 60));
    }

    #[test]
    fn test_no_drift_low_last_score() {
        // Crescente mas último score < Medium — não é drift relevante
        let scores = [0u8, 0, 0, 1, 1];
        assert!(!detect_drift(&scores, 50));
    }

    #[test]
    fn test_drift_detected_ascending() {
        // 4 de 4 passos crescentes, último = Critical(4)
        let scores = [0u8, 1, 2, 3, 4];
        assert!(detect_drift(&scores, 60));
    }

    #[test]
    fn test_drift_not_detected_below_threshold() {
        // 1 de 4 passos crescentes (25%) < threshold 60%
        let scores = [2u8, 3, 2, 2, 2];
        assert!(!detect_drift(&scores, 60));
    }

    #[test]
    fn test_detect_drift_too_short() {
        assert!(!detect_drift(&[3u8], 60));
        assert!(!detect_drift(&[], 60));
    }

    // ── Flag helpers ──────────────────────────────────────────────────────

    #[test]
    fn test_set_get_drift_flag_true() {
        let mut meta = [0u8; 64];
        set_policy_drift_flag(&mut meta, true);
        assert!(get_policy_drift_flag(&meta));
    }

    #[test]
    fn test_set_get_drift_flag_false() {
        let mut meta = [0u8; 64];
        meta[DRIFT_FLAG_OFFSET] = 0xFF; // todos os bits setados
        set_policy_drift_flag(&mut meta, false);
        assert!(!get_policy_drift_flag(&meta));
        // outros bits preservados
        assert_eq!(meta[DRIFT_FLAG_OFFSET], 0xFE);
    }

    #[test]
    fn test_flag_does_not_corrupt_skill_hash_region() {
        // skill_hash está em [8..40], flag em [40] — não devem se sobrepor
        let mut meta = [0xABu8; 64];
        set_policy_drift_flag(&mut meta, true);
        // [8..40] intactos
        for i in 8..40 { assert_eq!(meta[i], 0xAB); }
    }
}
