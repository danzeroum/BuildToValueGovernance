//! goal_drift_ffi — Gap 4: FFI bindings para GoalDriftBuffer (C ABI).
//!
//! Expõe o GoalDriftBuffer do kernel Rust para uso em Python via ctypes/cffi.
//! Segue o padrão de validators_ffi.rs: funções C com #[no_mangle].
//!
//! Funções exportadas:
//!   btv_goal_drift_push  — insere score na janela de drift da sessão
//!   btv_goal_drift_score — retorna score de drift atual
//!   btv_goal_drift_reset — limpa janela da sessão
//!
//! Códigos de retorno: 0 = ok, -1 = session_not_found, -2 = invalid_input
//!
//! Fail-secure: ponteiro nulo ou sessão ausente → retorna -1 (erro).

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_float, c_int};
use std::sync::Mutex;

use crate::validators::goal_drift::{detect_drift, DriftScore, GoalDriftBuffer, DRIFT_WINDOW_K};

/// Código de erro: operação bem-sucedida.
const FFI_OK: c_int = 0;
/// Código de erro: sessão não encontrada.
const FFI_ERR_SESSION: c_int = -1;
/// Código de erro: entrada inválida (ponteiro nulo ou valor fora de range).
const FFI_ERR_INPUT: c_int = -2;

/// Registro de uma sessão de drift no estado global.
struct DriftSession {
    buffer: GoalDriftBuffer,
}

/// Estado global: mapa session_id → DriftSession.
/// Protegido por Mutex; fail-secure em caso de poisoning (retorna erro).
static DRIFT_SESSIONS: std::sync::LazyLock<Mutex<HashMap<String, DriftSession>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// Funções FFI exportadas
// ---------------------------------------------------------------------------

/// Insere `action_category_hash` (hash u64 da categoria de ação) no buffer
/// de drift da sessão identificada por `session_id`.
///
/// O hash é mapeado para DriftScore por módulo 5 (0..=4).
///
/// # Retorno
/// - 0 → ok (entrada registrada)
/// - -1 → session_id é NULL ou UTF-8 inválido
/// - -2 → valor inválido
#[no_mangle]
pub extern "C" fn btv_goal_drift_push(
    session_id: *const c_char,
    action_category_hash: u64,
) -> c_int {
    let sid = match parse_session_id(session_id) {
        Some(s) => s,
        None    => return FFI_ERR_SESSION,
    };

    let score = DriftScore::from_u8((action_category_hash % 5) as u8);

    match DRIFT_SESSIONS.lock() {
        Err(_) => FFI_ERR_SESSION, // mutex poisoned → fail-secure
        Ok(mut map) => {
            let entry = map.entry(sid).or_insert_with(|| DriftSession {
                buffer: GoalDriftBuffer::new(),
            });
            entry.buffer.push(score);
            FFI_OK
        }
    }
}

/// Retorna o score de drift atual da sessão.
///
/// Escreve o score normalizado (0.0 = None, 1.0 = Critical) em `out_score`.
///
/// # Retorno
/// - 0 → ok, `*out_score` preenchido
/// - -1 → session_id NULL, sessão não encontrada ou mutex poisoned
/// - -2 → `out_score` é NULL
#[no_mangle]
pub extern "C" fn btv_goal_drift_score(
    session_id: *const c_char,
    out_score: *mut c_float,
) -> c_int {
    if out_score.is_null() {
        return FFI_ERR_INPUT;
    }

    let sid = match parse_session_id(session_id) {
        Some(s) => s,
        None    => return FFI_ERR_SESSION,
    };

    match DRIFT_SESSIONS.lock() {
        Err(_) => FFI_ERR_SESSION,
        Ok(map) => {
            match map.get(&sid) {
                None => FFI_ERR_SESSION,
                Some(session) => {
                    let (scores_arr, len) = session.buffer.ordered();
                    let scores = &scores_arr[..len];
                    let drift = detect_drift(scores, 60); // threshold 60%
                    // Normaliza: drift detectado → score = última entrada / 4.0
                    let normalized = if drift && len > 0 {
                        scores[len - 1] as f32 / 4.0
                    } else {
                        0.0_f32
                    };
                    // SAFETY: verificamos out_score não-nulo acima
                    unsafe { *out_score = normalized };
                    FFI_OK
                }
            }
        }
    }
}

/// Limpa o buffer de drift da sessão `session_id`.
///
/// # Retorno
/// - 0 → ok (buffer limpo)
/// - -1 → session_id NULL, sessão não encontrada ou mutex poisoned
#[no_mangle]
pub extern "C" fn btv_goal_drift_reset(session_id: *const c_char) -> c_int {
    let sid = match parse_session_id(session_id) {
        Some(s) => s,
        None    => return FFI_ERR_SESSION,
    };

    match DRIFT_SESSIONS.lock() {
        Err(_) => FFI_ERR_SESSION,
        Ok(mut map) => {
            map.remove(&sid);
            FFI_OK
        }
    }
}

// ---------------------------------------------------------------------------
// Auxiliares internos
// ---------------------------------------------------------------------------

/// Converte `*const c_char` para `String`. Retorna `None` para ponteiro nulo
/// ou UTF-8 inválido (fail-secure).
fn parse_session_id(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: verificamos ptr não-nulo; a string C deve ser válida e terminada em null
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().ok().map(|s| s.to_owned())
}

// ---------------------------------------------------------------------------
// Extensão de DriftScore para suportar from_u8 via u8
// ---------------------------------------------------------------------------

impl DriftScore {
    /// Constrói DriftScore a partir de u8 (0–4). Valores > 4 → Critical.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => DriftScore::None,
            1 => DriftScore::Low,
            2 => DriftScore::Medium,
            3 => DriftScore::High,
            _ => DriftScore::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn sid(s: &str) -> CString {
        CString::new(s).expect("CString válido")
    }

    #[test]
    fn test_push_and_score_ok() {
        let id = sid("test-session-push");
        btv_goal_drift_reset(id.as_ptr()); // limpar estado de testes anteriores

        // Inserir 7 scores ascendentes (sem drift ainda — janela = 10)
        for i in 0u64..7 {
            assert_eq!(btv_goal_drift_push(id.as_ptr(), i % 5), FFI_OK);
        }
        let mut score: c_float = -1.0;
        assert_eq!(btv_goal_drift_score(id.as_ptr(), &mut score), FFI_OK);
        assert!(score >= 0.0 && score <= 1.0, "score deve estar em [0,1]");
    }

    #[test]
    fn test_null_session_id_returns_error() {
        assert_eq!(btv_goal_drift_push(std::ptr::null(), 1), FFI_ERR_SESSION);
        let mut score: c_float = 0.0;
        assert_eq!(btv_goal_drift_score(std::ptr::null(), &mut score), FFI_ERR_SESSION);
        assert_eq!(btv_goal_drift_reset(std::ptr::null()), FFI_ERR_SESSION);
    }

    #[test]
    fn test_null_out_score_returns_error() {
        let id = sid("test-null-out");
        assert_eq!(btv_goal_drift_score(id.as_ptr(), std::ptr::null_mut()), FFI_ERR_INPUT);
    }

    #[test]
    fn test_unknown_session_score_returns_error() {
        let id = sid("session-never-pushed");
        let mut score: c_float = 0.0;
        assert_eq!(btv_goal_drift_score(id.as_ptr(), &mut score), FFI_ERR_SESSION);
    }

    #[test]
    fn test_reset_clears_session() {
        let id = sid("test-reset");
        btv_goal_drift_push(id.as_ptr(), 4);
        assert_eq!(btv_goal_drift_reset(id.as_ptr()), FFI_OK);
        let mut score: c_float = 0.0;
        // após reset, sessão não existe
        assert_eq!(btv_goal_drift_score(id.as_ptr(), &mut score), FFI_ERR_SESSION);
    }
}
