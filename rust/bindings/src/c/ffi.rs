//! C Foreign Function Interface
//!
//! Funções exportadas com `#[no_mangle]` para interoperabilidade C.
//!
//! # Safety
//! Todas as funções que recebem pointers raw são `unsafe` e requerem
//! que os ponteiros sejam válidos e não nulos.

use std::slice;
use super::TechnicalEvidence;

/// Scans input for technical evidence (C-compatible interface)
///
/// # Safety
/// - `input_ptr` must point to a valid buffer of at least `input_len` bytes
/// - `input_len` must be the exact length of the buffer
/// - `output_ptr` must point to a valid `TechnicalEvidence` struct
///
/// # Returns
/// - `0` on success
/// - `-1` on null pointer
/// - `-2` on invalid input
/// - `-3` on processing error
#[no_mangle]
pub unsafe extern "C" fn btv_scan_for_evidence(
    input_ptr: *const u8,
    input_len: usize,
    output_ptr: *mut TechnicalEvidence,
) -> i32 {
    // Validação de ponteiros
    if input_ptr.is_null() || output_ptr.is_null() {
        return -1;
    }

    if input_len == 0 || input_len > 10 * 1024 * 1024 { // 10MB max
        return -2;
    }

    // Converte para slice seguro
    let input_slice = slice::from_raw_parts(input_ptr, input_len);

    // Processamento real - substitua por sua lógica
    match process_evidence(input_slice) {
        Ok(evidence) => {
            // Escreve resultado no ponteiro de saída
            *output_ptr = evidence;
            0 // Sucesso
        }
        Err(_) => -3, // Erro de processamento
    }
}

/// Versão da API C
#[no_mangle]
pub extern "C" fn btv_api_version() -> u32 {
    super::C_API_VERSION
}

/// Inicializa o sistema (pode ser chamado uma vez no início)
#[no_mangle]
pub extern "C" fn btv_initialize() -> i32 {
    // Inicialização do sistema
    // Retorna 0 em sucesso, negativo em erro
    0
}

/// Libera recursos (chamar no final)
#[no_mangle]
pub extern "C" fn btv_cleanup() {
    // Cleanup se necessário
}

// Função de processamento interna
fn process_evidence(input: &[u8]) -> anyhow::Result<TechnicalEvidence> {
    // TODO: Implementar processamento real com kernel
    let evidence = TechnicalEvidence {
        protocol_version: 2,
        audit_trail_id: 123456789,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        evidence_hash: sha256_hash(input),
        composite_risk: calculate_risk(input),
        input_size: input.len(),
        processing_time_us: 0, // Será preenchido
    };

    Ok(evidence)
}

// Funções auxiliares
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.into()
}

fn calculate_risk(_data: &[u8]) -> u8 {
    // TODO: Implementar cálculo de risco real
    42 // Placeholder
}