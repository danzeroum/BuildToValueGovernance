//! Configurações para sincronização remota.
//! Este módulo contém definições de configuração que são usadas por vários componentes,
//! independentemente de a feature `s3` estar ativa.

use serde::{Deserialize, Serialize};

/// Configuração para conexão com S3 (ou outros backends compatíveis).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket: String,
    pub key_prefix: String,
    pub region: String,
    pub endpoint: Option<String>, // Para LocalStack/MinIO
    pub force_path_style: bool,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            bucket: "buildtovalue-ledger".to_string(),
            key_prefix: "wal/".to_string(),
            region: "us-east-1".to_string(),
            endpoint: None,
            force_path_style: false,
        }
    }
}