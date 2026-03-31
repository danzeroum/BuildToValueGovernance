//! Cliente read-only para o Transparency Log (btv-sigma).
//!
//! O Judiciário consulta o log DIRETAMENTE — nunca através do Executivo.
//! Paper 5, Theorem 3.4: "J pode verificar sem consultar E."
use crate::hmac_verify::JudicialError;

#[derive(serde::Deserialize)]
struct RootResponse {
    root: [u8; 32],
    #[allow(dead_code)]
    tree_size: u64,
}

#[derive(serde::Deserialize)]
struct ProofResponse {
    #[allow(dead_code)]
    leaf_hash: [u8; 32],
    proof: Vec<[u8; 32]>,
    #[allow(dead_code)]
    root: [u8; 32],
}

/// Cliente read-only para btv-sigma.
#[derive(Clone)]
pub struct LedgerQuery {
    endpoint: String,
    http: reqwest::Client,
}

impl LedgerQuery {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint, http: reqwest::Client::new() }
    }

    pub fn from_env() -> Self {
        let endpoint = std::env::var("BTV_SIGMA_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:3100".into());
        Self::new(endpoint)
    }

    /// Busca o Merkle root atual do log. Dado público — sem autenticação.
    pub async fn current_root(&self) -> Result<[u8; 32], JudicialError> {
        let resp = self.http
            .get(format!("{}/root", self.endpoint))
            .send().await
            .map_err(|e| JudicialError::LogQueryFailed(e.to_string()))?;
        let body: RootResponse = resp.json().await
            .map_err(|e| JudicialError::LogQueryFailed(e.to_string()))?;
        Ok(body.root)
    }

    /// Busca um Merkle inclusion proof para um dado índice.
    pub async fn get_proof(
        &self,
        index: u64,
    ) -> Result<btv_types::MerkleProof, JudicialError> {
        let resp = self.http
            .get(format!("{}/proof/{}", self.endpoint, index))
            .send().await
            .map_err(|e| JudicialError::LogQueryFailed(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(JudicialError::LogQueryFailed(
                format!("Proof not found for index {index}")
            ));
        }

        let body: ProofResponse = resp.json().await
            .map_err(|e| JudicialError::LogQueryFailed(e.to_string()))?;

        Ok(btv_types::MerkleProof { path: body.proof, leaf_index: index })
    }
}
