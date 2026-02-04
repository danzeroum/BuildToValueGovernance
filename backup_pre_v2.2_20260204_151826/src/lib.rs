
//! BuildToValue Rust SDK
//!
//! Ethical governance and policy enforcement client for Rust applications.
//!
//! # Installation
//!
//! Add to `Cargo.toml`:
//! ```toml
//! [dependencies]
//! buildtovalue = "2.0"
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! # Example
//!
//! ```no_run
//! use buildtovalue::{Client, ValidateRequest};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = Client::new("btv_your_key_here");
//!     
//!     let result = client.validate(ValidateRequest {
//!         text: Some("My CPF is 123.456.789-09".to_string()),
//!         session_id: "session_123".to_string(),
//!         ..Default::default()
//!     }).await?;
//!     
//!     println!("Action: {:?}", result.action);
//!     Ok(())
//! }
//! ```

use reqwest::{Client as HttpClient, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Allow,
    Educate,
    Redact,
    Log,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    General,
    Healthcare,
    Financial,
    Educational,
    Research,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Context {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_role: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ValidateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub structured_data: Option<HashMap<String, serde_json::Value>>,
    
    pub session_id: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<ValidateOptions>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ValidateOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explain: Option<bool>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_evidence: Option<bool>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#async: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Finding {
    pub r#type: String,
    pub location: String,
    pub value: String,
    pub confidence: f64,
    pub severity: String,
    pub validator: String,
    
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Statistics {
    pub entropy: f64,
    pub length: usize,
    
    #[serde(default)]
    pub char_distribution: HashMap<String, usize>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub z_score: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TechnicalEvidence {
    pub protocol_version: u8,
    pub finding_count: usize,
    pub critical_count: usize,
    pub findings: Vec<Finding>,
    pub critical_findings: Vec<Finding>,
    pub statistics: Statistics,
    pub has_pii: bool,
    pub has_sensitive_data: bool,
    pub evidence_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppealInfo {
    pub can_appeal: bool,
    pub appeal_url: String,
    pub sla_hours: u32,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appeal_instructions: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidationResult {
    pub verdict_id: String,
    pub action: Action,
    pub confidence: f64,
    pub rationale: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical_evidence: Option<TechnicalEvidence>,
    
    #[serde(default)]
    pub mercy_applied: bool,
    
    #[serde(default)]
    pub mercy_factors: Vec<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appeal_info: Option<AppealInfo>,
    
    pub processing_time_ms: u32,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchValidateRequest {
    pub inputs: Vec<BatchInput>,
    pub session_id: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchInput {
    pub id: String,
    pub text: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchValidationResult {
    pub batch_id: String,
    pub results: Vec<BatchValidationResultItem>,
    pub total_processing_time_ms: u32,
    pub timestamp: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchValidationResultItem {
    pub input_id: String,
    #[serde(flatten)]
    pub result: ValidationResult,
}

// ═══════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Error)]
pub enum BuildToValueError {
    #[error("API error: {code} - {message}")]
    ApiError {
        code: String,
        message: String,
        details: Option<HashMap<String, serde_json::Value>>,
    },
    
    #[error("Rate limit exceeded (retry after {retry_after_seconds}s)")]
    RateLimitError {
        message: String,
        retry_after_seconds: u32,
    },
    
    #[error("Authentication failed: {0}")]
    AuthenticationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
    #[serde(default)]
    details: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    retry_after_seconds: Option<u32>,
}

// ═══════════════════════════════════════════════════════════════
// Client
// ═══════════════════════════════════════════════════════════════

/// BuildToValue API client
pub struct Client {
    api_key: String,
    base_url: String,
    http_client: HttpClient,
}

impl Client {
    /// Create a new client with the given API key
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: "https://api.buildtovalue.com/v2".to_string(),
            http_client: HttpClient::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }
    
    /// Set a custom base URL (for testing/staging)
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }
    
    /// Set a custom timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.http_client = HttpClient::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to build HTTP client");
        self
    }
    
    /// Validate user input
    pub async fn validate(&self, request: ValidateRequest) -> Result<ValidationResult, BuildToValueError> {
        self.post("/validate", &request).await
    }
    
    /// Batch validate multiple inputs
    pub async fn validate_batch(&self, request: BatchValidateRequest) -> Result<BatchValidationResult, BuildToValueError> {
        self.post("/validate/batch", &request).await
    }
    
    /// Submit an appeal
    pub async fn submit_appeal(&self, verdict_id: &str, reason: &str) -> Result<String, BuildToValueError> {
        #[derive(Serialize)]
        struct AppealRequest {
            verdict_id: String,
            reason: String,
        }
        
        #[derive(Deserialize)]
        struct AppealResponse {
            appeal_id: String,
        }
        
        let response: AppealResponse = self.post(
            "/appeals",
            &AppealRequest {
                verdict_id: verdict_id.to_string(),
                reason: reason.to_string(),
            },
        ).await?;
        
        Ok(response.appeal_id)
    }
    
    /// Health check
    pub async fn health_check(&self) -> Result<HashMap<String, serde_json::Value>, BuildToValueError> {
        self.get("/health").await
    }
    
    // ─────────────────────────────────────────────────────────────
    // Internal methods
    // ─────────────────────────────────────────────────────────────
    
    async fn post<T, R>(&self, path: &str, body: &T) -> Result<R, BuildToValueError>
    where
        T: Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        
        let response = self.http_client
            .post(&url)
            .header("X-API-Key", &self.api_key)
            .header("Content-Type", "application/json")
            .header("User-Agent", "BuildToValue-Rust-SDK/2.0.0")
            .json(body)
            .send()
            .await?;
        
        self.handle_response(response).await
    }
    
    async fn get<R>(&self, path: &str) -> Result<R, BuildToValueError>
    where
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        
        let response = self.http_client
            .get(&url)
            .header("X-API-Key", &self.api_key)
            .header("User-Agent", "BuildToValue-Rust-SDK/2.0.0")
            .send()
            .await?;
        
        self.handle_response(response).await
    }
    
    async fn handle_response<R>(&self, response: reqwest::Response) -> Result<R, BuildToValueError>
    where
        R: serde::de::DeserializeOwned,
    {
        let status = response.status();
        
        if status.is_success() {
            let body = response.json::<R>().await?;
            return Ok(body);
        }
        
        // Parse error response
        let error_response = response.json::<ErrorResponse>().await?;
        
        match status {
            StatusCode::TOO_MANY_REQUESTS => {
                Err(BuildToValueError::RateLimitError {
                    message: error_response.message,
                    retry_after_seconds: error_response.retry_after_seconds.unwrap_or(60),
                })
            }
            StatusCode::UNAUTHORIZED => {
                Err(BuildToValueError::AuthenticationError(error_response.message))
            }
            _ => {
                Err(BuildToValueError::ApiError {
                    code: error_response.error,
                    message: error_response.message,
                    details: error_response.details,
                })
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Builder Patterns
// ═══════════════════════════════════════════════════════════════

impl ValidateRequest {
    pub fn builder(session_id: impl Into<String>) -> ValidateRequestBuilder {
        ValidateRequestBuilder {
            request: ValidateRequest {
                session_id: session_id.into(),
                ..Default::default()
            },
        }
    }
}

pub struct ValidateRequestBuilder {
    request: ValidateRequest,
}

impl ValidateRequestBuilder {
    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.request.text = Some(text.into());
        self
    }
    
    pub fn structured_data(mut self, data: HashMap<String, serde_json::Value>) -> Self {
        self.request.structured_data = Some(data);
        self
    }
    
    pub fn profile(mut self, profile: Profile) -> Self {
        self.request.profile = Some(profile);
        self
    }
    
    pub fn context(mut self, context: Context) -> Self {
        self.request.context = Some(context);
        self
    }
    
    pub fn build(self) -> ValidateRequest {
        self.request
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_builder_pattern() {
        let request = ValidateRequest::builder("session_123")
            .text("My CPF is 123.456.789-09")
            .profile(Profile::General)
            .build();
        
        assert_eq!(request.session_id, "session_123");
        assert_eq!(request.text, Some("My CPF is 123.456.789-09".to_string()));
        assert_eq!(request.profile, Some(Profile::General));
    }
}