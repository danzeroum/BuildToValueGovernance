//! Shared helpers for gateway routes — DRY enforcement.
//!
//! v2.3.1: Extracted from validate.rs and decide.rs to eliminate duplication.
//! Both routes had identical copies of extract_client_ip, ip_risk_to_str, and
//! FALLBACK_POLICY. Any future change only needs to happen here.

use axum::http::HeaderMap;
use buildtovalue_kernel::network::IpRisk;

/// Extract client IP from forwarded headers (X-Forwarded-For, X-Real-IP).
/// Fail-safe: returns "0.0.0.0" if no header is present.
pub fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "0.0.0.0".to_string())
}

/// Convert IpRisk enum to a static string for logging and serialization.
pub fn ip_risk_to_str(risk: IpRisk) -> &'static str {
    match risk {
        IpRisk::Low      => "Low",
        IpRisk::Medium   => "Medium",
        IpRisk::High     => "High",
        IpRisk::Critical => "Critical",
    }
}

/// Minimal fallback policy used when the compiled-in default.yaml fails to parse.
/// Should NEVER be reached in production — indicates a build or packaging issue.
pub const FALLBACK_POLICY: &str = r#"
version: "1.0"
metadata:
  name: "Fallback"
  description: "Minimal fallback"
  created_at: "2026-01-01"
  updated_at: "2026-01-01"
  author: "System"
hard_blocks:
  - "DROP TABLE"
  - "<script>"
policies: []
"#;
