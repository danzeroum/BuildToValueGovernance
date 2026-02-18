//! OpenTelemetry W3C Trace Propagation middleware.
//! Extracts/injects `traceparent` header for distributed tracing.
//! Jonas: accountability requires traceability across boundaries.

use axum::{
    body::Body,
    http::{Request, Response, HeaderValue},
    middleware::Next,
};
use uuid::Uuid;

const TRACEPARENT: &str = "traceparent";
const VERSION: &str = "00";

/// Extract or generate W3C traceparent.
/// Format: 00-{trace_id}-{span_id}-{flags}
pub async fn trace_propagation(
    mut req: Request<Body>,
    next: Next,
) -> Response<Body> {
    // Extract existing traceparent or generate new
    let (trace_id, parent_span) = match req.headers().get(TRACEPARENT) {
        Some(val) => parse_traceparent(val),
        None => (generate_trace_id(), "0000000000000000".to_string()),
    };

    let span_id = generate_span_id();
    let traceparent = format!("{}-{}-{}-01", VERSION, trace_id, span_id);

    // Inject into request extensions for downstream use
    req.extensions_mut().insert(TraceContext {
        trace_id: trace_id.clone(),
        span_id: span_id.clone(),
        parent_span_id: parent_span,
    });

    let mut response = next.run(req).await;

    // Inject traceparent into response
    if let Ok(val) = HeaderValue::from_str(&traceparent) {
        response.headers_mut().insert(TRACEPARENT, val);
    }

    response
}

#[derive(Clone, Debug)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: String,
}

fn parse_traceparent(val: &HeaderValue) -> (String, String) {
    let s = val.to_str().unwrap_or("");
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() >= 4 {
        (parts[1].to_string(), parts[2].to_string())
    } else {
        (generate_trace_id(), "0000000000000000".to_string())
    }
}

fn generate_trace_id() -> String {
    Uuid::new_v4().as_simple().to_string()
}

fn generate_span_id() -> String {
    let id = Uuid::new_v4();
    id.as_simple().to_string()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_trace_id_length() {
        let id = generate_trace_id();
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn test_generate_span_id_length() {
        let id = generate_span_id();
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_parse_valid_traceparent() {
        let val = HeaderValue::from_static("00-abcd1234abcd1234abcd1234abcd1234-1234567890abcdef-01");
        let (trace, parent) = parse_traceparent(&val);
        assert_eq!(trace, "abcd1234abcd1234abcd1234abcd1234");
        assert_eq!(parent, "1234567890abcdef");
    }

    #[test]
    fn test_parse_invalid_traceparent() {
        let val = HeaderValue::from_static("garbage");
        let (trace, _parent) = parse_traceparent(&val);
        assert_eq!(trace.len(), 32); // Generated new
    }
}