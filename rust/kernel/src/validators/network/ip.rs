//! Network Validators (IP, DNS, URL) v2.3.1
//!
//! Detecta infraestrutura de rede e classifica por nível de risco.

use crate::evidence::finding::Finding;
use crate::core::types::{ValidatorModule, TechnicalSeverity};
use regex::Regex;
use lazy_static::lazy_static; // Alterado de once_cell para manter consistência com outros arquivos
use std::net::Ipv4Addr;

// ═══════════════════════════════════════════════════════════════════════════
// REGEX PATTERNS
// ═══════════════════════════════════════════════════════════════════════════

lazy_static! {
    static ref IPV4_REGEX: Regex = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ).unwrap();

    // ✅ CORREÇÃO: Usando r#""# para permitir aspas duplas literais sem erro de token
    static ref URL_REGEX: Regex = Regex::new(
        r#"https?://[^\s<>"{}\||\\^`\[\]]+"#
    ).unwrap();

    static ref DOMAIN_REGEX: Regex = Regex::new(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ).unwrap();
}

// ═══════════════════════════════════════════════════════════════════════════
// IPV4 VALIDATOR
// ═══════════════════════════════════════════════════════════════════════════

impl Default for Ipv4Validator {
    fn default() -> Self { Self::new() }
}
pub struct Ipv4Validator {
    rule_id: String,
}

#[derive(Debug, PartialEq)]
enum IpClass { Public, Private, Loopback, LinkLocal, Multicast, Invalid }

impl Ipv4Validator {
    pub fn new() -> Self {
        Self { rule_id: "VALIDATORS_NET_IP_001".to_string() }
    }

    fn classify_ip(ip: &str) -> IpClass {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            let octets = addr.octets();
            if octets[0] == 10 || (octets[0] == 172 && (16..=31).contains(&octets[1])) || (octets[0] == 192 && octets[1] == 168) {
                return IpClass::Private;
            }
            if octets[0] == 127 { return IpClass::Loopback; }
            if octets[0] == 169 && octets[1] == 254 { return IpClass::LinkLocal; }
            if (224..=239).contains(&octets[0]) { return IpClass::Multicast; }
            IpClass::Public
        } else {
            IpClass::Invalid
        }
    }

    pub fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for mat in IPV4_REGEX.find_iter(input) {
            let ip = mat.as_str();
            let class = Self::classify_ip(ip);

            if class == IpClass::Invalid { continue; }

            let severity = match class {
                IpClass::Public => TechnicalSeverity::High,
                IpClass::Private => TechnicalSeverity::Medium,
                _ => TechnicalSeverity::Low,
            };

            findings.push(Finding::new(
                ValidatorModule::Network,
                severity,
                &self.rule_id,
                "IPV4_DETECTED",
                &format!("IPv4 address detected: {} ({:?})", ip, class),
            )
                .with_matched_text(ip)
                .with_position(mat.start() as u16, mat.end() as u16));
        }
        findings
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// URL VALIDATOR
// ═══════════════════════════════════════════════════════════════════════════
impl Default for UrlValidator {
    fn default() -> Self { Self::new() }
}
pub struct UrlValidator {
    rule_id: String,
}

impl UrlValidator {
    pub fn new() -> Self {
        Self { rule_id: "VALIDATORS_NET_URL_001".to_string() }
    }

    pub fn validate(&self, input: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for mat in URL_REGEX.find_iter(input) {
            let url = mat.as_str();
            let severity = if IPV4_REGEX.is_match(url) || url.contains(":8080") {
                TechnicalSeverity::High
            } else {
                TechnicalSeverity::Medium
            };

            findings.push(Finding::new(
                ValidatorModule::Network,
                severity,
                &self.rule_id,
                "URL_DETECTED",
                "Network URL pattern detected",
            )
                .with_matched_text(url)
                .with_position(mat.start() as u16, mat.end() as u16));
        }
        findings
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_detection() {
        let v = Ipv4Validator::new();
        let f = v.validate("Server: 8.8.8.8");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, TechnicalSeverity::High);
    }

    #[test]
    fn test_url_detection() {
        let v = UrlValidator::new();
        let f = v.validate("Link: https://example.com");
        assert_eq!(f.len(), 1);
    }
}