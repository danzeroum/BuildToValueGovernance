//! Network Validators (IP, DNS, URL)
//!
//! Detecta:
//! - IPv4 addresses
//! - IPv6 addresses (básico)
//! - Domain names
//! - URLs (http/https)
//!
//! Gate: Week 3 - Day 13

use super::{Validator, ValidationResult};
use regex::Regex;
use once_cell::sync::Lazy;
use std::net::{IpAddr, Ipv4Addr};

// ═══════════════════════════════════════════════════════════════════════════
// REGEX PATTERNS
// ═══════════════════════════════════════════════════════════════════════════

static IPV4_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https?://[^\s<>\"{}|\\^`\[\]]+").unwrap()
});

static DOMAIN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b").unwrap()
});

// ═══════════════════════════════════════════════════════════════════════════
// IPV4 VALIDATOR
// ═══════════════════════════════════════════════════════════════════════════

pub struct Ipv4Validator;

impl Ipv4Validator {
    /// Classifica IP
    fn classify_ip(ip: &str) -> IpClass {
        if let Ok(addr) = ip.parse::<Ipv4Addr>() {
            let octets = addr.octets();

            // Private ranges (RFC 1918)
            if octets[0] == 10 {
                return IpClass::Private;
            }
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return IpClass::Private;
            }
            if octets[0] == 192 && octets[1] == 168 {
                return IpClass::Private;
            }

            // Loopback
            if octets[0] == 127 {
                return IpClass::Loopback;
            }

            // Link-local
            if octets[0] == 169 && octets[1] == 254 {
                return IpClass::LinkLocal;
            }

            // Multicast
            if (224..=239).contains(&octets[0]) {
                return IpClass::Multicast;
            }

            IpClass::Public
        } else {
            IpClass::Invalid
        }
    }
}

#[derive(Debug, PartialEq)]
enum IpClass {
    Public,
    Private,
    Loopback,
    LinkLocal,
    Multicast,
    Invalid,
}

impl Validator for Ipv4Validator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        for capture in IPV4_REGEX.find_iter(input) {
            let ip = capture.as_str();
            let class = Self::classify_ip(ip);

            // Severidade baseada na classe
            let (severity, confidence) = match class {
                IpClass::Public => (0.7, 0.9),      // HIGH
                IpClass::Private => (0.4, 0.9),     // MEDIUM
                IpClass::Loopback => (0.2, 0.95),   // LOW
                IpClass::LinkLocal => (0.3, 0.9),   // LOW-MEDIUM
                IpClass::Multicast => (0.3, 0.9),   // LOW-MEDIUM
                IpClass::Invalid => continue,        // Skip
            };

            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: format!("IPv4 address detected: {} ({:?})", ip, class),
                category: "network".to_string(),
                location: format!("offset {}", capture.start()),
                evidence: ip.to_string(),
                severity,
                confidence,
            });
        }

        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// URL VALIDATOR
// ═══════════════════════════════════════════════════════════════════════════

pub struct UrlValidator;

impl UrlValidator {
    /// Classifica URL por risco
    fn classify_url(url: &str) -> UrlRisk {
        let lower = url.to_lowercase();

        // Suspeito: IP direto em URL
        if IPV4_REGEX.is_match(&lower) {
            return UrlRisk::Suspicious;
        }

        // Suspeito: portas não-padrão
        if lower.contains(":8080") || lower.contains(":3000") || lower.contains(":8000") {
            return UrlRisk::Suspicious;
        }

        // Suspeito: domínios curtos (<3 chars)
        if let Some(domain) = lower.split("://").nth(1) {
            if let Some(host) = domain.split('/').next() {
                if host.len() < 5 {
                    return UrlRisk::Suspicious;
                }
            }
        }

        UrlRisk::Normal
    }
}

#[derive(Debug, PartialEq)]
enum UrlRisk {
    Normal,
    Suspicious,
}

impl Validator for UrlValidator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        for capture in URL_REGEX.find_iter(input) {
            let url = capture.as_str();
            let risk = Self::classify_url(url);

            let (severity, confidence) = match risk {
                UrlRisk::Suspicious => (0.6, 0.8),
                UrlRisk::Normal => (0.3, 0.9),
            };

            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: format!("URL detected: {} ({:?})", url, risk),
                category: "network".to_string(),
                location: format!("offset {}", capture.start()),
                evidence: url.to_string(),
                severity,
                confidence,
            });
        }

        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DOMAIN VALIDATOR
// ═══════════════════════════════════════════════════════════════════════════

pub struct DomainValidator;

impl Validator for DomainValidator {
    fn validate(&self, input: &str, name: &str) -> Option<ValidationResult> {
        for capture in DOMAIN_REGEX.find_iter(input) {
            let domain = capture.as_str();

            // Skip domínios muito comuns (whitelist)
            if domain.ends_with("example.com") || domain.ends_with("localhost") {
                continue;
            }

            return Some(ValidationResult {
                validator_name: name.to_string(),
                is_violation: true,
                message: format!("Domain name detected: {}", domain),
                category: "network".to_string(),
                location: format!("offset {}", capture.start()),
                evidence: domain.to_string(),
                severity: 0.3,
                confidence: 0.7,
            });
        }

        None
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTES
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_public() {
        let validator = Ipv4Validator;
        let result = validator.validate("Server: 8.8.8.8", "ipv4");

        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.severity, 0.7); // HIGH
    }

    #[test]
    fn test_ipv4_private() {
        let validator = Ipv4Validator;
        let result = validator.validate("IP: 192.168.1.1", "ipv4");

        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, 0.4); // MEDIUM
    }

    #[test]
    fn test_ipv4_loopback() {
        let validator = Ipv4Validator;
        let result = validator.validate("Localhost: 127.0.0.1", "ipv4");

        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, 0.2); // LOW
    }

    #[test]
    fn test_url_detection() {
        let validator = UrlValidator;
        let result = validator.validate("Visit https://example.com/page", "url");

        assert!(result.is_some());
        assert!(result.unwrap().evidence.contains("https://"));
    }

    #[test]
    fn test_url_suspicious() {
        let validator = UrlValidator;
        let result = validator.validate("URL: http://192.168.1.1:8080", "url");

        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, 0.6); // Suspicious
    }

    #[test]
    fn test_domain() {
        let validator = DomainValidator;
        let result = validator.validate("Email: user@company.com", "domain");

        assert!(result.is_some());
        assert!(result.unwrap().evidence.contains("company.com"));
    }
}
