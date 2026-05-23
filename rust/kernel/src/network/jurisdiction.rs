//! Jurisdiction Mapper v1.7.0 — IP → Country → Compliance Framework
//!
//! Maps IP addresses to jurisdictions using GeoIP CIDR ranges.
//! Returns applicable compliance frameworks (LGPD, EU AI Act, GDPR, etc.).
//!
//! Filosofia (Rawls): Same rules apply regardless of who is behind the IP.
//! The framework selection is blind to identity — only geography matters.

use std::net::Ipv4Addr;
use std::str::FromStr;
use crate::core::types::BiasDeclaration;

// ─────────────────────────────────────────────────────────────
// JURISDICTION
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Jurisdiction {
    Brazil,
    EuropeanUnion,
    UnitedStates,
    UnitedKingdom,
    Canada,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceFramework {
    Lgpd,
    EuAiAct,
    Gdpr,
    Hipaa,
    Ccpa,
    Pipeda,
    UkGdpr,
}

#[derive(Debug, Clone)]
pub struct JurisdictionResult {
    pub ip: String,
    pub jurisdiction: Jurisdiction,
    pub country_code: &'static str,
    pub frameworks: Vec<ComplianceFramework>,
    pub confidence: u8,
}

// ─────────────────────────────────────────────────────────────
// GEO RANGE
// ─────────────────────────────────────────────────────────────

struct GeoRange {
    base: u32,
    mask: u32,
    jurisdiction: Jurisdiction,
    country_code: &'static str,
}

impl GeoRange {
    fn new(cidr: &str, jurisdiction: Jurisdiction, cc: &'static str) -> Option<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 { return None; }
        let ip = Ipv4Addr::from_str(parts[0]).ok()?;
        let prefix: u32 = parts[1].parse().ok()?;
        if prefix > 32 { return None; }
        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        Some(Self {
            base: u32::from(ip) & mask,
            mask,
            jurisdiction,
            country_code: cc,
        })
    }

    fn contains(&self, ip: u32) -> bool {
        (ip & self.mask) == self.base
    }
}

// ─────────────────────────────────────────────────────────────
// JURISDICTION MAPPER
// ─────────────────────────────────────────────────────────────

pub struct JurisdictionMapper {
    ranges: Vec<GeoRange>,
}

impl JurisdictionMapper {
    pub fn new() -> Self {
        let mut ranges = Vec::new();

        // ── BRAZIL ────────────────────────────────────────
        for cidr in &[
            "177.0.0.0/8", "179.0.0.0/8", "186.0.0.0/8",
            "187.0.0.0/8", "189.0.0.0/8", "191.0.0.0/8",
            "200.0.0.0/7", "201.0.0.0/8",
            "138.0.0.0/8", "143.0.0.0/8", "152.0.0.0/8",
        ] {
            if let Some(r) = GeoRange::new(cidr, Jurisdiction::Brazil, "BR") {
                ranges.push(r);
            }
        }

        // ── EUROPEAN UNION (major allocations) ────────────
        // DE
        for cidr in &["5.0.0.0/8", "46.0.0.0/8", "78.0.0.0/8", "85.0.0.0/8"] {
            if let Some(r) = GeoRange::new(cidr, Jurisdiction::EuropeanUnion, "EU") {
                ranges.push(r);
            }
        }
        // FR
        for cidr in &["80.0.0.0/8", "81.0.0.0/8", "82.0.0.0/8", "90.0.0.0/8"] {
            if let Some(r) = GeoRange::new(cidr, Jurisdiction::EuropeanUnion, "EU") {
                ranges.push(r);
            }
        }
        // NL, IT, ES
        for cidr in &["83.0.0.0/8", "84.0.0.0/8", "86.0.0.0/8", "87.0.0.0/8"] {
            if let Some(r) = GeoRange::new(cidr, Jurisdiction::EuropeanUnion, "EU") {
                ranges.push(r);
            }
        }

        // ── UNITED STATES ─────────────────────────────────
        for cidr in &[
            "4.0.0.0/8", "6.0.0.0/8", "7.0.0.0/8",
            "8.0.0.0/8", "9.0.0.0/8", "11.0.0.0/8",
            "12.0.0.0/8", "15.0.0.0/8", "16.0.0.0/8",
            "17.0.0.0/8", "18.0.0.0/8", "19.0.0.0/8",
            "24.0.0.0/8", "32.0.0.0/8", "44.0.0.0/8",
            "48.0.0.0/8", "50.0.0.0/8", "52.0.0.0/8",
            "54.0.0.0/8", "56.0.0.0/8", "63.0.0.0/8",
            "64.0.0.0/8", "65.0.0.0/8", "66.0.0.0/8",
            "67.0.0.0/8", "68.0.0.0/8", "69.0.0.0/8",
            "70.0.0.0/8", "71.0.0.0/8", "72.0.0.0/8",
            "73.0.0.0/8", "74.0.0.0/8", "75.0.0.0/8",
            "76.0.0.0/8", "96.0.0.0/8", "97.0.0.0/8",
            "98.0.0.0/8", "99.0.0.0/8",
        ] {
            if let Some(r) = GeoRange::new(cidr, Jurisdiction::UnitedStates, "US") {
                ranges.push(r);
            }
        }

        // ── UNITED KINGDOM ────────────────────────────────
        for cidr in &["2.0.0.0/8", "25.0.0.0/8", "51.0.0.0/8"] {
            if let Some(r) = GeoRange::new(cidr, Jurisdiction::UnitedKingdom, "GB") {
                ranges.push(r);
            }
        }

        // ── CANADA ────────────────────────────────────────
        for cidr in &["142.0.0.0/8", "198.0.0.0/8", "207.0.0.0/8"] {
            if let Some(r) = GeoRange::new(cidr, Jurisdiction::Canada, "CA") {
                ranges.push(r);
            }
        }

        Self { ranges }
    }

    pub fn classify(&self, ip_str: &str) -> JurisdictionResult {
        let ip = match Ipv4Addr::from_str(ip_str) {
            Ok(ip) => ip,
            Err(_) => return self.unknown(ip_str),
        };

        let ip_u32 = u32::from(ip);

        // Private/loopback → Unknown jurisdiction
        if Self::is_private(ip_u32) {
            return JurisdictionResult {
                ip: ip_str.to_string(),
                jurisdiction: Jurisdiction::Unknown,
                country_code: "XX",
                frameworks: Vec::new(),
                confidence: 0,
            };
        }

        for range in &self.ranges {
            if range.contains(ip_u32) {
                let frameworks = Self::frameworks_for(range.jurisdiction);
                return JurisdictionResult {
                    ip: ip_str.to_string(),
                    jurisdiction: range.jurisdiction,
                    country_code: range.country_code,
                    frameworks,
                    confidence: 70,
                };
            }
        }

        self.unknown(ip_str)
    }

    fn frameworks_for(j: Jurisdiction) -> Vec<ComplianceFramework> {
        match j {
            Jurisdiction::Brazil => vec![
                ComplianceFramework::Lgpd,
            ],
            Jurisdiction::EuropeanUnion => vec![
                ComplianceFramework::Gdpr,
                ComplianceFramework::EuAiAct,
            ],
            Jurisdiction::UnitedStates => vec![
                ComplianceFramework::Hipaa,
                ComplianceFramework::Ccpa,
            ],
            Jurisdiction::UnitedKingdom => vec![
                ComplianceFramework::UkGdpr,
            ],
            Jurisdiction::Canada => vec![
                ComplianceFramework::Pipeda,
            ],
            Jurisdiction::Unknown => Vec::new(),
        }
    }

    fn is_private(ip: u32) -> bool {
        let a = (ip >> 24) as u8;
        let b = (ip >> 16) as u8;
        a == 10
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || a == 127
    }

    fn unknown(&self, ip_str: &str) -> JurisdictionResult {
        JurisdictionResult {
            ip: ip_str.to_string(),
            jurisdiction: Jurisdiction::Unknown,
            country_code: "XX",
            frameworks: Vec::new(),
            confidence: 0,
        }
    }

    pub fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::from_static(0.15, 0.25, 20260522, 100)
            .with_limitations(
                "Static /8 CIDR blocks. Many ranges are shared across countries. \
                 No MaxMind GeoIP. Confidence is low (~70%). \
                 Use as hint, not definitive jurisdiction."
            )
            .with_affected_groups(
                "Users behind CDNs, VPNs, or corporate proxies \
                 will be misclassified."
            )
    }
}

impl Default for JurisdictionMapper {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brazil_ip() {
        let m = JurisdictionMapper::new();
        let r = m.classify("189.50.100.1");
        assert_eq!(r.jurisdiction, Jurisdiction::Brazil);
        assert_eq!(r.country_code, "BR");
        assert!(r.frameworks.contains(&ComplianceFramework::Lgpd));
    }

    #[test]
    fn test_eu_ip() {
        let m = JurisdictionMapper::new();
        let r = m.classify("85.10.20.30");
        assert_eq!(r.jurisdiction, Jurisdiction::EuropeanUnion);
        assert!(r.frameworks.contains(&ComplianceFramework::Gdpr));
        assert!(r.frameworks.contains(&ComplianceFramework::EuAiAct));
    }

    #[test]
    fn test_us_ip() {
        let m = JurisdictionMapper::new();
        let r = m.classify("8.8.8.8");
        assert_eq!(r.jurisdiction, Jurisdiction::UnitedStates);
        assert!(r.frameworks.contains(&ComplianceFramework::Hipaa));
        assert!(r.frameworks.contains(&ComplianceFramework::Ccpa));
    }

    #[test]
    fn test_uk_ip() {
        let m = JurisdictionMapper::new();
        let r = m.classify("2.100.50.1");
        assert_eq!(r.jurisdiction, Jurisdiction::UnitedKingdom);
        assert!(r.frameworks.contains(&ComplianceFramework::UkGdpr));
    }

    #[test]
    fn test_canada_ip() {
        let m = JurisdictionMapper::new();
        let r = m.classify("142.10.20.30");
        assert_eq!(r.jurisdiction, Jurisdiction::Canada);
        assert!(r.frameworks.contains(&ComplianceFramework::Pipeda));
    }

    #[test]
    fn test_private_ip_unknown() {
        let m = JurisdictionMapper::new();
        let r = m.classify("192.168.1.1");
        assert_eq!(r.jurisdiction, Jurisdiction::Unknown);
        assert!(r.frameworks.is_empty());
    }

    #[test]
    fn test_loopback_unknown() {
        let m = JurisdictionMapper::new();
        let r = m.classify("127.0.0.1");
        assert_eq!(r.jurisdiction, Jurisdiction::Unknown);
    }

    #[test]
    fn test_invalid_ip() {
        let m = JurisdictionMapper::new();
        let r = m.classify("not-an-ip");
        assert_eq!(r.jurisdiction, Jurisdiction::Unknown);
        assert_eq!(r.confidence, 0);
    }

    #[test]
    fn test_brazil_multiple_ranges() {
        let m = JurisdictionMapper::new();
        for ip in &["177.10.1.1", "186.50.1.1", "200.100.1.1"] {
            let r = m.classify(ip);
            assert_eq!(r.jurisdiction, Jurisdiction::Brazil, "Failed for {}", ip);
        }
    }
}