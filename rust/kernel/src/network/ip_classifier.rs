//! IP Classifier v1.7.0 — Tor/VPN/Datacenter detection (ADR-014)
//! Local classification using known ranges. No external API calls.

use std::net::Ipv4Addr;
use std::str::FromStr;
use crate::core::types::BiasDeclaration;

// ---------------------------------------------------------------------
// CLASSIFICATION
// ---------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRisk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCategory {
    Residential,
    Datacenter,
    Vpn,
    Tor,
    Private,
    Loopback,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct IpClassification {
    pub ip: String,
    pub category: IpCategory,
    pub risk: IpRisk,
    pub is_private: bool,
    pub confidence: u8,
}

// ---------------------------------------------------------------------
// KNOWN RANGES (static, no external deps)
// ---------------------------------------------------------------------
struct CidrRange {
    base: u32,
    mask: u32,
    category: IpCategory,
}

impl CidrRange {
    fn new(cidr: &str, category: IpCategory) -> Option<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 { return None; }
        let ip = Ipv4Addr::from_str(parts[0]).ok()?;
        let prefix: u32 = parts[1].parse().ok()?;
        if prefix > 32 { return None; }
        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        Some(Self {
            base: u32::from(ip) & mask,
            mask,
            category,
        })
    }

    fn contains(&self, ip: u32) -> bool {
        (ip & self.mask) == self.base
    }
}

// ---------------------------------------------------------------------
// IP CLASSIFIER
// ---------------------------------------------------------------------
pub struct IpClassifier {
    ranges: Vec<CidrRange>,
}

impl IpClassifier {
    pub fn new() -> Self {
        let mut ranges = Vec::new();

        // Private ranges
        for cidr in &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
            if let Some(r) = CidrRange::new(cidr, IpCategory::Private) {
                ranges.push(r);
            }
        }

        // Loopback
        if let Some(r) = CidrRange::new("127.0.0.0/8", IpCategory::Loopback) {
            ranges.push(r);
        }

        // Known datacenter ranges (major cloud providers, sample)
        for cidr in &[
            "3.0.0.0/8",        // AWS partial
            "13.0.0.0/8",       // AWS partial
            "34.0.0.0/8",       // GCP partial
            "35.184.0.0/13",    // GCP
            "20.0.0.0/8",       // Azure partial
            "40.64.0.0/10",     // Azure
            "104.16.0.0/12",    // Cloudflare
            "162.158.0.0/15",   // Cloudflare
            "198.41.128.0/17",  // Cloudflare
        ] {
            if let Some(r) = CidrRange::new(cidr, IpCategory::Datacenter) {
                ranges.push(r);
            }
        }

        // Known Tor exit nodes (sample ranges — in production, load from file)
        for cidr in &[
            "185.220.100.0/24",
            "185.220.101.0/24",
            "185.220.102.0/24",
            "199.249.230.0/24",
            "204.8.156.0/24",
        ] {
            if let Some(r) = CidrRange::new(cidr, IpCategory::Tor) {
                ranges.push(r);
            }
        }

        // Known VPN providers (sample ranges)
        for cidr in &[
            "103.86.96.0/21",   // NordVPN sample
            "146.70.0.0/16",    // Mullvad sample
            "198.54.128.0/17",  // PIA sample
        ] {
            if let Some(r) = CidrRange::new(cidr, IpCategory::Vpn) {
                ranges.push(r);
            }
        }

        Self { ranges }
    }

    pub fn classify(&self, ip_str: &str) -> IpClassification {
        let ip = match Ipv4Addr::from_str(ip_str) {
            Ok(ip) => ip,
            Err(_) => return self.unknown(ip_str),
        };

        let ip_u32 = u32::from(ip);

        for range in &self.ranges {
            if range.contains(ip_u32) {
                let is_private = matches!(range.category, IpCategory::Private | IpCategory::Loopback);
                let (risk, confidence) = match range.category {
                    IpCategory::Tor => (IpRisk::Critical, 90),
                    IpCategory::Vpn => (IpRisk::High, 75),
                    IpCategory::Datacenter => (IpRisk::Medium, 80),
                    IpCategory::Private => (IpRisk::Low, 95),
                    IpCategory::Loopback => (IpRisk::Low, 99),
                    _ => (IpRisk::Low, 50),
                };
                return IpClassification {
                    ip: ip_str.to_string(),
                    category: range.category,
                    risk,
                    is_private,
                    confidence,
                };
            }
        }

        // No match → residential (default)
        IpClassification {
            ip: ip_str.to_string(),
            category: IpCategory::Residential,
            risk: IpRisk::Low,
            is_private: false,
            confidence: 50,
        }
    }

    fn unknown(&self, ip_str: &str) -> IpClassification {
        IpClassification {
            ip: ip_str.to_string(),
            category: IpCategory::Unknown,
            risk: IpRisk::Medium, // fail-secure: unknown = medium risk
            is_private: false,
            confidence: 0,
        }
    }

    pub fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.10, 0.20, 20260517, 100)
            .with_limitations(
                "Static CIDR ranges. Tor/VPN lists are samples, not comprehensive. IPv6 not supported."
            )
            .with_affected_groups(
                "Users behind corporate proxies may be misclassified as datacenter."
            )
    }
}

impl Default for IpClassifier {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip() {
        let c = IpClassifier::new();
        let r = c.classify("192.168.1.1");
        assert_eq!(r.category, IpCategory::Private);
        assert_eq!(r.risk, IpRisk::Low);
        assert!(r.is_private);
    }

    #[test]
    fn test_loopback() {
        let c = IpClassifier::new();
        let r = c.classify("127.0.0.1");
        assert_eq!(r.category, IpCategory::Loopback);
        assert!(r.is_private);
    }

    #[test]
    fn test_datacenter_aws() {
        let c = IpClassifier::new();
        let r = c.classify("3.5.10.20");
        assert_eq!(r.category, IpCategory::Datacenter);
        assert_eq!(r.risk, IpRisk::Medium);
    }

    #[test]
    fn test_tor_exit() {
        let c = IpClassifier::new();
        let r = c.classify("185.220.100.50");
        assert_eq!(r.category, IpCategory::Tor);
        assert_eq!(r.risk, IpRisk::Critical);
    }

    #[test]
    fn test_vpn() {
        let c = IpClassifier::new();
        let r = c.classify("146.70.50.1");
        assert_eq!(r.category, IpCategory::Vpn);
        assert_eq!(r.risk, IpRisk::High);
    }

    #[test]
    fn test_residential_default() {
        let c = IpClassifier::new();
        let r = c.classify("189.50.100.1"); // Brazilian ISP
        assert_eq!(r.category, IpCategory::Residential);
        assert_eq!(r.risk, IpRisk::Low);
    }

    #[test]
    fn test_invalid_ip() {
        let c = IpClassifier::new();
        let r = c.classify("not-an-ip");
        assert_eq!(r.category, IpCategory::Unknown);
        assert_eq!(r.risk, IpRisk::Medium); // fail-secure
    }

    #[test]
    fn test_cloudflare_datacenter() {
        let c = IpClassifier::new();
        let r = c.classify("104.16.50.1");
        assert_eq!(r.category, IpCategory::Datacenter);
    }
}