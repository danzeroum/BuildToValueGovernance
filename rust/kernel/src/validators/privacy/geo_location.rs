//! GeoLocationValidator — Cenário 26: Over-sharing GPS (PROP-039).
//!
//! Detecta coordenadas geográficas no hot path antes de transmissão.
//! Zero heap: regex compilada via lazy_static.
//! Sensibilidade: Hypersensitive (requer aprovação humana).

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref RE_DECIMAL: Regex = Regex::new(
        r"(?i)(?P<lat>[+-]?(?:[0-8]?\d|90)(?:[.,]\d{3,7}))[\s,;/]+(?P<lon>[+-]?(?:1[0-7]\d|\d{1,2})(?:[.,]\d{3,7}))"
    ).unwrap_or_else(|e| panic!("BTV init: RE_DECIMAL compile failed: {e}"));

    static ref RE_DMS: Regex = Regex::new(
        r#"(?i)\d{1,3}\u00b0\d{1,2}'(?:\d{1,2}(?:[.,]\d+)?")?[NSns][\s,;]+\d{1,3}\u00b0\d{1,2}'(?:\d{1,2}(?:[.,]\d+)?")?[EWew]"#
    ).unwrap_or_else(|e| panic!("BTV init: RE_DMS compile failed: {e}"));

    static ref RE_PLUS_CODE: Regex = Regex::new(
        r"(?i)\b[23456789CFGHJMPQRVWX]{4,8}\+[23456789CFGHJMPQRVWX]{2,3}\b"
    ).unwrap_or_else(|e| panic!("BTV init: RE_PLUS_CODE compile failed: {e}"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoMatchKind {
    Decimal,
    Dms,
    PlusCode,
}

#[derive(Debug, Clone)]
pub struct GeoLocationFinding {
    pub lat: f32,
    pub lon: f32,
    pub kind: GeoMatchKind,
    pub raw_match: String,
}

pub fn scan(text: &str) -> Option<GeoLocationFinding> {
    if let Some(caps) = RE_DECIMAL.captures(text) {
        let full = caps.get(0).map_or("", |m| m.as_str());
        let lat = parse_coord(caps.name("lat").map_or("", |m| m.as_str()));
        let lon = parse_coord(caps.name("lon").map_or("", |m| m.as_str()));
        return Some(GeoLocationFinding {
            lat,
            lon,
            kind: GeoMatchKind::Decimal,
            raw_match: full.to_string(),
        });
    }

    if let Some(m) = RE_DMS.find(text) {
        return Some(GeoLocationFinding {
            lat: 0.0,
            lon: 0.0,
            kind: GeoMatchKind::Dms,
            raw_match: m.as_str().to_string(),
        });
    }

    if let Some(m) = RE_PLUS_CODE.find(text) {
        return Some(GeoLocationFinding {
            lat: 0.0,
            lon: 0.0,
            kind: GeoMatchKind::PlusCode,
            raw_match: m.as_str().to_string(),
        });
    }

    None
}

fn parse_coord(s: &str) -> f32 {
    s.replace(',', ".").trim().parse::<f32>().unwrap_or(0.0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_decimal_lat_lon_detected() {
        let result = scan("-23.5505, -46.6333");
        assert!(result.is_some(), "deve detectar coordenada decimal");
        let f = result.unwrap();
        assert_eq!(f.kind, GeoMatchKind::Decimal);
        assert!((f.lat - (-23.5505_f32)).abs() < 0.001);
    }

    #[test]
    fn test_decimal_br_locale_comma() {
        let result = scan("-23,5505 -46,6333");
        assert!(result.is_some(), "deve aceitar vírgula BR-locale");
    }

    #[test]
    fn test_dms_detected() {
        let result = scan("48°51'30\"N 2°17'40\"E");
        assert!(result.is_some(), "deve detectar DMS");
        assert_eq!(result.unwrap().kind, GeoMatchKind::Dms);
    }

    #[test]
    fn test_plus_code_detected() {
        let result = scan("6GCR+F5 São Paulo");
        assert!(result.is_some(), "deve detectar Plus Code");
        assert_eq!(result.unwrap().kind, GeoMatchKind::PlusCode);
    }

    #[test]
    fn test_plain_address_not_detected() {
        assert!(scan("Rua A, 123").is_none());
        assert!(scan("contato@empresa.com.br").is_none());
        assert!(scan("12345-678").is_none());
    }

    #[test]
    fn test_fail_secure_empty_string() {
        assert!(scan("").is_none(), "string vazia → None (fail-secure)");
    }

    #[test]
    fn test_performance_under_1ms() {
        use std::time::Instant;
        let input = "-23.5505, -46.6333";
        let start = Instant::now();
        let _r = scan(input);
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 1, "deve completar em <1ms: {:?}", elapsed);
    }
}
