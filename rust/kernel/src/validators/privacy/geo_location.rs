//! GeoLocationValidator — Cenário 26: Over-sharing GPS (PROP-039).
//!
//! Detecta coordenadas geográficas no hot path antes de transmissão.
//! Zero heap: regex compilada via lazy_static.
//! Sensibilidade: Hypersensitive (requer aprovação humana).
//!
//! Padrões cobertos:
//!   - Decimal:  ±DD.DDDDD, ±DD,DDDDD  (vírgula BR-locale)
//!   - DMS:      48°51'30"N  ou  48°51'N
//!   - Plus Code: 6GCR+F5 (6–7 chars alfanum + "+")

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// Regex para coordenadas decimais:  -23.5505, -46.6333  ou  -23,5505 -46,6333
    static ref RE_DECIMAL: Regex = Regex::new(
        r"(?i)(?P<lat>[+-]?(?:[0-8]?\d|90)(?:[.,]\d{3,7}))[\s,;/]+(?P<lon>[+-]?(?:1[0-7]\d|\d{1,2})(?:[.,]\d{3,7}))"
    ).expect("RE_DECIMAL compile");

    /// Regex para DMS: 48°51'30"N 2°17'40"E  ou  48°51'N 2°17'E
    static ref RE_DMS: Regex = Regex::new(
        r"(?i)\d{1,3}°\d{1,2}'(?:\d{1,2}(?:[.,]\d+)?\")?[NSns][\s,;]+\d{1,3}°\d{1,2}'(?:\d{1,2}(?:[.,]\d+)?\")?[EWew]"
    ).expect("RE_DMS compile");

    /// Regex para Open Location Code (Plus Codes): 6GCR+F5  ou  6GCR+F5 São Paulo
    static ref RE_PLUS_CODE: Regex = Regex::new(
        r"(?i)\b[23456789CFGHJMPQRVWX]{4,8}\+[23456789CFGHJMPQRVWX]{2,3}\b"
    ).expect("RE_PLUS_CODE compile");
}

/// Categoria de correspondência encontrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoMatchKind {
    Decimal,
    Dms,
    PlusCode,
}

/// Resultado de detecção de coordenada geográfica.
///
/// `raw_match` é o trecho do texto que disparou a detecção.
/// `lat` / `lon` são aproximações parseadas (0.0 para DMS/PlusCode).
#[derive(Debug, Clone)]
pub struct GeoLocationFinding {
    pub lat: f32,
    pub lon: f32,
    pub kind: GeoMatchKind,
    pub raw_match: String,
}

/// Escaneia `text` em busca de coordenadas geográficas.
///
/// Retorna `Some(GeoLocationFinding)` na primeira correspondência.
/// Retorna `None` se nenhum padrão for encontrado.
///
/// # Exemplo
/// ```
/// use buildtovalue_kernel::validators::privacy::geo_location::scan;
/// let result = scan("-23.5505, -46.6333");
/// assert!(result.is_some());
/// let result_none = scan("Rua A, 123");
/// assert!(result_none.is_none());
/// ```
pub fn scan(text: &str) -> Option<GeoLocationFinding> {
    // 1. Tenta decimal (mais comum e preciso)
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

    // 2. Tenta DMS (graus/minutos/segundos)
    if let Some(m) = RE_DMS.find(text) {
        return Some(GeoLocationFinding {
            lat: 0.0,
            lon: 0.0,
            kind: GeoMatchKind::Dms,
            raw_match: m.as_str().to_string(),
        });
    }

    // 3. Tenta Plus Code
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

/// Converte string de coordenada (vírgula ou ponto) para f32.
fn parse_coord(s: &str) -> f32 {
    s.replace(',', ".").trim().parse::<f32>().unwrap_or(0.0)
}

#[cfg(test)]
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
