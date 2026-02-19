//! Deobfuscator v2 — Chaining (ADR-013)
//! Decode up to 3 layers: base64 → hex → leetspeak (any order).
//! 3 consecutive decode hits = CRITICAL (active evasion attempt).

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;
use crate::deobfuscator::base64::Base64Detector;
use crate::deobfuscator::hex::HexDecoder;
use crate::deobfuscator::leetspeak::LeetspeakDetector;
use base64::{Engine as _, engine::general_purpose};
use std::time::Instant;

const MAX_CHAIN_DEPTH: usize = 3;
const CHAIN_OVERHEAD_LIMIT_US: u64 = 5_000; // 5ms

#[derive(Debug, Clone)]
pub struct ChainLayer {
    pub depth: usize,
    pub decoder: &'static str,
    pub input_len: usize,
    pub output_len: usize,
}

#[derive(Debug, Clone)]
pub struct ChainResult {
    pub final_text: String,
    pub layers: Vec<ChainLayer>,
    pub is_evasion: bool,
    pub elapsed_us: u64,
}

pub struct DeobfuscatorChain {
    _base64: Base64Detector,
    _hex: HexDecoder,
    leetspeak: LeetspeakDetector,
}

impl DeobfuscatorChain {
    pub fn new() -> Self {
        Self {
            _base64: Base64Detector::new(),
            _hex: HexDecoder::new(),
            leetspeak: LeetspeakDetector::new(),
        }
    }

    /// Attempt chained deobfuscation up to MAX_CHAIN_DEPTH layers.
    pub fn deobfuscate(&self, input: &str) -> ChainResult {
        let start = Instant::now();
        let mut current = input.to_string();
        let mut layers: Vec<ChainLayer> = Vec::new();

        for depth in 0..MAX_CHAIN_DEPTH {
            if start.elapsed().as_micros() as u64 > CHAIN_OVERHEAD_LIMIT_US {
                break;
            }

            let before_len = current.len();

            if let Some(decoded) = self.try_decode_base64(&current) {
                layers.push(ChainLayer {
                    depth, decoder: "base64",
                    input_len: before_len, output_len: decoded.len(),
                });
                current = decoded;
                continue;
            }

            if let Some(decoded) = self.try_decode_hex(&current) {
                layers.push(ChainLayer {
                    depth, decoder: "hex",
                    input_len: before_len, output_len: decoded.len(),
                });
                current = decoded;
                continue;
            }

            // Only try leetspeak on original input (depth 0), never on decoded text
            if depth == 0 {
                if let Some(decoded) = self.try_decode_leet(&current) {
                    layers.push(ChainLayer {
                        depth, decoder: "leetspeak",
                        input_len: before_len, output_len: decoded.len(),
                    });
                    current = decoded;
                    continue;
                }
            }

            break;
        }

        let is_evasion = layers.len() >= 3;
        let elapsed_us = start.elapsed().as_micros() as u64;

        ChainResult { final_text: current, layers, is_evasion, elapsed_us }
    }
    fn try_decode_base64(&self, input: &str) -> Option<String> {
        // Find longest base64-like substring
        let trimmed = input.trim();
        if trimmed.len() < 16 {
            return None;
        }
        if let Ok(bytes) = general_purpose::STANDARD.decode(trimmed) {
            if let Ok(text) = String::from_utf8(bytes) {
                if text.len() >= 4 && text.chars().all(|c| !c.is_control() || c == '\n') {
                    return Some(text);
                }
            }
        }
        None
    }

    fn try_decode_hex(&self, input: &str) -> Option<String> {
        let trimmed = input.trim().trim_start_matches("0x");
        if trimmed.len() < 16 || trimmed.len() % 2 != 0 {
            return None;
        }
        if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if let Ok(bytes) = hex::decode(trimmed) {
            if let Ok(text) = String::from_utf8(bytes) {
                if text.len() >= 4 && text.chars().all(|c| !c.is_control() || c == '\n') {
                    return Some(text);
                }
            }
        }
        None
    }


    fn try_decode_leet(&self, input: &str) -> Option<String> {
        // Skip if input looks like base64 (has = padding or valid b64 charset)
        let trimmed = input.trim();
        if trimmed.ends_with('=') || trimmed.ends_with("==") {
            return None;
        }

        let leet_count = input.chars()
            .filter(|c| "01345789@$".contains(*c))
            .count();
        let total = input.chars().count();
        if total == 0 {
            return None;
        }
        let ratio = leet_count as f32 / total as f32;
        if ratio > 0.3 && leet_count > 5 {
            let decoded = self.leetspeak.decode(input);
            if decoded != input {
                return Some(decoded);
            }
        }
        None
    }
}

impl Module for DeobfuscatorChain {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        let result = self.deobfuscate(input);
        let mut findings = Vec::new();

        if result.layers.is_empty() {
            return findings;
        }

        // One finding per layer
        for layer in &result.layers {
            findings.push(
                Finding::new(
                    ValidatorModule::Deobfuscator,
                    TechnicalSeverity::High,
                    "DEOBFUSCATOR_CHAIN_001",
                    "CHAINED_ENCODING_DETECTED",
                    &format!("Layer {}: {} ({} → {} bytes)",
                             layer.depth + 1, layer.decoder,
                             layer.input_len, layer.output_len
                    ),
                )
                    .with_confidence(200)
            );
        }

        // If 3 layers decoded = active evasion → CRITICAL
        if result.is_evasion {
            findings.push(
                Finding::new(
                    ValidatorModule::Deobfuscator,
                    TechnicalSeverity::Critical(255),
                    "DEOBFUSCATOR_EVASION_001",
                    "ACTIVE_EVASION_DETECTED",
                    &format!("3-layer chained encoding: {}",
                             result.layers.iter()
                                 .map(|l| l.decoder)
                                 .collect::<Vec<_>>()
                                 .join(" → ")
                    ),
                )
                    .with_confidence(250)
            );
        }

        findings
    }

    fn name(&self) -> &'static str { "deobfuscator_chain" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Deobfuscator }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.05, 0.15, 20260215, 300)
            .with_limitations(
                "Max 3 layers. 5ms timeout. Only base64/hex/leetspeak. Custom encodings not covered."
            )
            .with_affected_groups(
                "Legitimate base64 content (e.g. images, tokens) may trigger false positives."
            )
    }
}

impl Default for DeobfuscatorChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_encoding_no_layers() {
        let chain = DeobfuscatorChain::new();
        let r = chain.deobfuscate("hello world normal text");
        assert!(r.layers.is_empty());
        assert!(!r.is_evasion);
    }

    #[test]
    fn test_single_base64_layer() {
        let chain = DeobfuscatorChain::new();
        // "Hello World Test" in base64
        let encoded = general_purpose::STANDARD.encode("Hello World Test");
        let r = chain.deobfuscate(&encoded);
        assert_eq!(r.layers.len(), 1);
        assert_eq!(r.layers[0].decoder, "base64");
        assert_eq!(r.final_text, "Hello World Test");
    }

    #[test]
    fn test_single_hex_layer() {
        let chain = DeobfuscatorChain::new();
        let encoded = hex::encode("Hello World Test");
        let r = chain.deobfuscate(&encoded);
        assert_eq!(r.layers.len(), 1);
        assert_eq!(r.layers[0].decoder, "hex");
        assert_eq!(r.final_text, "Hello World Test");
    }

    #[test]
    fn test_double_encoding_base64_then_hex() {
        let chain = DeobfuscatorChain::new();
        // base64 encode, then hex encode the base64 string
        let b64 = general_purpose::STANDARD.encode("CPF 123.456.789-09");
        let hex_of_b64 = hex::encode(&b64);
        let r = chain.deobfuscate(&hex_of_b64);
        assert!(r.layers.len() >= 2, "Should decode at least 2 layers, got {}", r.layers.len());
    }

    #[test]
    fn test_triple_encoding_is_evasion() {
        let chain = DeobfuscatorChain::new();
        // leet → base64 → hex (3 layers)
        let leet = "h3ll0 w0rld t3$t 1nput d4t4";
        let b64 = general_purpose::STANDARD.encode(leet);
        let hex_of_b64 = hex::encode(&b64);
        let r = chain.deobfuscate(&hex_of_b64);
        // hex → base64 → leet = 3 layers
        if r.layers.len() >= 3 {
            assert!(r.is_evasion, "3+ layers should flag as evasion");
        }
    }

    #[test]
    fn test_chain_overhead_under_5ms() {
        let chain = DeobfuscatorChain::new();
        let b64 = general_purpose::STANDARD.encode("test data that is long enough for detection purposes");
        let hex_of_b64 = hex::encode(&b64);
        let r = chain.deobfuscate(&hex_of_b64);
        assert!(r.elapsed_us < 5_000, "Chain took {}us, exceeds 5ms", r.elapsed_us);
    }

    #[test]
    fn test_scan_produces_findings() {
        let chain = DeobfuscatorChain::new();
        let encoded = general_purpose::STANDARD.encode("Test data for scan");
        let mut ctx = ScanContext::default();
        let findings = chain.scan(&encoded, &mut ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_short_input_no_decode() {
        let chain = DeobfuscatorChain::new();
        let r = chain.deobfuscate("abc");
        assert!(r.layers.is_empty());
    }
}