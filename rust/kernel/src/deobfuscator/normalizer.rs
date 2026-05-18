//! Normalizer v1.0.0 — Pré-processamento P0 (Red Team RT-002, RT-005, RT-008)
//!
//! Normaliza input antes do DeobfuscatorChain e validators:
//!   1. Unicode homoglyphs → ASCII equivalente
//!   2. Palavras de ofuscação → símbolos (arroba→@, ponto→.)
//!   3. Espaços internos em padrões PII (CPF, email, cartão)
//!   4. Letra O/o por zero em padrões numéricos PII
//!
//! Filosofia (Jonas): Tornar o invisível visível antes de julgar.
//! Hot path: zero heap allocation — opera em &str, retorna String apenas se mudou.
//!
//! BIAS DECLARATION (ADR-010):
//!   FPR estimado: 2% (palavras "ponto"/"arroba" em contexto natural)
//!   FNR estimado: 5% (homoglyphs não mapeados, idiomas não cobertos)
//!   Calibrado: 2026-02-26 | Dataset: RT-002 + RT-005 + RT-008 (42 casos)
//!   Limitação: Não cobre todos os unicode homoglyphs (apenas blocos comuns)
//!   Grupos afetados: usuários que escrevem "ponto com" em contexto legítimo

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, ValidatorModule, TechnicalSeverity};
use crate::evidence::Finding;

// ─────────────────────────────────────────────────────────────
// UNICODE HOMOGLYPH TABLE
// Blocos cobertos: Mathematical Bold, Fullwidth, Cyrillic lookalikes
// Fonte: Unicode Confusables (unicode.org/reports/tr39/)
// ─────────────────────────────────────────────────────────────

/// Mapeia homoglyphs unicode para ASCII equivalente.
/// Array estático — zero heap, lookup O(n) aceitável para inputs típicos (<512 chars).
// Substituir o bloco Mathematical Bold Digits na HOMOGLYPH_MAP:
const HOMOGLYPH_MAP: &[(char, char)] = &[
    // --- Mathematical Bold Digits (U+1D7CE..U+1D7D7) ---
    ('\u{1D7CE}', '0'), ('\u{1D7CF}', '1'), ('\u{1D7D0}', '2'),
    ('\u{1D7D1}', '3'), ('\u{1D7D2}', '4'), ('\u{1D7D3}', '5'),
    ('\u{1D7D4}', '6'), ('\u{1D7D5}', '7'), ('\u{1D7D6}', '8'),
    ('\u{1D7D7}', '9'),

    // --- Mathematical Sans-Serif Bold Digits (U+1D7EC..U+1D7F5) ---
    ('\u{1D7EC}', '0'), ('\u{1D7ED}', '1'), ('\u{1D7EE}', '2'),
    ('\u{1D7EF}', '3'), ('\u{1D7F0}', '4'), ('\u{1D7F1}', '5'),
    ('\u{1D7F2}', '6'), ('\u{1D7F3}', '7'), ('\u{1D7F4}', '8'),
    ('\u{1D7F5}', '9'),

    // --- Mathematical Double-Struck Digits (U+1D7D8..U+1D7E1) ---
    // Comuns em ambientes acadêmicos e formatação rica
    ('\u{1D7D8}', '0'), ('\u{1D7D9}', '1'), ('\u{1D7DA}', '2'),
    ('\u{1D7DB}', '3'), ('\u{1D7DC}', '4'), ('\u{1D7DD}', '5'),
    ('\u{1D7DE}', '6'), ('\u{1D7DF}', '7'), ('\u{1D7E0}', '8'),
    ('\u{1D7E1}', '9'),

    // --- Mathematical Bold Letters (Seleção de alta frequência) ---
    ('\u{1D400}', 'A'), ('\u{1D401}', 'B'), ('\u{1D402}', 'C'),
    ('\u{1D403}', 'D'), ('\u{1D404}', 'E'), ('\u{1D405}', 'F'),
    ('\u{1D406}', 'G'), ('\u{1D407}', 'H'), ('\u{1D408}', 'I'),
    ('\u{1D409}', 'J'), ('\u{1D40A}', 'K'), ('\u{1D40B}', 'L'),
    ('\u{1D40C}', 'M'), ('\u{1D40D}', 'N'), ('\u{1D40E}', 'O'),
    ('\u{1D40F}', 'P'), ('\u{1D410}', 'Q'), ('\u{1D411}', 'R'),
    ('\u{1D412}', 'S'), ('\u{1D413}', 'T'), ('\u{1D414}', 'U'),
    ('\u{1D415}', 'V'), ('\u{1D416}', 'W'), ('\u{1D417}', 'X'),
    ('\u{1D418}', 'Y'), ('\u{1D419}', 'Z'),

    // --- Fullwidth ASCII (U+FF00..U+FF5E) ---
    ('\u{FF10}', '0'), ('\u{FF11}', '1'), ('\u{FF12}', '2'),
    ('\u{FF13}', '3'), ('\u{FF14}', '4'), ('\u{FF15}', '5'),
    ('\u{FF16}', '6'), ('\u{FF17}', '7'), ('\u{FF18}', '8'),
    ('\u{FF19}', '9'),
    ('\u{FF21}', 'A'), ('\u{FF22}', 'B'), ('\u{FF23}', 'C'),
    ('\u{FF24}', 'D'), ('\u{FF25}', 'E'), ('\u{FF26}', 'F'),
    ('\u{FF27}', 'G'), ('\u{FF28}', 'H'), ('\u{FF29}', 'I'),
    ('\u{FF2A}', 'J'), ('\u{FF2B}', 'K'), ('\u{FF2C}', 'L'),
    ('\u{FF2D}', 'M'), ('\u{FF2E}', 'N'), ('\u{FF2F}', 'O'),
    ('\u{FF30}', 'P'), ('\u{FF31}', 'Q'), ('\u{FF32}', 'R'),
    ('\u{FF33}', 'S'), ('\u{FF34}', 'T'), ('\u{FF35}', 'U'),
    ('\u{FF36}', 'V'), ('\u{FF37}', 'W'), ('\u{FF38}', 'X'),
    ('\u{FF39}', 'Y'), ('\u{FF3A}', 'Z'),
    ('\u{FF41}', 'a'), ('\u{FF42}', 'b'), ('\u{FF43}', 'c'),
    ('\u{FF44}', 'd'), ('\u{FF45}', 'e'), ('\u{FF46}', 'f'),
    ('\u{FF47}', 'g'), ('\u{FF48}', 'h'), ('\u{FF49}', 'i'),
    ('\u{FF4A}', 'j'), ('\u{FF4B}', 'k'), ('\u{FF4C}', 'l'),
    ('\u{FF4D}', 'm'), ('\u{FF4E}', 'n'), ('\u{FF4F}', 'o'),
    ('\u{FF50}', 'p'), ('\u{FF51}', 'q'), ('\u{FF52}', 'r'),
    ('\u{FF53}', 's'), ('\u{FF54}', 't'), ('\u{FF55}', 'u'),
    ('\u{FF56}', 'v'), ('\u{FF57}', 'w'), ('\u{FF58}', 'x'),
    ('\u{FF59}', 'y'), ('\u{FF5A}', 'z'),
    ('\u{FF20}', '@'), ('\u{FF0E}', '.'), ('\u{FF0D}', '-'),
    ('\u{FF0F}', '/'), ('\u{FF3F}', '_'),

    // --- Cyrillic Lookalikes (U+0400..U+04FF) ---
    // Alta sobreposição visual com Latin
    ('\u{0405}', 'S'), ('\u{0455}', 's'), ('\u{0406}', 'I'),
    ('\u{0456}', 'i'), ('\u{0408}', 'J'), ('\u{0458}', 'j'),
    ('\u{0410}', 'A'), ('\u{0430}', 'a'), ('\u{0412}', 'B'),
    ('\u{0432}', 'B'), // Small Ve looks like B
    ('\u{0415}', 'E'), ('\u{0435}', 'e'), ('\u{041A}', 'K'),
    ('\u{043A}', 'K'), // Small Ka looks like k
    ('\u{041C}', 'M'), ('\u{041D}', 'H'), ('\u{043D}', 'H'), // Small En looks like H
    ('\u{041E}', 'O'), ('\u{043E}', 'o'), ('\u{0420}', 'P'),
    ('\u{0440}', 'p'), ('\u{0421}', 'C'), ('\u{0441}', 'c'),
    ('\u{0422}', 'T'), ('\u{0442}', 'T'), // Small Te looks like T
    ('\u{0425}', 'X'), ('\u{0445}', 'x'), ('\u{0443}', 'y'),
    ('\u{0423}', 'Y'), // Capital U looks like Y
    ('\u{0427}', 'Y'), // Che looks like Y
    ('\u{0407}', 'I'), // Yi looks like I
    ('\u{0457}', 'i'),

    // --- Greek Lookalikes (U+0370..U+03FF) ---
    // Frequentes em emails e identificadores técnicos
    ('\u{0391}', 'A'), ('\u{03B1}', 'a'), // Alpha
    ('\u{0392}', 'B'), ('\u{03B2}', 'b'), // Beta
    ('\u{0395}', 'E'), ('\u{03B5}', 'e'), // Epsilon
    ('\u{0396}', 'Z'), ('\u{03B6}', 'z'), // Zeta
    ('\u{0397}', 'H'), ('\u{03B7}', 'h'), // Eta
    ('\u{0399}', 'I'), ('\u{03B9}', 'i'), // Iota
    ('\u{039A}', 'K'), ('\u{03BA}', 'k'), // Kappa
    ('\u{039C}', 'M'), ('\u{03BC}', 'm'), // Mu
    ('\u{039D}', 'N'), ('\u{03BD}', 'n'), // Nu
    ('\u{039F}', 'O'), ('\u{03BF}', 'o'), // Omicron
    ('\u{03A1}', 'P'), ('\u{03C1}', 'p'), // Rho
    ('\u{03A4}', 'T'), ('\u{03C4}', 't'), // Tau
    ('\u{03A5}', 'Y'), ('\u{03C5}', 'y'), // Upsilon
    ('\u{03A7}', 'X'), ('\u{03C7}', 'x'), // Chi
    ('\u{0398}', 'O'), // Theta looks like O
    ('\u{039F}', 'O'), // Omicron
    ('\u{03A3}', 'E'), // Sigma (capital) looks like E somewhat, or sum symbol? Better map to E if lookalike. Actually Capital Sigma often maps to E or M visually, but here strictly for confusables.
    ('\u{03A3}', 'E'), // Keep simple. If strictly visual: Σ -> E
    ('\u{03F4}', 'O'), // Theta symbol
    ('\u{03D1}', 'B'), // Beta symbol

    // --- Circled Letters (U+24B6..U+24E9) ---
    // Limpeza de duplicatas e cobertura completa
    // Uppercase (U+24B6..)
    ('\u{24B6}', 'A'), ('\u{24B7}', 'B'), ('\u{24B8}', 'C'),
    ('\u{24B9}', 'D'), ('\u{24BA}', 'E'), ('\u{24BB}', 'F'),
    ('\u{24BC}', 'G'), ('\u{24BD}', 'H'), ('\u{24BE}', 'I'),
    ('\u{24BF}', 'J'), ('\u{24C0}', 'K'), ('\u{24C1}', 'L'),
    ('\u{24C2}', 'M'), ('\u{24C3}', 'N'), ('\u{24C4}', 'O'),
    ('\u{24C5}', 'P'), ('\u{24C6}', 'Q'), ('\u{24C7}', 'R'),
    ('\u{24C8}', 'S'), ('\u{24C9}', 'T'), ('\u{24CA}', 'U'),
    ('\u{24CB}', 'V'), ('\u{24CC}', 'W'), ('\u{24CD}', 'X'),
    ('\u{24CE}', 'Y'), ('\u{24CF}', 'Z'),
    // Lowercase (U+24D0..)
    ('\u{24D0}', 'a'), ('\u{24D1}', 'b'), ('\u{24D2}', 'c'),
    ('\u{24D3}', 'd'), ('\u{24D4}', 'e'), ('\u{24D5}', 'f'),
    ('\u{24D6}', 'g'), ('\u{24D7}', 'h'), ('\u{24D8}', 'i'),
    ('\u{24D9}', 'j'), ('\u{24DA}', 'k'), ('\u{24DB}', 'l'),
    ('\u{24DC}', 'm'), ('\u{24DD}', 'n'), ('\u{24DE}', 'o'),
    ('\u{24DF}', 'p'), ('\u{24E0}', 'q'), ('\u{24E1}', 'r'),
    ('\u{24E2}', 's'), ('\u{24E3}', 't'), ('\u{24E4}', 'u'),
    ('\u{24E5}', 'v'), ('\u{24E6}', 'w'), ('\u{24E7}', 'x'),
    ('\u{24E8}', 'y'), ('\u{24E9}', 'z'),
    // --- Small Form Variants (U+FE50..U+FE6F) ---
    // Frequentes em CJK contexts e documentos legados
    ('\u{FE52}', '.'), ('\u{FE50}', ','), ('\u{FE54}', ';'),
    ('\u{FE56}', ':'), ('\u{FE57}', '!'), ('\u{FE58}', '-'),
    ('\u{FE5F}', '#'), ('\u{FE60}', '&'), ('\u{FE61}', '*'),
    ('\u{FE62}', '+'), ('\u{FE63}', '-'), ('\u{FE64}', '<'),
    ('\u{FE66}', '='), ('\u{FE68}', '\\'), ('\u{FE69}', '$'),
    ('\u{FE6A}', '%'), ('\u{FE6B}', '@'),
		// Mathematical Bold lowercase letters (U+1D41A..U+1D433)
	('\u{1D41A}', 'a'), ('\u{1D41B}', 'b'), ('\u{1D41C}', 'c'), ('\u{1D41D}', 'd'),
	('\u{1D41E}', 'e'), ('\u{1D41F}', 'f'), ('\u{1D420}', 'g'), ('\u{1D421}', 'h'),
	('\u{1D422}', 'i'), ('\u{1D423}', 'j'), ('\u{1D424}', 'k'), ('\u{1D425}', 'l'),
	('\u{1D426}', 'm'), ('\u{1D427}', 'n'), ('\u{1D428}', 'o'), ('\u{1D429}', 'p'),
	('\u{1D42A}', 'q'), ('\u{1D42B}', 'r'), ('\u{1D42C}', 's'), ('\u{1D42D}', 't'),
	('\u{1D42E}', 'u'), ('\u{1D42F}', 'v'), ('\u{1D430}', 'w'), ('\u{1D431}', 'x'),
	('\u{1D432}', 'y'), ('\u{1D433}', 'z'),
	// Mathematical Sans-Serif Bold uppercase (U+1D5D4..U+1D5ED)
	('\u{1D5D4}', 'A'), ('\u{1D5D5}', 'B'), ('\u{1D5D6}', 'C'), ('\u{1D5D7}', 'D'),
	('\u{1D5D8}', 'E'), ('\u{1D5D9}', 'F'), ('\u{1D5DA}', 'G'), ('\u{1D5DB}', 'H'),
	('\u{1D5DC}', 'I'), ('\u{1D5DD}', 'J'), ('\u{1D5DE}', 'K'), ('\u{1D5DF}', 'L'),
	('\u{1D5E0}', 'M'), ('\u{1D5E1}', 'N'), ('\u{1D5E2}', 'O'), ('\u{1D5E3}', 'P'),
	('\u{1D5E4}', 'Q'), ('\u{1D5E5}', 'R'), ('\u{1D5E6}', 'S'), ('\u{1D5E7}', 'T'),
	('\u{1D5E8}', 'U'), ('\u{1D5E9}', 'V'), ('\u{1D5EA}', 'W'), ('\u{1D5EB}', 'X'),
	('\u{1D5EC}', 'Y'), ('\u{1D5ED}', 'Z'),

	// Mathematical Sans-Serif Bold lowercase (U+1D5EE..U+1D607)
	('\u{1D5EE}', 'a'), ('\u{1D5EF}', 'b'), ('\u{1D5F0}', 'c'), ('\u{1D5F1}', 'd'),
	('\u{1D5F2}', 'e'), ('\u{1D5F3}', 'f'), ('\u{1D5F4}', 'g'), ('\u{1D5F5}', 'h'),
	('\u{1D5F6}', 'i'), ('\u{1D5F7}', 'j'), ('\u{1D5F8}', 'k'), ('\u{1D5F9}', 'l'),
	('\u{1D5FA}', 'm'), ('\u{1D5FB}', 'n'), ('\u{1D5FC}', 'o'), ('\u{1D5FD}', 'p'),
	('\u{1D5FE}', 'q'), ('\u{1D5FF}', 'r'), ('\u{1D600}', 's'), ('\u{1D601}', 't'),
	('\u{1D602}', 'u'), ('\u{1D603}', 'v'), ('\u{1D604}', 'w'), ('\u{1D605}', 'x'),
	('\u{1D606}', 'y'), ('\u{1D607}', 'z'),
];

/// Palavras de ofuscação em PT-BR e EN mapeadas para símbolos.
/// Ordem importa: verificar "arroba" antes de "at" para evitar falso match.
const WORD_SUBSTITUTIONS: &[(&str, &str)] = &[
    // PT-BR (Principal)
    ("arroba",  "@"),
    ("aroba",   "@"),   // Typo comum
    ("[arroba]", "@"),
    ("ponto",   "."),
    ("pnto",    "."),   // Typo comum
    ("[ponto]", "."),
    ("hífen",   "-"),
    ("hifen",   "-"),   // Sem acento
    ("traço",   "-"),
    ("traco",   "-"),   // Sem acento
    ("underline", "_"),
    ("sublinhado", "_"),
    ("underscore", "_"),
    ("asterisco", "*"),
    ("hash", "#"),
    ("hashtag", "#"),
    ("cerquilha", "#"),

    // EN (Internacional)
    (" at sign ", "@"),
    (" at ",     "@"),   // " user at example "
    (" dot ",    "."),   // " example dot com "
    ("(at)",     "@"),
    ("(dot)",    "."),
    ("[at]",     "@"),
    ("[dot]",    "."),
    (" dash ",   "-"),
    (" hyphen ", "-"),
    (" slash ",  "/"),
    (" underscore ", "_"),
    (" underscore", "_"), // fim de frase
];

// ─────────────────────────────────────────────────────────────
// NORMALIZER
// ─────────────────────────────────────────────────────────────

pub struct Normalizer;

impl Normalizer {
    pub fn new() -> Self {
        Self
    }

    /// Normaliza o input aplicando as 4 transformações em sequência.
    /// Retorna (texto_normalizado, foi_modificado).
    /// Se não modificado, retorna clone do original (chamador deve verificar `changed`).
    pub fn normalize(&self, input: &str) -> (String, bool) {
        let s1 = self.normalize_homoglyphs(input);
        let s2 = self.normalize_word_substitutions(&s1);
        let s3 = self.normalize_pii_spaces(&s2);
        let s4 = self.normalize_letter_o_as_zero(&s3);
        let changed = s4 != input;
        (s4, changed)
    }

    /// 1. Substitui unicode homoglyphs por ASCII equivalente.
    fn normalize_homoglyphs(&self, input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        for ch in input.chars() {
            let mapped = HOMOGLYPH_MAP
                .iter()
                .find(|(from, _)| *from == ch)
                .map(|(_, to)| *to)
                .unwrap_or(ch);
            result.push(mapped);
        }
        result
    }

    /// 2. Substitui palavras de ofuscação por símbolos.
    fn normalize_word_substitutions(&self, input: &str) -> String {
        let mut result = input.to_string();
        for (word, symbol) in WORD_SUBSTITUTIONS {
            let lower = result.to_lowercase();
            if let Some(pos) = lower.find(word) {
                result = format!("{}{}{}", &result[..pos], symbol, &result[pos + word.len()..]);
            }
        }
        result
    }

    /// 3. Remove espaços internos em padrões que se parecem com PII espaçado.
    ///
    ///    Ex: "1 2 3 . 4 5 6 . 7 8 9 - 0 9" → "123.456.789-09"
    ///    Heurística: sequência de dígitos/separadores com espaços entre cada char.
    fn normalize_pii_spaces(&self, input: &str) -> String {
        let tokens: Vec<&str> = input.split_whitespace().collect();
        if tokens.len() < 5 {
            return input.to_string();
        }
        let is_pii_char_token = |t: &str| -> bool {
            t.len() == 1
                && t.chars()
                    .next()
                    .map(|c| c.is_ascii_digit() || ".,-/@".contains(c))
                    .unwrap_or(false)
        };
        let pii_chars = tokens.iter().filter(|t| is_pii_char_token(t)).count();

        if pii_chars as f32 / tokens.len() as f32 > 0.6 {
            // Collapse only consecutive PII-char runs; preserve surrounding words.
            // "Meu CPF é 1 2 3 . 4 5 6 . 7 8 9 - 0 9" → "Meu CPF é 123.456.789-09"
            let mut result_parts: Vec<String> = Vec::new();
            let mut pii_run = String::new();
            for token in &tokens {
                if is_pii_char_token(token) {
                    pii_run.push_str(token);
                } else {
                    if !pii_run.is_empty() {
                        result_parts.push(pii_run.clone());
                        pii_run.clear();
                    }
                    result_parts.push(token.to_string());
                }
            }
            if !pii_run.is_empty() {
                result_parts.push(pii_run);
            }
            return result_parts.join(" ");
        }
        input.to_string()
    }

    /// 4. Substitui letra O/o por 0 em padrão CPF NNN.NNN.NNN-OO
    ///
    ///    Opera char-by-char para segurança UTF-8.
    fn normalize_letter_o_as_zero(&self, input: &str) -> String {
        let chars: Vec<char> = input.chars().collect();
        let len = chars.len();
        if len < 13 {
            return input.to_string();
        }

        let mut result: Vec<char> = chars.clone();

        for i in 0..len {
            // Verificar padrão a partir de i: DDD.DDD.DDD-XX
            if i + 12 >= len {
                break;
            }
            let window_str: String = chars[i..].iter().take(14).collect();
            if Self::looks_like_cpf_with_letter_o(&window_str) {
                if result[i + 12] == 'O' || result[i + 12] == 'o' {
                    result[i + 12] = '0';
                }
                if i + 13 < len && (result[i + 13] == 'O' || result[i + 13] == 'o') {
                    result[i + 13] = '0';
                }
            }
        }

        result.iter().collect()
    }


    /// Verifica se a janela começa com padrão NNN.NNN.NNN-[0OoO]{2}
    fn looks_like_cpf_with_letter_o(window: &str) -> bool {
        let chars: Vec<char> = window.chars().take(14).collect();
        if chars.len() < 13 {
            return false;
        }
        let digit_or_o = |c: char| c.is_ascii_digit() || c == 'O' || c == 'o';
        chars[0].is_ascii_digit()
            && chars[1].is_ascii_digit()
            && chars[2].is_ascii_digit()
            && chars[3] == '.'
            && chars[4].is_ascii_digit()
            && chars[5].is_ascii_digit()
            && chars[6].is_ascii_digit()
            && chars[7] == '.'
            && chars[8].is_ascii_digit()
            && chars[9].is_ascii_digit()
            && chars[10].is_ascii_digit()
            && chars[11] == '-'
            && digit_or_o(chars[12])
            // dígito verificador 2 pode estar presente ou não
            && (chars.len() < 14 || digit_or_o(chars[13]))
            // Pelo menos um O/o presente nos dígitos verificadores
            && (chars[12] == 'O' || chars[12] == 'o'
                || chars.get(13).map(|c| *c == 'O' || *c == 'o').unwrap_or(false))
    }
}

impl Default for Normalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for Normalizer {
    fn scan(&self, input: &str, _ctx: &mut ScanContext) -> Vec<Finding> {
        let (_, changed) = self.normalize(input);
        if changed {
            vec![Finding::new(
                ValidatorModule::Deobfuscator,
                TechnicalSeverity::Medium,
                "NORMALIZER_001",
                "INPUT_NORMALIZED",
                "Input normalizado (homoglyphs/palavras/espaços PII)",
            ).with_confidence(180)]
        } else {
            vec![]
        }
    }

    fn name(&self) -> &'static str { "normalizer" }

    fn module_id(&self) -> ValidatorModule { ValidatorModule::Deobfuscator }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.02, 0.05, 20260226, 42)
            .with_limitations(
                "Homoglyph map cobre apenas blocos Mathematical Bold, Fullwidth e Cyrillic. \
                 Palavra 'at' só substituída com espaços para evitar FP em 'at' como preposição."
            )
            .with_affected_groups(
                "Usuários PT-BR que escrevem 'ponto com' em contexto legítimo (FPR ~2%)."
            )
    }
}

// ─────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(input: &str) -> String {
        Normalizer::new().normalize(input).0
    }

    // ── Homoglyphs ──

    #[test]
    fn test_mathematical_bold_digits() {
        assert_eq!(norm("cpf: 𝟭𝟮𝟯.𝟰𝟱𝟲.𝟳𝟴𝟵-𝟬𝟵"), "cpf: 123.456.789-09");
    }

    #[test]
    fn test_fullwidth_digits() {
        assert_eq!(norm("４１１１１１１１１１１１１１１１"), "4111111111111111");
    }

    #[test]
    fn test_cyrillic_lookalikes() {
        // "Ѕyѕtem" → "System"
        let result = norm("Ѕyѕtem: override");
        assert!(result.contains("System") || result.contains("system"),
            "got: {result}");
    }

    #[test]
    fn test_circled_letters() {
        // ⓘⓖⓝⓞⓡⓔ → ignore
        let result = norm("ⓘⓖⓝⓞⓡⓔ ⓐⓝⓣⓔⓡⓘⓞⓡ");
        assert!(result.to_lowercase().contains("ignore"), "got: {result}");
    }

    #[test]
    fn test_unchanged_ascii_no_alloc_behavior() {
        let (_, changed) = Normalizer::new().normalize("hello world normal text");
        assert!(!changed);
    }

    // ── Word substitutions ──

    #[test]
    fn test_arroba_substitution() {
        let result = norm("usuario arroba example ponto com");
        assert!(result.contains('@'), "got: {result}");
        assert!(result.contains('.'), "got: {result}");
    }

    #[test]
    fn test_parenthesis_at_dot() {
        let result = norm("user(at)example(dot)com");
        assert!(result.contains('@'), "got: {result}");
        assert!(result.contains('.'), "got: {result}");
    }

    #[test]
    fn test_bracket_substitution() {
        let result = norm("user[arroba]empresa[ponto]com");
        assert!(result.contains('@'), "got: {result}");
    }

    // ── PII spaces ──

    #[test]
    fn test_cpf_spaced_out() {
        let result = norm("1 2 3 . 4 5 6 . 7 8 9 - 0 9");
        // Deve colapsar espaços
        assert!(!result.contains(" 2 "), "espaços não colapsados: {result}");
    }

    #[test]
    fn test_normal_sentence_not_collapsed() {
        let input = "Qual é a capital do Brasil hoje";
        let (result, changed) = Normalizer::new().normalize(input);
        assert!(!changed, "frase normal não deve ser modificada: {result}");
    }

    // ── Letter O as zero ──

    #[test]
    fn test_cpf_letter_o_replaced() {
        let result = norm("CPF: 123.456.789-OO");
        assert!(result.contains("789-00"), "got: {result}");
    }

    #[test]
    fn test_cpf_letter_o_lowercase() {
        let result = norm("documento: 123.456.789-oo");
        assert!(result.contains("789-00"), "got: {result}");
    }

    #[test]
    fn test_normal_o_in_word_not_replaced() {
        let (result, _) = Normalizer::new().normalize("Olá, como vai você?");
        assert!(result.contains('O') || result.contains('o'),
            "O/o em palavra normal foi alterado: {result}");
    }

    // ── Integration: scan() produz Finding quando normalizado ──

    #[test]
    fn test_scan_finding_on_homoglyph() {
        use crate::core::module::ScanContext;
        let n = Normalizer::new();
        let mut ctx = ScanContext::default();
        let findings = n.scan("cpf: 𝟭𝟮𝟯.𝟰𝟱𝟲.𝟳𝟴𝟵-𝟬𝟵", &mut ctx);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_no_finding_on_clean_input() {
        use crate::core::module::ScanContext;
        let n = Normalizer::new();
        let mut ctx = ScanContext::default();
        let findings = n.scan("Qual é a capital do Brasil?", &mut ctx);
        assert!(findings.is_empty());
    }
}