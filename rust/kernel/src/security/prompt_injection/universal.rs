//! Universal Prompt Injection & RLM Detection (Tier 0)
//!
//! Camada de execução rápida (hardcoded) no Rust Kernel.
//! Detecta padrões críticos sem dependência de I/O ou YAML.

use regex::Regex;
use std::sync::LazyLock;

// ==========================================
// TIPOS DE DADOS (Públicos para o mod.rs)
// ==========================================

/// Nível de severidade da detecção.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Categoria do ataque detectado.
#[derive(Debug, Clone, Copy)]
pub enum ThreatCategory {
    Jailbreak,
    RlmRecursion,
    RlmCodeExec,
    Obfuscation,
}

/// Resultado de uma detecção Tier 0.
#[derive(Debug)]
pub struct ThreatSignal {
    pub pattern_id: &'static str,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub confidence: u8,
}

/// Padrão estático otimizado.
pub struct StaticPattern {
    pub id: &'static str,
    pub regex: &'static str,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub confidence: u8,
    pub description: &'static str,
}

// ==========================================
// PADRÕES TIER 0: RLM ATTACKS
// ==========================================

static RLM_REGEX_LIST: LazyLock<Vec<(Regex, &'static StaticPattern)>> = LazyLock::new(|| {
    RLM_PATTERNS.iter().filter_map(|p| {
        Regex::new(p.regex).ok().map(|re| (re, p))
    }).collect()
});

pub static RLM_PATTERNS: &[StaticPattern] = &[
    StaticPattern {
        id: "RLM_T0_001",
        regex: r"llm_query\s*\(",
        category: ThreatCategory::RlmRecursion,
        severity: Severity::Critical,
        confidence: 95,
        description: "Detecta função de chamada recursiva ao LLM",
    },
    StaticPattern {
        id: "RLM_T0_002",
        regex: r"call_self\s*\(",
        category: ThreatCategory::RlmRecursion,
        severity: Severity::Critical,
        confidence: 95,
        description: "Função explícita de auto-chamada",
    },
    StaticPattern {
        id: "RLM_T0_003",
        regex: r"```repl",
        category: ThreatCategory::RlmCodeExec,
        severity: Severity::High,
        confidence: 90,
        description: "Bloco de código REPL detectado",
    },
    StaticPattern {
        id: "RLM_T0_004",
        regex: r"execute_code\s*\(",
        category: ThreatCategory::RlmCodeExec,
        severity: Severity::Critical,
        confidence: 98,
        description: "Chamada explícita para execução de código",
    },
];

// ==========================================
// PADRÕES TIER 0: JAILBREAK (DAN PRIMARY)
// ==========================================

static JAILBREAK_REGEX_LIST: LazyLock<Vec<(Regex, &'static StaticPattern)>> = LazyLock::new(|| {
    JAILBREAK_PATTERNS.iter().filter_map(|p| {
        Regex::new(p.regex).ok().map(|re| (re, p))
    }).collect()
});

pub static JAILBREAK_PATTERNS: &[StaticPattern] = &[
    StaticPattern {
        id: "JAILBREAK_T0_001",
        regex: r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        category: ThreatCategory::Jailbreak,
        severity: Severity::Critical,
        confidence: 98,
        description: "Override total de instruções (DAN Clássico)",
    },
    StaticPattern {
        id: "JAILBREAK_T0_002",
        regex: r"(?i)you\s+are\s+now\s+(dan|do\s+anything\s+now)",
        category: ThreatCategory::Jailbreak,
        severity: Severity::Critical,
        confidence: 95,
        description: "Ativação de persona DAN",
    },
    StaticPattern {
        id: "JAILBREAK_T0_003",
        regex: r"(?i)(developer|debug|admin)\s+mode\s+(enabled|activated)",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 85,
        description: "Injeção de modo privilegiado",
    },
];

// ==========================================
// FUNÇÃO DE DETECÇÃO
// ==========================================

/// Escaneia o input contra todos os padrões Tier 0.
/// Retorna o primeiro sinal crítico encontrado.
pub fn detect_tier0(input: &str) -> Option<ThreatSignal> {
    // Checagem RLM
    for (re, pattern) in RLM_REGEX_LIST.iter() {
        if re.is_match(input) {
            return Some(ThreatSignal {
                pattern_id: pattern.id,
                category: pattern.category,
                severity: pattern.severity,
                confidence: pattern.confidence,
            });
        }
    }

    // Checagem Jailbreak
    for (re, pattern) in JAILBREAK_REGEX_LIST.iter() {
        if re.is_match(input) {
            return Some(ThreatSignal {
                pattern_id: pattern.id,
                category: pattern.category,
                severity: pattern.severity,
                confidence: pattern.confidence,
            });
        }
    }

    None
}