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

#[allow(dead_code)]
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
    StaticPattern {
        id: "JAILBREAK_T0_004",
        regex: r"(?i)dev(?:eloper)?\s+mode\s*[:\-]\s*\w+",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 82,
        description: "Modo desenvolvedor com separador alternativo (colon/dash)",
    },
    StaticPattern {
        id: "JAILBREAK_T0_005",
        regex: r"(?i)(?:don\'?t|do\s+not)(?:\s+need\s+to)?\s+follow\s+(?:these|those|the|any|your)\s+(?:rules?|instructions?|guidelines?|restrictions?)",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 80,
        description: "Override indireto via negacao de obrigacao de seguir regras",
    },
    // ── PT-BR Tier 0 — Promovidos de Tier 1 (RT-001 bypasses) ──
    StaticPattern {
        id: "JAILBREAK_T0_006",
        regex: r"(?i)\bdesconsidere\s+(tudo|as|todas)\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::Critical,
        confidence: 95,
        description: "PT-BR: desconsidere tudo/as instruções",
    },
    StaticPattern {
        id: "JAILBREAK_T0_007",
        regex: r"(?i)\besqu[eê][çc]a\s+(?:todas?\s+)?(?:as\s+)?(?:suas?\s+)?(?:diretrizes?|regras?|instru[çc][õo]es?)\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::Critical,
        confidence: 92,
        description: "PT-BR: esqueça diretrizes/regras/instruções",
    },
    StaticPattern {
        id: "JAILBREAK_T0_008",
        regex: r"(?i)\baja\s+como\s+(um|uma|se\s)?\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 80,
        description: "PT-BR: aja como (role-play injection)",
    },
    StaticPattern {
        id: "JAILBREAK_T0_009",
        regex: r"(?i)\bmodo\s+(sem\s+restri[çc][õo]es|desenvolvedor|irrestrito)\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::Critical,
        confidence: 95,
        description: "PT-BR: modo desenvolvedor/irrestrito/sem restrições",
    },
    StaticPattern {
        id: "JAILBREAK_T0_010",
        regex: r"(?i)\bsem\s+(regras|restri[çc][õo]es|limites)\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 85,
        description: "PT-BR: sem regras/restrições/limites",
    },
    StaticPattern {
        id: "JAILBREAK_T0_011",
        regex: r"(?i)\bnovo\s+(comando|prompt)\s*(do\s+sistema)?\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 88,
        description: "PT-BR: novo comando/prompt do sistema",
    },
    StaticPattern {
        id: "JAILBREAK_T0_012",
        regex: r"(?i)\bignore\s+(as\s+)?instru[çc][õo]es\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::Critical,
        confidence: 95,
        description: "PT-BR: ignore as instruções",
    },
    StaticPattern {
        id: "JAILBREAK_T0_013",
        regex: r"(?i)\bfinja\s+que\s+(voc[êe]|tu)\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 82,
        description: "PT-BR: finja que você (role impersonation)",
    },
    // ── Universal (EN) — RT-001 expanded bypasses ──
    StaticPattern {
        id: "JAILBREAK_T0_014",
        regex: r"(?i)\bdisregard\s+(all\s+)?(previous|prior|above)",
        category: ThreatCategory::Jailbreak,
        severity: Severity::Critical,
        confidence: 95,
        description: "Disregard previous instructions",
    },
    StaticPattern {
        id: "JAILBREAK_T0_015",
        regex: r"(?i)\bforget\s+(?:everything|all|previous|the\s+\w+)",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 88,
        description: "Forget everything/previous",
    },
    StaticPattern {
        id: "JAILBREAK_T0_016",
        regex: r"(?i)\boverride\s+(?:your|the|all)\s+(?:your\s+)?(?:instructions?|rules?|guidelines?|safety\s+settings?)",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 88,
        description: "Override instructions/rules/safety settings",
    },
    StaticPattern {
        id: "JAILBREAK_T0_017",
        regex: r"(?i)\bbypass\s+(your|the|all)?\s*(safety|security|content\s+)?filters?",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 85,
        description: "Bypass safety/content filters",
    },
    StaticPattern {
        id: "JAILBREAK_T0_018",
        regex: r"(?i)\bjailbreak\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::Critical,
        confidence: 90,
        description: "Explicit jailbreak keyword",
    },
    StaticPattern {
        id: "JAILBREAK_T0_019",
        regex: r"(?i)\bunrestricted\s+(?:mode|AI|responses?|bot|access)\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 85,
        description: "Unrestricted mode/AI/responses",
    },
    StaticPattern {
        id: "JAILBREAK_T0_020",
        regex: r"(?i)\bpretend\s+.{0,50}(?:guidelines?|safety|restrictions?)\s+do\s+not\s+exist\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 85,
        description: "Creative writing bypass — pretend guidelines don't exist",
    },
    // ── ES Tier 0 — cobertura multilíngue ──
    StaticPattern {
        id: "JAILBREAK_T0_021",
        regex: r"(?i)\bignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\b",
        category: ThreatCategory::Jailbreak,
        severity: Severity::Critical,
        confidence: 95,
        description: "ES: ignora (todas) las instrucciones",
    },
    // ── Data Exfiltration ──
    StaticPattern {
        id: "JAILBREAK_T0_022",
        regex: r"(?i)\b(?:output|print|repeat|show)\s+(?:your\s+)?(?:initialization|initial|system)\s+(?:prompt|instructions?)",
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 88,
        description: "Data exfiltration — output system/initialization prompt",
    },
    // ── Delimiter Injection ──
    StaticPattern {
        id: "JAILBREAK_T0_023",
        regex: r#"(?i)\{\s*"role"\s*:\s*"system""#,
        category: ThreatCategory::Jailbreak,
        severity: Severity::High,
        confidence: 88,
        description: "JSON role:system delimiter injection",
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