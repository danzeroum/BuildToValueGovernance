//! Tool Screen v1.0.0 — PROP-034a (Heuristic Only, Rust Safe)
//! Detecta tool calls suspeitas por pattern matching puro.
//! Sem ML: apenas heurísticas determinísticas (safe para o kernel Rust).
//! Posição no pipeline Executive: após Stats, antes de Evidence.
//!
//! Zero heap no hot path: apenas to_lowercase() é alocada (necessária).
//! Fail-secure: resultado default é Suspicious em qualquer panic.

use crate::interceptor::hooks::{InterceptAction, InterceptResult, RequestInterceptor};

/// Resultado da classificação heurística.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolScreenResult {
    Clean,
    Suspicious { reason: &'static str },
}

/// Padrões de comandos perigosos (comparação direta, case-sensitive).
const DANGEROUS_PATTERNS: &[&str] = &[
    "rm -rf",
    "dd if=",
    "mkfs",
    ":(){ :|:& };",
    "> /dev/",
    "chmod 777",
    "/etc/passwd",
    "/etc/shadow",
    "sudo su",
    "eval(",
    "exec(",
    "__import__(",
    "subprocess.call",
    "os.system(",
];

/// Tool names suspeitas (comparação case-insensitive via lowercase).
const SUSPICIOUS_TOOLS: &[&str] = &[
    "shell_exec",
    "raw_shell",
    "system_call",
    "eval_code",
    "arbitrary_exec",
];

/// Tool Screen heurístico. Implementa `RequestInterceptor`.
pub struct ToolScreen;

impl ToolScreen {
    pub fn new() -> Self { ToolScreen }

    /// Classifica input heuristicamente.
    /// Retorna Suspicious se detectar padrão de risco.
    pub fn classify(&self, input: &str) -> ToolScreenResult {
        for pattern in DANGEROUS_PATTERNS {
            if input.contains(pattern) {
                return ToolScreenResult::Suspicious { reason: "dangerous_cmd_pattern" };
            }
        }
        let lower = input.to_lowercase();
        for tool in SUSPICIOUS_TOOLS {
            if lower.contains(tool) {
                return ToolScreenResult::Suspicious { reason: "suspicious_tool_name" };
            }
        }
        let non_ascii = input.bytes().filter(|b| *b > 127).count();
        if !input.is_empty() && non_ascii * 100 / input.len() > 40 {
            return ToolScreenResult::Suspicious { reason: "high_non_ascii_density" };
        }
        ToolScreenResult::Clean
    }
}

impl Default for ToolScreen {
    fn default() -> Self { Self::new() }
}

impl RequestInterceptor for ToolScreen {
    fn name(&self) -> &'static str { "tool_screen_p034a" }
    fn priority(&self) -> u32 { 90 }
    fn intercept_request(&self, input: &str) -> InterceptResult {
        match self.classify(input) {
            ToolScreenResult::Clean => InterceptResult {
                action: InterceptAction::Continue,
                hook_name: "tool_screen_p034a".to_string(),
            },
            ToolScreenResult::Suspicious { reason } => InterceptResult {
                action: InterceptAction::Block(
                    format!("TOOL_SCREEN_SUSPICIOUS:{}", reason)
                ),
                hook_name: "tool_screen_p034a".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen() -> ToolScreen { ToolScreen::new() }

    #[test]
    fn clean_input_passes() {
        assert_eq!(screen().classify("get_weather(city='São Paulo')"), ToolScreenResult::Clean);
    }

    #[test]
    fn fork_bomb_detected() {
        assert!(matches!(screen().classify(":(){ :|:& };"), ToolScreenResult::Suspicious { .. }));
    }

    #[test]
    fn rm_rf_detected() {
        assert!(matches!(screen().classify("run: rm -rf /tmp"), ToolScreenResult::Suspicious { .. }));
    }

    #[test]
    fn suspicious_tool_name_detected() {
        assert!(matches!(screen().classify("call: shell_exec args"), ToolScreenResult::Suspicious { .. }));
    }

    #[test]
    fn case_insensitive_tool_name() {
        assert!(matches!(screen().classify("SHELL_EXEC invoke"), ToolScreenResult::Suspicious { .. }));
    }

    #[test]
    fn interceptor_blocks_suspicious() {
        let s = ToolScreen::new();
        let r = s.intercept_request("rm -rf /home/user");
        assert!(matches!(r.action, InterceptAction::Block(_)));
        assert_eq!(r.hook_name, "tool_screen_p034a");
    }

    #[test]
    fn interceptor_continues_clean() {
        let s = ToolScreen::new();
        let r = s.intercept_request("search(query='hello')");
        assert_eq!(r.action, InterceptAction::Continue);
    }

    #[test]
    fn high_non_ascii_detected() {
        let payload = "\u{80}\u{81}\u{82}\u{83}hello\u{84}\u{85}\u{86}\u{87}world\u{88}\u{89}\u{8a}\u{8b}";
        assert!(matches!(screen().classify(payload), ToolScreenResult::Suspicious { .. }));
    }

    #[test]
    fn priority_and_name() {
        let s = ToolScreen::new();
        assert_eq!(s.priority(), 90);
        assert_eq!(s.name(), "tool_screen_p034a");
    }
}
