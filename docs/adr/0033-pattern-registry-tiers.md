# ADR-0033: PatternRegistry — Tier 0/1/2, ArcSwap e Epoch

**Status:** 🔒 Planejado
**Data:** 24 de fevereiro de 2026
**Autores:** BuildToValue AI Squad (Arquiteta + Staff Engineer)
**Versão Alvo:** v1.6.0
**Grupo:** J — Multilingual & Multi-tenant Foundation
**Depende de:** ADR-0032 (ScanContextFlags)
**Bloqueado por:** ADR-0032 mergeado

---

## 1. Contexto

### Estado atual

O `PromptInjectionDetector` (ADR-028) armazena todos os patterns em quatro
`lazy_static!` compilados em tempo de build:

```
EN_PATTERNS:        15 regex — sempre em memória
PT_PATTERNS:         8 regex — sempre em memória
DELIMITER_PATTERNS: 11 regex — sempre em memória
STRUCTURAL_PATTERNS: 4 regex — sempre em memória
```

Consequências diretas deste design:

1. **Novos idiomas exigem recompilação e redeploy do binário.** Adicionar
   padrões em russo ou árabe não é possível sem um novo release de kernel.

2. **Todos os patterns de todos os idiomas carregam na memória,
   independente do idioma configurado no deployment.** Um deploy brasileiro
   (PT/EN) carrega patterns de idiomas não usados.

3. **Não há controle de versão dos patterns em runtime.** Quando um pattern
   é atualizado, não há como saber qual versão foi usada em uma decisão
   específica registrada no Ledger. Isso prejudica contestabilidade.

4. **Hot reload é impossível.** Correção de um FP massivo exige restart
   do processo, causando downtime.

### Forças adicionais

- O `phf` já está no workspace (`Cargo.toml`), mas não está sendo usado
  para patterns de segurança — apenas para `compliance/penalty.rs`.
- O `arc_swap` **não está no workspace** — precisa ser adicionado.
- O `serde_yaml` já está disponível para leitura de YAML em runtime.
- O ADR-032 introduz `ScanContextFlags.pattern_epoch: u64`, que só tem
  semântica útil se existir um registro de versão de patterns para
  correlacionar.

---

## 2. Alternativas Consideradas

### A — Manter lazy_static + adicionar novos idiomas como novos lazy_static
**Rejeitada.** Arquivo `prompt_injection.rs` cresce para 2000+ linhas.
Viola regra de arquivos ≤ 200 linhas. Todos os patterns continuam
sempre em memória.

### B — Build-time completo via build.rs + PHF para todos os idiomas
**Rejeitada para Tier 2.** Compilar 100+ idiomas via `build.rs` inflaria
o binário e tornaria impossível hot-reload de patterns sem recompilação.
Correto apenas para idiomas de deployment primário (EN, PT).

### C — Runtime puro com YAML (sem build-time)
**Rejeitada para Tier 0/1.** Delimiters universais e patterns EN/PT
devem ser garantidos mesmo se o filesystem falhar. Dependência de I/O
para patterns críticos viola fail-secure.

### D — Arquitetura em três tiers com estratégias distintas por tier (adotada)
**Adotada.** Cada tier tem a estratégia de carregamento adequada ao seu
perfil de mudança e criticidade.

---

## 3. Decisão

Implementar um `PatternRegistry` com três tiers de carregamento,
isolando a lógica do `PromptInjectionDetector` em um submódulo com
quatro arquivos, respeitando o limite de 200 linhas por arquivo.

### 3.1 Definição dos Tiers

| Tier | Nome | Conteúdo | Carregamento | Atualização |
|:----:|:-----|:---------|:-------------|:------------|
| 0 | Universal | Delimiters, structural patterns idioma-agnósticos | Hardcoded em `universal.rs` | Recompilação |
| 1 | Primary | EN, PT (deployment primário) | `build.rs` via `include_str!` + `OnceLock` | Recompilação |
| 2 | Extended | FR, DE, RU, ZH, AR e demais | YAML runtime via `ArcSwap` | Deploy de YAML |

**Invariante de Tier 0:** os delimiters (`<|system|>`, `[INST]`, `###System:`,
etc.) e os structural patterns (`{"role":"system"}`, XML-like tags) NUNCA
dependem de YAML, de idioma detectado, ou de qualquer estado externo.
São a última linha de defesa e devem funcionar em qualquer condição.

**Invariante de Tier 1:** patterns EN e PT são compilados em build-time
via `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/policies/security/patterns_en.yaml"))`.
O YAML é a fonte canônica (editável por humanos), mas o Rust compilado
é o runtime (zero I/O). Mudanças exigem recompilação — isso é intencional.

**Invariante de Tier 2:** qualquer idioma não listado em Tier 1 carrega
via YAML runtime. O primeiro request de um idioma não cacheado paga o
custo de parsing (~2ms). Requests subsequentes custam zero (snapshot
imutável via `ArcSwap`).

### 3.2 Estrutura de Arquivos

```
rust/kernel/src/security/
├── mod.rs                    # re-exports existentes (sem mudança)
├── prompt_injection/         # NOVO — substitui prompt_injection.rs
│   ├── mod.rs                # orquestrador: coordena tiers por flags
│   ├── universal.rs          # Tier 0: delimiters + structural hardcoded
│   ├── registry.rs           # PatternRegistry: ArcSwap + epoch
│   └── loader.rs             # YAML → Vec<CompiledPattern> (Tier 2)
└── language_detector.rs      # ADR-034 (sprint seguinte)
```

Cada arquivo respeita o limite de ≤ 200 linhas.

### 3.3 Tipos Fundamentais

```rust
// rust/kernel/src/security/prompt_injection/mod.rs

/// Código de idioma — mapeado dos bits de ScanContextFlags.lang_bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LangCode {
    En,    // bit 0
    Pt,    // bit 1
    Es,    // bit 2
    Fr,    // bit 3
    De,    // bit 4
    Ru,    // bit 5
    Zh,    // bit 6
    Ar,    // bit 7
    Universal, // Tier 0 — idioma-agnóstico
}

/// Pattern compilado: regex + categoria + severidade declarada.
pub struct CompiledPattern {
    pub regex: Regex,
    pub category: &'static str,  // ex: "INSTRUCTION_OVERRIDE"
    pub risk: PatternRisk,
}

#[derive(Debug, Clone, Copy)]
pub enum PatternRisk {
    Medium,
    High,
    Critical,
}
```

### 3.4 PatternRegistry com ArcSwap e Epoch

```rust
// rust/kernel/src/security/prompt_injection/registry.rs

use arc_swap::ArcSwap;
use std::sync::{Arc, OnceLock, atomic::{AtomicU64, Ordering}};
use std::collections::HashMap;
use super::{LangCode, CompiledPattern};

pub struct PatternRegistry {
    /// Tier 1: EN + PT compilados em build-time.
    /// OnceLock garante inicialização única; zero I/O após primeira chamada.
    tier1: OnceLock<HashMap<LangCode, Vec<CompiledPattern>>>,

    /// Tier 2: idiomas estendidos carregados via YAML.
    /// ArcSwap permite hot-reload atômico sem lock global.
    tier2: ArcSwap<HashMap<LangCode, Vec<CompiledPattern>>>,

    /// Epoch global: incrementa a cada reload do Tier 2.
    /// Capturado em ScanContextFlags.pattern_epoch no início do scan.
    epoch: AtomicU64,
}

impl PatternRegistry {
    pub fn new() -> Self {
        Self {
            tier1: OnceLock::new(),
            tier2: ArcSwap::new(Arc::new(HashMap::new())),
            epoch: AtomicU64::new(1), // epoch 0 = sem registry (Tier 0/1 apenas)
        }
    }

    /// Retorna epoch atual e snapshot imutável dos Tier 2.
    /// ZERO-COPY: ArcSwap garante que nenhum scan vê estado parcial de reload.
    /// Chamado pelo orquestrador antes de iniciar o scan de patterns.
    pub fn snapshot(&self) -> (u64, Arc<HashMap<LangCode, Vec<CompiledPattern>>>) {
        let epoch = self.epoch.load(Ordering::Acquire);
        let data  = self.tier2.load_full();
        (epoch, data)
    }

    /// Retorna patterns Tier 1 para o idioma dado.
    /// Inicializa o OnceLock na primeira chamada (startup penalty, não hot path).
    pub fn tier1_patterns(&self, lang: LangCode) -> Option<&[CompiledPattern]> {
        self.tier1
            .get_or_init(loader::load_tier1)
            .get(&lang)
            .map(|v| v.as_slice())
    }

    /// Hot-reload do Tier 2 (chamado fora do hot path).
    /// Pode ser disparado por inotify, endpoint admin, ou intervalo de polling.
    pub fn reload_tier2(&self, new_data: HashMap<LangCode, Vec<CompiledPattern>>) {
        self.tier2.store(Arc::new(new_data));
        self.epoch.fetch_add(1, Ordering::Release);
    }

    /// Retorna true se o idioma tem cobertura em Tier 1 ou Tier 2.
    pub fn covers_lang(&self, lang: LangCode) -> bool {
        if self.tier1_patterns(lang).is_some() {
            return true;
        }
        let snapshot = self.tier2.load();
        snapshot.contains_key(&lang)
    }
}

/// Instância global do registry — inicializada uma vez no startup do kernel.
pub static REGISTRY: OnceLock<PatternRegistry> = OnceLock::new();

pub fn global_registry() -> &'static PatternRegistry {
    REGISTRY.get_or_init(PatternRegistry::new)
}
```

### 3.5 Universal (Tier 0) — hardcoded, sempre ativo

```rust
// rust/kernel/src/security/prompt_injection/universal.rs
// ≤ 200 linhas

use lazy_static::lazy_static;
use regex::Regex;
use crate::evidence::Finding;
use crate::core::types::{TechnicalSeverity, ValidatorModule};

// Delimiters: idioma-agnósticos, sempre críticos
lazy_static! {
    static ref DELIMITER_PATTERNS: Vec<Regex> = compile(&[
        r"<\|system\|>",
        r"<\|user\|>",
        r"<\|assistant\|>",
        r"\[INST\]",
        r"\[/INST\]",
        r"###\s*(System|User|Assistant)\s*:",
        r"```\s*system",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
    ]);

    // Structural: JSON role injection, XML-like tags
    static ref STRUCTURAL_PATTERNS: Vec<Regex> = compile(&[
        r#"(?i)\{[^{}]{0,50}"role"\s*:\s*"(system|assistant)"[^{}]{0,100}"content"\s*:"#,
        r"</?(?:s|system|user|assistant|instruction|prompt|context)>",
        r"(?i)IMPORTANT:\s*(?:ignore|override|forget|disregard)",
        r"(?i)(?:BEGIN|START)\s+(?:NEW|OVERRIDE)\s+(?:INSTRUCTIONS?|PROMPT)",
    ]);
}

/// Escaneia apenas Tier 0 (universal). Idioma-agnóstico.
/// Chamado SEMPRE, independente de idioma detectado.
pub fn scan(input: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for pattern in DELIMITER_PATTERNS.iter() {
        if pattern.is_match(input) {
            findings.push(Finding::new(
                ValidatorModule::PromptInjection,
                TechnicalSeverity::Critical(255),
                "DELIMITER_INJECTION",
                "TIER0_UNIVERSAL",
                &mask(input),
            ).with_confidence(98));
        }
    }

    for pattern in STRUCTURAL_PATTERNS.iter() {
        if pattern.is_match(input) {
            findings.push(Finding::new(
                ValidatorModule::PromptInjection,
                TechnicalSeverity::High,
                "STRUCTURAL_INJECTION",
                "TIER0_UNIVERSAL",
                &mask(input),
            ).with_confidence(90));
        }
    }

    findings
}

fn compile(patterns: &[&str]) -> Vec<Regex> {
    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
}

fn mask(input: &str) -> String {
    if input.len() <= 20 { return "***".to_string(); }
    format!("{}...{}", &input[..10], &input[input.len()-10..])
}
```

### 3.6 Loader (Tier 1 + Tier 2)

```rust
// rust/kernel/src/security/prompt_injection/loader.rs
// ≤ 200 linhas

use std::collections::HashMap;
use regex::Regex;
use super::{LangCode, CompiledPattern, PatternRisk};

/// Carrega Tier 1 (EN + PT) via YAML embutido em build-time.
/// include_str! garante zero I/O em runtime; o YAML é validado
/// em compile-time implicitamente (falha de parse = panic no init).
pub fn load_tier1() -> HashMap<LangCode, Vec<CompiledPattern>> {
    let en_yaml = include_str!(
        concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../data/policies/security/patterns_en.yaml")
    );
    let pt_yaml = include_str!(
        concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../data/policies/security/patterns_pt.yaml")
    );

    let mut map = HashMap::new();
    map.insert(LangCode::En, parse_yaml(en_yaml));
    map.insert(LangCode::Pt, parse_yaml(pt_yaml));
    map
}

/// Carrega Tier 2 (idioma estendido) de um arquivo YAML no filesystem.
/// Retorna None se o arquivo não existir ou falhar no parse.
/// Falha não bloqueia o scan — apenas o idioma específico fica sem cobertura.
pub fn load_tier2_from_file(path: &std::path::Path)
    -> Option<(LangCode, Vec<CompiledPattern>)>
{
    let content = std::fs::read_to_string(path).ok()?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&content).ok()?;
    let lang  = parse_lang_code(doc.get("lang")?.as_str()?)?;
    let patterns = parse_yaml(&content);
    if patterns.is_empty() { return None; }
    Some((lang, patterns))
}

fn parse_yaml(yaml: &str) -> Vec<CompiledPattern> {
    let doc: serde_yaml::Value = match serde_yaml::from_str(yaml) {
        Ok(v)  => v,
        Err(_) => return Vec::new(),
    };

    let Some(patterns) = doc.get("patterns").and_then(|v| v.as_sequence()) else {
        return Vec::new();
    };

    patterns.iter().filter_map(|entry| {
        let regex_str = entry.get("regex")?.as_str()?;
        let risk_str  = entry.get("risk")?.as_str().unwrap_or("medium");
        let category  = entry.get("category")?.as_str().unwrap_or("INSTRUCTION_OVERRIDE");

        Some(CompiledPattern {
            regex: Regex::new(regex_str).ok()?,
            category: Box::leak(category.to_string().into_boxed_str()),
            risk: match risk_str {
                "high"     => PatternRisk::High,
                "critical" => PatternRisk::Critical,
                _          => PatternRisk::Medium,
            },
        })
    }).collect()
}

fn parse_lang_code(s: &str) -> Option<LangCode> {
    match s {
        "en" => Some(LangCode::En), "pt" => Some(LangCode::Pt),
        "es" => Some(LangCode::Es), "fr" => Some(LangCode::Fr),
        "de" => Some(LangCode::De), "ru" => Some(LangCode::Ru),
        "zh" => Some(LangCode::Zh), "ar" => Some(LangCode::Ar),
        _    => None,
    }
}
```

### 3.7 Orquestrador (mod.rs)

```rust
// rust/kernel/src/security/prompt_injection/mod.rs
// ≤ 200 linhas

use crate::core::module::{Module, ScanContext};
use crate::core::types::{BiasDeclaration, TechnicalSeverity, ValidatorModule};
use crate::evidence::Finding;
use super::super::core::module::ScanContextFlags;
use self::{registry::global_registry, universal};

mod universal;
mod registry;
mod loader;

pub use registry::{PatternRegistry, global_registry};

pub struct PromptInjectionDetector;

impl PromptInjectionDetector {
    pub fn new() -> Self {
        // Força inicialização do Tier 1 no startup (fora do hot path)
        let _ = global_registry().tier1_patterns(super::LangCode::En);
        let _ = global_registry().tier1_patterns(super::LangCode::Pt);
        Self
    }
}

impl Module for PromptInjectionDetector {
    fn scan(&self, input: &str, ctx: &mut ScanContext) -> Vec<Finding> {
        if input.len() < 10 { return Vec::new(); }

        let mut findings = Vec::new();

        // ── Tier 0: sempre, idioma-agnóstico ─────────────────────────
        findings.extend(universal::scan(input));

        // ── Tier 1/2: apenas se idioma detectado com confiança ────────
        if ctx.flags.is_language_undetermined() {
            // Undetermined: apenas Tier 0 aplicado — fail-secure reduzindo FP
            return findings;
        }

        // Captura epoch e snapshot do Tier 2 atomicamente
        let (epoch, snapshot) = global_registry().snapshot();
        ctx.flags.pattern_epoch = epoch;

        // Itera sobre idiomas detectados no bitmask
        for &(lang_bit, lang_code) in &[
            (ScanContextFlags::LANG_EN, super::LangCode::En),
            (ScanContextFlags::LANG_PT, super::LangCode::Pt),
            (ScanContextFlags::LANG_ES, super::LangCode::Es),
            (ScanContextFlags::LANG_FR, super::LangCode::Fr),
            (ScanContextFlags::LANG_DE, super::LangCode::De),
            (ScanContextFlags::LANG_RU, super::LangCode::Ru),
            (ScanContextFlags::LANG_ZH, super::LangCode::Zh),
            (ScanContextFlags::LANG_AR, super::LangCode::Ar),
        ] {
            if !ctx.flags.has_lang(lang_bit) { continue; }

            // Tier 1 (build-time)
            if let Some(patterns) = global_registry().tier1_patterns(lang_code) {
                findings.extend(scan_patterns(input, patterns));
            }
            // Tier 2 (runtime YAML)
            else if let Some(patterns) = snapshot.get(&lang_code) {
                findings.extend(scan_patterns(input, patterns));
            }
            // Idioma sem cobertura → UNSUPPORTED_LANGUAGE Finding
            else {
                findings.push(Finding::new(
                    ValidatorModule::PromptInjection,
                    TechnicalSeverity::Medium,
                    "UNSUPPORTED_LANGUAGE",
                    "LANG_COVERAGE_GAP",
                    &format!("lang_bit={:#018x}", lang_bit),
                ).with_confidence(70));
            }
        }

        findings
    }

    fn name(&self) -> &'static str { "prompt_injection" }
    fn module_id(&self) -> ValidatorModule { ValidatorModule::PromptInjection }

    fn bias_declaration(&self) -> BiasDeclaration {
        BiasDeclaration::new(0.08, 0.18, 20260224, 350)
            .with_limitations(
                "Heuristic only: keyword + structural signals. \
                 Cannot detect semantic attacks without keywords. \
                 Tier 2 languages: first-request penalty ~2ms."
            )
            .with_affected_groups(
                "Developers (code snippets FPR). \
                 Non-EN/PT speakers (FNR until Tier 2 loaded). \
                 AI educators (FPR)."
            )
    }
}

fn scan_patterns(input: &str, patterns: &[super::CompiledPattern]) -> Vec<Finding> {
    patterns.iter()
        .filter(|p| p.regex.is_match(input))
        .map(|p| {
            let severity = match p.risk {
                super::PatternRisk::Critical => TechnicalSeverity::Critical(255),
                super::PatternRisk::High     => TechnicalSeverity::High,
                super::PatternRisk::Medium   => TechnicalSeverity::Medium,
            };
            Finding::new(
                ValidatorModule::PromptInjection,
                severity,
                "PROMPT_INJECTION_DETECTED",
                p.category,
                &mask_input(input),
            ).with_confidence(match p.risk {
                super::PatternRisk::Critical => 95,
                super::PatternRisk::High     => 85,
                super::PatternRisk::Medium   => 60,
            })
        })
        .collect()
}

fn mask_input(input: &str) -> String {
    if input.len() <= 20 { return "***".to_string(); }
    format!("{}...{}", &input[..10], &input[input.len()-10..])
}
```

### 3.8 YAML de Patterns (fonte canônica para Tier 1 e Tier 2)

```yaml
# data/policies/security/patterns_en.yaml
# Tier 1 — EN (compilado em build-time via include_str!)
version: "1.0"
lang: "en"
patterns:
  - regex: "(?i)\\bignore\\s+(all\\s+)?(previous|prior|above)\\s+(instructions?|prompts?|rules?)"
    category: INSTRUCTION_OVERRIDE
    risk: high
  - regex: "(?i)\\byou\\s+are\\s+now\\b"
    category: ROLE_CONFUSION
    risk: high
  - regex: "(?i)\\bjailbreak\\b"
    category: JAILBREAK
    risk: critical
  # ... demais patterns EN migrados do lazy_static atual
```

```yaml
# data/policies/security/patterns_pt.yaml
# Tier 1 — PT (compilado em build-time via include_str!)
version: "1.0"
lang: "pt"
patterns:
  - regex: "(?i)\\bignore\\s+(as\\s+)?instru[çc][õo]es\\b"
    category: INSTRUCTION_OVERRIDE
    risk: high
  - regex: "(?i)\\bdesconsidere\\s+(tudo|as|todas)\\b"
    category: INSTRUCTION_OVERRIDE
    risk: high
  - regex: "(?i)\\bresponda\\s+sem\\s+(filtros?|censura|restrições)\\b"
    category: FILTER_BYPASS
    risk: high
  # ... demais patterns PT migrados + novos do RT-001
```

```yaml
# data/policies/security/patterns_ru.yaml
# Tier 2 — RU (carregado em runtime, lazy)
version: "1.0"
lang: "ru"
patterns:
  - regex: "(?i)игнорируй\\s+инструкции"
    category: INSTRUCTION_OVERRIDE
    risk: high
  - regex: "(?i)притворись\\s+что"
    category: ROLE_CONFUSION
    risk: medium
```

### 3.9 Mudanças no Cargo.toml

```toml
# rust/Cargo.toml — workspace.dependencies — adicionar:
arc_swap = "1.7"

# rust/kernel/Cargo.toml — dependencies — adicionar:
arc_swap = { workspace = true }
```

`whatlang` é adicionado no ADR-034 (Language Detection), não aqui.

---

## 4. Impacto na Migração do ADR-028

O arquivo `rust/kernel/src/security/prompt_injection.rs` é substituído
pelo diretório `rust/kernel/src/security/prompt_injection/`. A interface
pública não muda:

```rust
// security/mod.rs — sem mudança
pub use prompt_injection::PromptInjectionDetector;
```

Os 4 `lazy_static!` atuais (`EN_PATTERNS`, `PT_PATTERNS`, `DELIMITER_PATTERNS`,
`STRUCTURAL_PATTERNS`) migram para:
- `DELIMITER_PATTERNS` + `STRUCTURAL_PATTERNS` → `universal.rs` (Tier 0)
- `EN_PATTERNS` → `data/policies/security/patterns_en.yaml` (Tier 1)
- `PT_PATTERNS` → `data/policies/security/patterns_pt.yaml` (Tier 1, expandido)

Todos os testes existentes em `prompt_injection.rs` migram para
`prompt_injection/mod.rs` sem mudança de lógica.

---

## 5. Fundamento Filosófico

**Rawls (Blind Policy Testing):** o YAML como fonte canônica de patterns
permite que um comitê ético revise os patterns sem precisar ler código Rust.
Política é lei; código é enforcement. A separação é intencional.

**Jonas (Responsabilidade Proporcional):** o `pattern_epoch` registrado na
`TechnicalEvidence` responde "qual versão de patterns bloqueou este usuário?"
Sem epoch versionado, BiasDeclaration de um período específico é irrastreável.

**Levinas (Proteção do Usuário):** o Tier 0 hardcoded garante que delimiters
críticos são sempre detectados, mesmo que o YAML loader falhe, o filesystem
esteja indisponível, ou o idioma seja indeterminado. Fail-secure por design.

---

## 6. Consequências

### Positivas

- Novos idiomas (RU, ZH, AR) adicionados via YAML sem recompilação.
- Hot-reload de patterns Tier 2 via `reload_tier2()` sem restart do processo.
- `pattern_epoch` em `TechnicalEvidence` viabiliza auditoria forense de versão.
- Arquivos ≤ 200 linhas — invariante de projeto respeitado.
- PatternRegistry reutilizável para PII validators (ADR-035 seguirá a mesma
  arquitetura para `data/policies/security/pii_*.yaml`).

### Negativas e Trade-offs

- **Primeiro request de idioma Tier 2: +2ms** para parse de YAML e compilação
  de regex. Aceitável dentro do SLA de <30ms. Documentado na BiasDeclaration.
- **`Box::leak` no loader Tier 2** para converter `String` → `&'static str`
  em `category`. Alternativa: usar `Arc<str>` com custo de Arc overhead.
  `Box::leak` é preferível para patterns que vivem para sempre no processo.
- **Crescimento de memória linear com idiomas Tier 2 ativos:** ~200KB por
  idioma. 10 idiomas simultâneos = ~2MB. Dentro do budget do processo.

---

## 7. Critérios de Aceitação

- [ ] `arc_swap = "1.7"` adicionado ao `Cargo.toml` workspace
- [ ] `rust/kernel/src/security/prompt_injection/` existe com 4 arquivos ≤ 200 linhas cada
- [ ] `rust/kernel/src/security/prompt_injection.rs` removido (substituído pelo diretório)
- [ ] `data/policies/security/patterns_en.yaml` e `patterns_pt.yaml` criados
- [ ] `global_registry().tier1_patterns(LangCode::En)` retorna ≥ 10 patterns
- [ ] `global_registry().tier1_patterns(LangCode::Pt)` retorna ≥ 8 patterns
- [ ] Scan com idioma undetermined retorna apenas findings Tier 0
- [ ] Scan com `LANG_PT` ativo retorna findings Tier 0 + findings PT
- [ ] `ctx.flags.pattern_epoch > 0` após scan com Tier 1 ativo
- [ ] `evidence._reserved_metadata[0..8]` contém epoch em LE após scan
- [ ] Hot-reload via `reload_tier2()` incrementa epoch e reflete em scans seguintes
- [ ] Todos os testes existentes do `PromptInjectionDetector` passam sem mudança de lógica
- [ ] RT-001 roda sem regressão (detecções e FPs iguais ou melhores)

---

## 8. Referências

- `rust/kernel/src/security/prompt_injection.rs` — arquivo atual a ser substituído
- `rust/Cargo.toml` — workspace dependencies
- `rust/kernel/Cargo.toml` — kernel dependencies
- ADR-028 (Heuristic Prompt Injection Detector — especificação original)
- ADR-032 (ScanContextFlags — fonte de `lang_bitmask` e `pattern_epoch`)
- ADR-034 (Language Detection — preenche `lang_bitmask` antes do scan)
- `data/policies/security/` — diretório de patterns YAML (criar em v1.6.0)
