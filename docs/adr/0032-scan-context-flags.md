
# ADR-0032: ScanContextFlags — Layout dos 64 Bytes Reservados

**Status:** 🚧 Em Implementação
**Data:** 24 de fevereiro de 2026
**Autores:** BuildToValue AI Squad (Arquiteta + Staff Engineer)
**Versão Alvo:** v1.6.0
**Grupo:** J — Multilingual & Multi-tenant Foundation
**Próximo disponível:** ADR-0033

---

## 1. Contexto

### Estado atual

O `ScanContext` em `rust/kernel/src/core/module.rs` possui:

```rust
pub struct ScanContext {
    pub stats: InputStatistics,
    pub _reserved: [u8; 64],  // "para futuras extensões"
}
```

Esse campo `_reserved` existe desde a criação do pipeline, mas permanece
sem semântica documentada. Qualquer módulo que precisar de metadado de
contexto (idioma detectado, jurisdição ativa, tenant, versão de patterns)
não tem contrato para ler ou escrever.

### Forças que motivam a decisão agora

Três roadmap items convergem em v1.6.0 e todos precisam do mesmo slot
de 64 bytes:

1. **Language Detection (ADR-034):** o `LanguageDetector` precisa comunicar
   o idioma detectado para o `PromptInjectionDetector` selecionar patterns
   do `PatternRegistry` correto.

2. **Multi-jurisdiction PII (ADR-035):** o dispatcher de validators precisa
   saber quais jurisdições estão habilitadas neste scan sem consultar banco
   de dados ou receber parâmetros extras em todas as assinaturas de módulo.

3. **Multi-tenant Foundation (v2.0+):** o gateway precisará isolar política
   e evidência por tenant. Introduzir `tenant_key` como placeholder agora
   evita migração de ABI em v2.0 quando o multi-tenant for implementado de fato.

### Por que agora e não depois

A mudança de `_reserved: [u8; 64]` para `flags: ScanContextFlags` é a
**única mudança que quebra ABI** no pipeline de módulos — toda chamada
`Module::scan(&str, &mut ScanContext)` precisa compilar com o novo layout.
Fazer isso em v1.6.0 (antes de qualquer módulo novo que precise das flags)
é o momento de menor custo. Adiar para v1.7+ seria fazer a migration com
5–8 módulos já dependendo de `_reserved`.

---

## 2. Alternativas Consideradas

### A — Vec<Language> no ScanContext
**Rejeitada.** Introduz heap allocation no hot path, violando o invariante
mais crítico do sistema (zero heap em `scan()`). Um `Vec` dentro de qualquer
struct passado por valor no hot path invalida garantias de latência determinística.

### B — Passar idioma como parâmetro adicional em Module::scan()
**Rejeitada.** Muda a assinatura do trait `Module` e requer que todos os
13 módulos atuais atualizem sua implementação. Também não resolve jurisdição,
tenant e epoch sem proliferar parâmetros.

### C — Campo separado fora do ScanContext (global/thread-local)
**Rejeitada.** Introduz estado implícito, dificulta testabilidade e viola
o princípio de que cada scan é isolado e determinístico.

### D — Bitmasks dentro do _reserved existente (decisão adotada)
**Adotada.** O campo `_reserved: [u8; 64]` foi projetado para este uso.
Bitmasks são operações O(1) sem alocação, L1 cache-friendly, e o layout
de 64 bytes acomoda todos os campos necessários até v2.0+.

---

## 3. Decisão

Substituir `_reserved: [u8; 64]` no `ScanContext` por um campo nomeado
`flags: ScanContextFlags`, onde `ScanContextFlags` é um struct de **exatamente
64 bytes** com layout documentado e constantes de conveniência.

### 3.1 Struct ScanContextFlags

```rust
// rust/kernel/src/core/module.rs

/// Flags de contexto para um scan individual.
///
/// Exatamente 64 bytes. Substitui `_reserved: [u8; 64]`.
/// INVARIANTE ABSOLUTO: nunca usar Vec, String, Box, Rc, Arc ou qualquer
/// tipo com heap allocation neste struct. Qualquer PR que violar este
/// invariante será rejeitado sem review.
///
/// Layout (Little-Endian, align 8):
///
/// Bytes  0- 7: lang_bitmask       (u64) — idiomas detectados
/// Bytes  8-15: jurisdiction_bitmask (u64) — jurisdições habilitadas
/// Bytes 16-23: capability_mask    (u64) — features ativas para este scan
/// Bytes 24-39: tenant_key         ([u8; 16]) — BLAKE3 truncado do tenant_id
/// Bytes 40-47: pattern_epoch      (u64) — versão do PatternRegistry no scan
/// Bytes 48-55: lang_scores        ([u16; 4]) — scores top-4 idiomas detectados
/// Bytes 56-63: _reserved          ([u8; 8]) — reservado para v1.8+
#[derive(Debug, Default, Clone, Copy)]
#[repr(C, align(8))]
pub struct ScanContextFlags {
    /// Bitmask de idiomas detectados por whatlang-rs.
    /// Bit 0 = EN, Bit 1 = PT, Bit 2 = ES, Bit 3 = FR, Bit 4 = DE,
    /// Bit 5 = RU, Bit 6 = ZH, Bit 7 = AR.
    /// Bits 8–63 reservados para idiomas futuros.
    /// Valor 0 = idioma indeterminado (input curto ou baixa confiança).
    pub lang_bitmask: u64,

    /// Bitmask de jurisdições habilitadas para validação PII neste scan.
    /// Bit 0 = BR, Bit 1 = US, Bit 2 = EU, Bit 3 = UK.
    /// Bits 4–63 reservados para jurisdições futuras.
    /// Injetado pelo gateway via config de deployment ou header X-Client-Jurisdiction.
    /// Valor 0 = jurisdição não especificada → fallback para deployment default.
    pub jurisdiction_bitmask: u64,

    /// Features habilitadas para este scan/tenant.
    /// Bit 0 = CAP_PII (validadores PII ativos)
    /// Bit 1 = CAP_INJECTION (PromptInjectionDetector ativo)
    /// Bit 2 = CAP_DEOBFUSCATION (DeobfuscatorChain ativo)
    /// Bit 3 = CAP_OUTPUT_GUARD (OutputGuard ativo)
    /// Bits 4–63 reservados para features v1.7+.
    /// Valor u64::MAX = todas as features ativas (single-tenant default).
    pub capability_mask: u64,

    /// BLAKE3 truncado (128-bit) do tenant_id.
    /// O kernel NUNCA recebe o tenant_id em claro — apenas este hash.
    /// Injetado pelo gateway antes de scan_for_evidence().
    /// Valor [0u8; 16] = tenant padrão (deployment single-tenant).
    /// Semântica completa de isolamento implementada em v2.0+.
    pub tenant_key: [u8; 16],

    /// Epoch do PatternRegistry no momento em que o scan iniciou.
    /// Capturado pelo orquestrador de PromptInjection antes de selecionar patterns.
    /// Registrado no TechnicalEvidence._reserved_metadata para auditoria:
    /// permite responder "qual versão de patterns foi usada nesta decisão?".
    /// Valor 0 = Tier 0/1 apenas (sem PatternRegistry dinâmico ativo).
    pub pattern_epoch: u64,

    /// Scores de confiança dos top-4 idiomas detectados.
    /// Cada u16 = confidence * 65535 (fixed-point, sem float no hot path).
    /// Índice corresponde ao bit em lang_bitmask (0 = EN, 1 = PT, etc.).
    /// Permite ao PromptInjectionDetector aplicar threshold de confiança
    /// sem recalcular o score do detector de idioma.
    pub lang_scores: [u16; 4],

    /// Reservado para v1.8+ (Trust Weights entre módulos, SLM context flags).
    /// DEVE permanecer [0u8; 8] até ADR correspondente ser aprovado.
    pub _reserved: [u8; 8],
}

// Garantia de tamanho em compile-time — NUNCA remover este assert.
static_assertions::const_assert_eq!(core::mem::size_of::<ScanContextFlags>(), 64);
```

### 3.2 Constantes de Conveniência

```rust
impl ScanContextFlags {
    // ── Idiomas ──────────────────────────────────────────────────────
    pub const LANG_EN: u64 = 1 << 0;
    pub const LANG_PT: u64 = 1 << 1;
    pub const LANG_ES: u64 = 1 << 2;
    pub const LANG_FR: u64 = 1 << 3;
    pub const LANG_DE: u64 = 1 << 4;
    pub const LANG_RU: u64 = 1 << 5;
    pub const LANG_ZH: u64 = 1 << 6;
    pub const LANG_AR: u64 = 1 << 7;

    // ── Jurisdições ───────────────────────────────────────────────────
    pub const JURISDICTION_BR: u64 = 1 << 0;
    pub const JURISDICTION_US: u64 = 1 << 1;
    pub const JURISDICTION_EU: u64 = 1 << 2;
    pub const JURISDICTION_UK: u64 = 1 << 3;

    // ── Capabilities ──────────────────────────────────────────────────
    pub const CAP_PII: u64        = 1 << 0;
    pub const CAP_INJECTION: u64  = 1 << 1;
    pub const CAP_DEOBFUSC: u64   = 1 << 2;
    pub const CAP_OUTPUT: u64     = 1 << 3;
    /// Todas as features ativas — padrão para deployments single-tenant.
    pub const CAP_ALL: u64        = u64::MAX;

    // ── Helpers ───────────────────────────────────────────────────────

    /// Retorna true se o idioma está confirmado no bitmask.
    #[inline]
    pub fn has_lang(&self, lang_bit: u64) -> bool {
        self.lang_bitmask & lang_bit != 0
    }

    /// Retorna true se nenhum idioma foi detectado.
    /// Implica: aplicar apenas Tier 0 (universais) no PromptInjectionDetector.
    #[inline]
    pub fn is_language_undetermined(&self) -> bool {
        self.lang_bitmask == 0
    }

    /// Retorna true se a jurisdição está habilitada.
    #[inline]
    pub fn has_jurisdiction(&self, j_bit: u64) -> bool {
        self.jurisdiction_bitmask & j_bit != 0
    }

    /// Retorna true se a feature está habilitada para este scan.
    #[inline]
    pub fn has_capability(&self, cap: u64) -> bool {
        self.capability_mask & cap != 0
    }

    /// Retorna true se este é um scan de tenant padrão (single-tenant).
    #[inline]
    pub fn is_default_tenant(&self) -> bool {
        self.tenant_key == [0u8; 16]
    }

    /// Retorna o score de confiança (0.0–1.0) para o idioma no índice dado.
    #[inline]
    pub fn lang_confidence(&self, index: usize) -> f32 {
        if index >= 4 { return 0.0; }
        self.lang_scores[index] as f32 / 65535.0
    }
}
```

### 3.3 ScanContext Atualizado

```rust
// rust/kernel/src/core/module.rs

/// Contexto compartilhado durante um scan.
///
/// Alocado na stack e passado por referência mutável para todos os módulos.
/// Tamanho: size_of::<InputStatistics>() + 64 bytes.
/// INVARIANTE: zero heap em qualquer campo.
#[derive(Debug)]
pub struct ScanContext {
    pub stats: InputStatistics,
    pub flags: ScanContextFlags,
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            stats: InputStatistics::default(),
            flags: ScanContextFlags {
                // Single-tenant default: todas as features ativas
                capability_mask: ScanContextFlags::CAP_ALL,
                // Restante: zero (undetermined lang, no jurisdiction, default tenant)
                ..Default::default()
            },
        }
    }
}

// Garantia de tamanho em compile-time.
static_assertions::const_assert_eq!(
    core::mem::size_of::<ScanContext>(),
    core::mem::size_of::<InputStatistics>() + 64
);
```

### 3.4 Uso nos Módulos Existentes

A assinatura `Module::scan(&str, &mut ScanContext)` não muda. Os módulos
existentes que não usam `_reserved` simplesmente ignoram `flags` — sem
alteração de lógica. O único módulo que muda comportamento é o
`PromptInjectionDetector`, que passa a verificar `ctx.flags.is_language_undetermined()`
para decidir se aplica patterns Tier 1/2 ou apenas Tier 0 (universais).

```rust
// Uso em PromptInjectionDetector após ADR-033
impl Module for PromptInjectionDetector {
    fn scan(&self, input: &str, ctx: &mut ScanContext) -> Vec<Finding> {
        // Sempre: Tier 0 (universais, idioma-agnósticos)
        let mut findings = universal::scan(input);

        // Tier 1/2 apenas se idioma detectado com confiança
        if !ctx.flags.is_language_undetermined() {
            let (epoch, snapshot) = REGISTRY.load_snapshot();
            ctx.flags.pattern_epoch = epoch; // registra versão usada
            findings.extend(snapshot.scan_for_lang(input, ctx.flags.lang_bitmask));
        }

        findings
    }
}
```

### 3.5 Injeção pelo Gateway

O gateway Axum (`rust/gateway/`) injeta os campos relevantes antes de
chamar `scan_for_evidence()`:

```rust
// rust/gateway/src/routes/validate.rs
fn build_scan_context(req: &ValidateRequest, api_key: &ResolvedApiKey) -> ScanContext {
    ScanContext {
        stats: InputStatistics::default(),
        flags: ScanContextFlags {
            // Jurisdição explícita via header, ou fallback do deployment config
            jurisdiction_bitmask: resolve_jurisdiction(
                req.headers.get("X-Client-Jurisdiction"),
                &api_key.default_jurisdictions,
            ),
            // tenant_key: zero até multi-tenant ativo (v2.0+)
            tenant_key: [0u8; 16],
            // Capabilities definidas pela API key do tenant
            capability_mask: api_key.capabilities,
            // lang_bitmask e pattern_epoch preenchidos pelos módulos durante o scan
            ..Default::default()
        },
    }
}
```

### 3.6 Registro do pattern_epoch no TechnicalEvidence

O `pattern_epoch` capturado em `ScanContextFlags` deve ser escrito no
`TechnicalEvidence._reserved_metadata` após o scan, para auditoria:

```rust
// Convenção de offset dentro de _reserved_metadata: [u8; 7072]
// Bytes 0-7: pattern_epoch (u64 LE)
// Bytes 8-23: tenant_key ([u8; 16])
// Bytes 24+: reservados para ADRs futuros
//
// Implementado em gatekeeper.rs::scan_for_evidence() na fase Finalize.
evidence._reserved_metadata[0..8]
    .copy_from_slice(&ctx.flags.pattern_epoch.to_le_bytes());
evidence._reserved_metadata[8..24]
    .copy_from_slice(&ctx.flags.tenant_key);
```

---

## 4. Plano de Migração

### 4.1 Mudanças obrigatórias em v1.6.0

| Arquivo | Mudança |
|:---|:---|
| `rust/kernel/src/core/module.rs` | Adicionar `ScanContextFlags`, substituir `_reserved` por `flags` em `ScanContext` |
| `rust/kernel/src/gatekeeper.rs` | Inicializar `flags` com `capability_mask: CAP_ALL` por default; escrever epoch em `_reserved_metadata` |
| `rust/kernel/src/security/prompt_injection.rs` | Verificar `ctx.flags.is_language_undetermined()` antes de aplicar PT/EN patterns |
| `rust/Cargo.toml` (workspace) | Adicionar `arc_swap = "1.7"` e `whatlang = "0.16"` |
| Todos os testes com `ScanContext { stats, _reserved: [0u8; 64] }` | Migrar para `ScanContext { stats, flags: ScanContextFlags { capability_mask: CAP_ALL, ..Default::default() } }` |

### 4.2 O que NÃO muda

- Assinatura de `Module::scan()` — nenhum módulo muda sua interface
- `TechnicalEvidence` — estrutura de 9600 bytes intacta
- `LedgerEntry` — estrutura de 384 bytes intacta
- `Finding` — estrutura de 144 bytes intacta
- Python governance — sem impacto

### 4.3 Detecção de regressão

O teste abaixo deve ser adicionado em `rust/kernel/tests/` e deve passar
antes do merge:

```rust
#[test]
fn test_scan_context_flags_size() {
    use core::mem::size_of;
    // Garante que ScanContextFlags = 64 bytes exatos
    assert_eq!(size_of::<ScanContextFlags>(), 64);
    // Garante que a migração não inflou o ScanContext
    assert_eq!(
        size_of::<ScanContext>(),
        size_of::<InputStatistics>() + 64
    );
}

#[test]
fn test_scan_context_flags_default_is_single_tenant() {
    let ctx = ScanContext::default();
    assert!(ctx.flags.is_default_tenant());
    assert!(ctx.flags.is_language_undetermined());
    assert!(ctx.flags.has_capability(ScanContextFlags::CAP_PII));
    assert!(ctx.flags.has_capability(ScanContextFlags::CAP_INJECTION));
}

#[test]
fn test_scan_context_flags_bitmask_ops() {
    let mut flags = ScanContextFlags::default();
    flags.lang_bitmask |= ScanContextFlags::LANG_PT;
    flags.lang_bitmask |= ScanContextFlags::LANG_EN;

    assert!(flags.has_lang(ScanContextFlags::LANG_PT));
    assert!(flags.has_lang(ScanContextFlags::LANG_EN));
    assert!(!flags.has_lang(ScanContextFlags::LANG_RU));
    assert!(!flags.is_language_undetermined());
}

#[test]
fn test_existing_pipeline_unaffected() {
    // Garante que o pipeline de 13 módulos existente não regride
    let mut gk = Gatekeeper::new();
    let evidence = gk.scan_for_evidence("CPF: 123.456.789-09", 0x1234);
    assert!(evidence.critical_count > 0);
    assert!(evidence.bias.false_positive_rate > 0.0);
}
```

---

## 5. Fundamento Filosófico

**Rawls (Véu da Ignorância):** O `ScanContext` continua sem saber *quem* é
o usuário — sabe apenas *o que foi detectado* (idioma, jurisdição) e *o que
está autorizado* (capability_mask). A política de o que fazer com esses dados
permanece no Python governance. O Rust executa; o Python julga.

**Jonas (Responsabilidade Proporcional):** O `pattern_epoch` registrado na
evidência responde a uma pergunta de auditoria legítima: "a decisão de BLOCK
foi tomada com os patterns atuais ou com uma versão desatualizada?". Sem esse
campo, BiasDeclaration versionada não tem semântica operacional.

**Levinas (Dever de Cuidado):** O `capability_mask` garante que um tenant
sem cobertura de NHS não receba ALLOW silencioso em dados de saúde britânicos
— ele simplesmente não tem o `JURISDICTION_UK` habilitado, e o dispatcher de
validators passa por cima daquele módulo. Fail-secure por omissão de capability.

**Gilligan (Ética do Cuidado):** O `is_language_undetermined()` é a implementação
do cuidado com textos ambíguos: em vez de aplicar patterns do idioma errado e
gerar FP em massa, o sistema aplica apenas universais e registra a incerteza.
Contexto > regra rígida.

---

## 6. Consequências

### Positivas

- **Zero-heap confirmado:** nenhum campo dinâmico; `ScanContext` permanece
  100% stack-allocated com tamanho verificado em compile-time.
- **L1 cache-friendly:** 64 bytes cabem em uma linha de cache; acesso a
  `flags` durante o scan não gera cache miss.
- **Extensibilidade sem migração de ABI:** os 8 bytes `_reserved` dentro
  de `ScanContextFlags` absorvem futuras extensões de v1.8+ sem quebrar
  módulos existentes.
- **Multi-tenant sem rewrite:** `tenant_key` e `capability_mask` são
  placeholders com semântica zero-custo — o single-tenant usa `[0u8;16]`
  e `CAP_ALL` sem overhead.
- **Auditabilidade real:** `pattern_epoch` no `TechnicalEvidence` fecha o
  loop entre decisão e versão de detectores — requisito para contestabilidade
  com grau forense.

### Negativas e Trade-offs

- **ABI break em v1.6.0:** todos os 13 módulos compilam contra o novo
  `ScanContext` — mas a mudança é mecânica (renomear `_reserved` para `flags`).
  Testes de pipeline end-to-end detectam regressão antes do merge.
- **Limite de 64 idiomas:** `lang_bitmask: u64` suporta até 64 idiomas.
  Para o horizon de v3.0 (OSS Q3 2027), 64 idiomas é mais que suficiente
  (whatlang-rs suporta 69; os 5 não mapeados ficam como undetermined).
  Se necessário, bits 32–63 podem ser alocados para idiomas extras sem
  quebrar a semântica dos bits 0–7 já definidos.
- **`_reserved: [u8; 8]` interno:** 8 bytes sem uso são custo zero mas
  representam uma decisão de arquitetura que "congela" a compatibilidade.
  Documentados como reservados para v1.8+ (Trust Weights, SLM context).

---

## 7. ADRs Dependentes

| ADR | Título | Bloqueia |
|:---|:---|:---|
| ADR-033 | PatternRegistry (Tier 0/1/2 + ArcSwap + Epoch) | Lê `flags.lang_bitmask` e escreve `flags.pattern_epoch` |
| ADR-034 | Language Detection Strategy (whatlang-rs) | Escreve `flags.lang_bitmask` e `flags.lang_scores` |
| ADR-035 | Multi-jurisdiction PII Validators | Lê `flags.jurisdiction_bitmask` e `flags.capability_mask` |
| ADR-036 | Red-team Formal e Bias Guardian | Não depende de ScanContextFlags diretamente, mas mede qualidade dos módulos que dependem |

---

## 8. Critérios de Aceitação

- [ ] `static_assertions::const_assert_eq!(size_of::<ScanContextFlags>(), 64)` passa
- [ ] `static_assertions::const_assert_eq!(size_of::<ScanContext>(), size_of::<InputStatistics>() + 64)` passa
- [ ] Todos os 357 testes existentes passam sem modificação de lógica
- [ ] `gk.scan_for_evidence("CPF: 123.456.789-09", 0x1234)` ainda retorna `critical_count > 0`
- [ ] `ScanContext::default().flags.capability_mask == CAP_ALL`
- [ ] `ScanContext::default().flags.is_language_undetermined() == true`
- [ ] `pattern_epoch` registrado nos bytes 0–7 de `TechnicalEvidence._reserved_metadata`
- [ ] `tenant_key` registrado nos bytes 8–23 de `TechnicalEvidence._reserved_metadata`
- [ ] ADR registrado no `0000-adr-index.md` (Grupo J, entrada 0032)

---

## 9. Referências

- `rust/kernel/src/core/module.rs` — estado atual do `ScanContext`
- `rust/kernel/src/security/prompt_injection.rs` — primeiro consumidor das flags
- `rust/kernel/src/gatekeeper.rs` — ponto de criação e finalização do scan
- `rust/kernel/src/evidence/technical.rs` — `_reserved_metadata: [u8; 7072]`
- `rust/kernel/src/ledger/entry.rs` — `producer_id: [u8; 32]` (candidato a tenant_key no ledger)
- ADR-005 (Evidence Protocol v2.1)
- ADR-009 (Monolito Modular)
- ADR-010 (BiasDeclaration Mandate)
- ADR-028 (Heuristic Prompt Injection Detector — consumidor principal das flags em v1.6.1)
- RFC-001 (Análise Arquitetural Multi-language PII e Red-teaming — fevereiro 2026)
