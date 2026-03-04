# ADR-045 — Policy Schema v2: Threat Model Required Fields

**Status:** ACCEPTED  
**Data:** 2026-03-04  
**Autor:** AI Squad (Arquiteta Opus)  
**Versão BTV alvo:** v1.6.0  
**Origem:** SPECA paper (ICLR 2026, arquivo 230) — validação empírica em audit contest Ethereum Fusaka

---

## Contexto

O `PolicyEngine` v1.6.0 (`rust/kernel/src/policy/policy.rs`) parseia `PolicySet` com `PolicyConditions` contendo:
```rust
pub struct PolicyConditions {
    pub validators: Vec<String>,
    pub categories: Vec<String>,
    pub min_severity: f32,
    pub min_confidence: f32,
}
```

O schema YAML em `data/policies/default.yaml` define policies com `conditions` (validators, categories, min_severity, min_confidence) e `action`. **Nenhum campo declara trust boundaries, capabilities do atacante, ou exclusões de escopo.**

O paper SPECA demonstra empiricamente que **56.8% dos false positives** em auditorias agênticas derivam de threat model misalignment — premissas implícitas sobre quem pode atacar e em que perímetro. Quando o threat model é formalizado como artefato estruturado (V2), a detecção de vulnerabilidades High-severity sobe de 0/3 para 2/3.

### Problema concreto no BTV

Uma policy `block-credit-card` com `min_severity: 0.7` dispara identicamente para:
- Um agente interno processando dados em rede privada (trust_boundary = `internal`)
- Um agente público recebendo input de usuários anônimos (trust_boundary = `public`)

No contexto interno, o BLOCK é um false positive custoso. No contexto público, é correto. Sem `trust_boundary` explícito, a policy não distingue — violando o princípio SPECA de que **premissas de escopo devem ser artefatos, não suposições implícitas**.

### Relação com ScanContextFlags (ADR-032)

O `ScanContextFlags` já carrega `capability_mask` (u64) e `jurisdiction_bitmask` (u64) por scan. O campo `trust_boundary` na policy cria a **contrapartida declarativa**: a policy declara para qual perímetro foi escrita, e o `PolicyEngine::evaluate()` compara contra o contexto do scan.

---

## Decisão

Adicionar 3 campos **opcionais** ao struct `Policy` e ao schema YAML:

### 1. Rust (`rust/kernel/src/policy/policy.rs`)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: u32,
    pub conditions: PolicyConditions,
    pub action: PolicyAction,

    // ADR-045: Threat Model fields (opcionais, fail-secure defaults)
    #[serde(default)]
    pub threat_model: Option<ThreatModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatModel {
    /// Perímetro para o qual a policy foi escrita.
    /// "public" (default) | "federated" | "internal"
    /// Fail-secure: ausência = "public" (mais restritivo).
    #[serde(default = "ThreatModel::default_trust_boundary")]
    pub trust_boundary: String,

    /// Capabilities assumidas do atacante.
    /// Lista vazia = assume atacante com todas as capabilities.
    #[serde(default)]
    pub assumed_attacker_capabilities: Vec<String>,

    /// O que está FORA do escopo desta policy.
    /// Documentação explícita previne false positives por scope creep.
    #[serde(default)]
    pub scope_exclusions: Vec<String>,
}

impl ThreatModel {
    fn default_trust_boundary() -> String {
        "public".to_string()
    }
}

impl Default for ThreatModel {
    fn default() -> Self {
        Self {
            trust_boundary: Self::default_trust_boundary(),
            assumed_attacker_capabilities: Vec::new(),
            scope_exclusions: Vec::new(),
        }
    }
}
```

### 2. YAML (`data/policies/default.yaml`)
```yaml
# Policies existentes NÃO precisam de alteração (campos opcionais).
# Exemplo de policy com threat_model explícito:

  - id: "block-credit-card"
    name: "Block Credit Card"
    description: "Block credit card numbers in public-facing contexts"
    enabled: true
    priority: 90
    conditions:
      validators: ["credit_card"]
      min_severity: 0.7
      min_confidence: 0.9
    action: BLOCK
    threat_model:
      trust_boundary: "public"
      assumed_attacker_capabilities:
        - "external_user_input"
        - "encoded_payloads"
      scope_exclusions:
        - "internal_batch_processing"
        - "encrypted_transit_logs"
```

### 3. Filtro no `PolicyEngine::evaluate()`
```rust
impl PolicyEngine {
    pub fn evaluate_with_context(
        &mut self,
        validator: &str,
        input: &str,
        severity: f32,
        confidence: f32,
        scan_trust_boundary: &str,  // "public" | "federated" | "internal"
    ) -> PolicyAction {
        // Hard blocks: sempre aplicam (independente de trust_boundary)
        if let Some(term) = self.check_hard_blocks(input) {
            return PolicyAction::Block;
        }

        // Filter policies by trust_boundary compatibility
        // Regra: policy "public" aplica em qualquer contexto.
        //        policy "federated" aplica em federated e public.
        //        policy "internal" aplica APENAS em internal.
        let boundary_level = |b: &str| -> u8 {
            match b {
                "internal" => 0,
                "federated" => 1,
                "public" => 2,
                _ => 2, // fail-secure: desconhecido = public
            }
        };

        let scan_level = boundary_level(scan_trust_boundary);
        // ... filtro durante iteração das policies:
        // policy aplica se policy_level >= scan_level
    }
}
```

A assinatura existente `evaluate(&mut self, validator, input, severity, confidence)` é mantida como wrapper que chama `evaluate_with_context(..., "public")` — **zero breaking changes**.

### 4. Propagação do trust_boundary

O `ScanContextFlags` (ADR-032) já existe com 8 bytes reservados (`_reserved: [u8; 8]`). O byte `_reserved[0]` pode carregar o trust_boundary como enum:
```rust
// Em ScanContextFlags:
// _reserved[0]: 0 = public (default), 1 = federated, 2 = internal
```

O gateway (`rust/gateway/src/routes/decide.rs`) popula este byte a partir do header `X-BTV-Trust-Boundary` ou default `0` (public).

---

## Filosofia

**Rawls (Véu de Ignorância):** O `BlindEvaluator` (ADR-042) continua avaliando com `context={}`. O `threat_model` é propriedade da **policy**, não do avaliado. A mesma policy aplicada de forma cega pode ter trust_boundary diferente — o véu cobre a identidade do agente, não o perímetro em que opera.

**Jonas (Responsabilidade):** Tornar explícito o threat model de cada policy é um ato de responsabilidade: declara publicamente as premissas sob as quais a policy opera, permitindo auditoria e contestação informada.

**Levinas (Proteção):** Fail-secure: policy sem `threat_model` → assume `public` (mais restritivo). O sistema protege o usuário por default, não o relaxa.

**Gilligan (Cuidado):** `scope_exclusions` previne que policies apliquem force-BLOCK em contextos onde o agente opera legitimamente — reduz punição desnecessária, alinhado com mercy.

---

## Consequências

### Positivas
- **-56.8% false positives** (projeção baseada no achado empírico do SPECA para threat model misalignment)
- Retrocompatível: policies existentes sem `threat_model` funcionam identicamente (default = public)
- O `PolicyTester` (ADR-042) pode usar `trust_boundary` para gerar test cases por perímetro
- Habilita multi-tenant real (v2.0+): tenants diferentes podem ter trust_boundaries diferentes

### Negativas
- `Policy` struct ganha `Option<ThreatModel>` — 1 campo opcional com heap allocation (Vec<String>). Aceitável: `PolicyEngine::new()` roda uma vez no startup, não no hot path
- Policies YAML existentes precisam de migração gradual para declarar threat_model (sem urgência — default é seguro)
- `evaluate_with_context()` adiciona 1 comparação por policy na iteração — overhead negligível (< 1μs para 20 policies)

### Neutras
- Hard blocks continuam independentes de trust_boundary (BLOCK absoluto)
- `BiasDeclaration` do `PolicyEngine` não muda — FPR/FNR declarados continuam como worst-case agregado

---

## Implementação

### Arquivos alterados

| Arquivo | Mudança |
|---|---|
| `rust/kernel/src/policy/policy.rs` | Adicionar `ThreatModel` struct + `threat_model: Option<ThreatModel>` em `Policy` + `evaluate_with_context()` |
| `rust/kernel/src/core/module.rs` | Documentar `_reserved[0]` como trust_boundary byte em `ScanContextFlags` |
| `rust/gateway/src/routes/decide.rs` | Ler header `X-BTV-Trust-Boundary`, popular `_reserved[0]`, passar para `evaluate_with_context()` |
| `data/policies/default.yaml` | Adicionar `threat_model` nas policies de maior prioridade (block-*) |
| `rust/kernel/tests/` | Novos testes: policy com trust_boundary internal não dispara em scan public |

### Testes obrigatórios

1. `test_policy_without_threat_model_defaults_public` — retrocompatibilidade
2. `test_policy_internal_skipped_in_public_scan` — filtro funciona
3. `test_policy_public_applies_everywhere` — fail-secure
4. `test_hard_block_ignores_trust_boundary` — hard blocks são absolutos
5. `test_evaluate_with_context_wrapper_compat` — `evaluate()` existente não quebra
6. `test_yaml_with_threat_model_parses` — serde deserializa corretamente
7. `test_yaml_without_threat_model_parses` — retrocompatível

### Estimativa

- **Dev Rust:** ~2h (struct + filtro + testes)
- **Gateway:** ~30min (header parsing + propagação)
- **YAML migration:** ~1h (anotar 5 policies de maior prioridade)
- **Review:** ~1h

---

## Referências

- SPECA (ICLR 2026 Workshop, arquivo 230): 56.8% FP por threat model misalignment
- ADR-032: ScanContextFlags com `_reserved[0..8]` disponível
- ADR-042: BlindEvaluator / PolicyTester (consumidor downstream)
- ADR-011: Policy-as-Code (Legislativo da República Algorítmica)

---

## Checklist de Review (Reviewer Opus)

- [ ] `ThreatModel` struct tem Default impl fail-secure (public)
- [ ] `evaluate()` existente mantém assinatura — zero breaking changes
- [ ] Hard blocks ignoram trust_boundary
- [ ] `_reserved[0]` documentado e não conflita com PatternRegistry epoch (`_reserved_metadata[0..8]`)
- [ ] YAML sem threat_model continua parseando
- [ ] Nenhum `.unwrap()` em lib code
- [ ] Nenhum `.clone()` sem justificativa
- [ ] Funções ≤ 50 linhas
- [ ] Arquivo não ultrapassa 200 linhas (ThreatModel pode ser em sub-módulo se necessário)
- [ ] BiasDeclaration do PolicyEngine documentada no ADR

### O Que Está Bem Feito (obrigatório por AI Squad Workflow)
*(preenchido pelo Reviewer após implementação)*