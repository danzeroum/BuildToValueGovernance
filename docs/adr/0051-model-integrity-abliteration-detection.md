# ADR-051: Model Integrity Verification — Structural Abliteration Detection

**Status:** Aceito  
**Data:** 2026-03-08  
**Autores:** AI Squad (Arquiteta)  
**Supera:** —  
**Relacionados:** ADR-027 (Local SLM Strategy), ADR-033 (Pattern Registry Tiers), ADR-036 (RedTeam Bias Guardian), ADR-049 (CoT Opacity Controlled)

---

## Contexto

Modelos de linguagem locais (SLMs) podem sofrer adulteração pós-deployment via três vetores primários:

1. **Abliteration de recusa** — remoção cirúrgica de "refusal directions" no espaço de ativação residual, tornando o modelo incapaz de recusar instruções prejudiciais sem alterar outputs normais detectáveis por testes funcionais.
2. **LoRA rank-1 injection** — adaptadores de baixo rank inseridos para sobrescrever comportamento de alinhamento com custo computacional mínimo e footprint reduzido.
3. **Weight tampering direto** — modificação de pesos em camadas específicas (MLP gate, attention QKV), detectável apenas por hash criptográfico dos tensores.

O BuildToValue v2.x detectava adulteração apenas via blacklist de nomes de modelos (`HereticAI`, variantes) e bloqueio de veredicto `UNKNOWN→BLOCK`. Isso é insuficiente: um modelo renomeado ou parcialmente adulterado passa pelo filtro.

O invariante ético central exige que qualquer agente de IA que processe decisões auditáveis pelo BuildToValue seja verificável em integridade estrutural — não apenas por nome ou comportamento observado. ADR-036 princípio 3 estabelece: "evidência forense, não confiança implícita".

---

## Decisão

Implementar **Model Integrity Verification** em duas camadas complementares.

### Camada 1 — Rust Kernel (hot path, meta: <5ms)

**Artefato:** `rust/kernel/src/security/model_integrity.rs`

- **BLAKE3 hash de manifesto**: verificação do arquivo `.manifest.json` contendo hashes SHA-256 dos tensores, pré-computados e assinados pelo operador no momento do deploy.
- **Fail-secure**: manifesto ausente ou hash divergente → veredicto `BLOCK` + finding `MODEL_INTEGRITY_VIOLATION` com `severity: Critical`. Nunca `ALLOW` em caso de erro de leitura.
- **Zero heap no hot path**: hash verificado contra array estático `[u8; 32]`; nenhuma alocação dinâmica no caminho de verificação.
- **Ring buffer de alertas**: últimos 256 eventos de violação em memória para agregação de observabilidade (ADR-041).
- **HMAC-SHA256** no finding gerado, garantindo contestabilidade (ADR-017).

Interface canônica:

```rust
pub struct ModelIntegrityVerifier {
    expected_hash: [u8; 32],   // BLAKE3, 256-bit
    manifest_path: &'static str,
}

impl ModelIntegrityVerifier {
    pub fn verify(&self) -> Result<(), IntegrityViolation>;
}
```

### Camada 2 — Python Governance (cold path, análise estrutural)

**Artefato:** `python/buildtovalue/intelligence/abliteration_detector.py`

- **Refusal direction probe**: executa N=5 prompts canônicos de recusa (harm, PII exfiltration, instrução prejudicial) e verifica se o modelo recusa com embedding de recusa esperado (cosine similarity ≥ 0.85 contra vetor de referência por família de modelo).
- **LoRA rank detection**: inspeciona `state_dict` e sinaliza qualquer adaptador com `rank ≤ 4` não presente no manifesto original assinado.
- **`explain_decision` obrigatório**: todo `AbliterationReport` deve incluir raciocínio auditável (ADR-038 §4.2).
- **BiasDeclaration**: limitação conhecida — LoRA merged em pesos base não é detectável por inspeção de `state_dict`; documentado com `false_negative_rate` explícito.
- **SLA**: executado apenas no ciclo de auditoria periódica, não em cada request. Latência tolerada até 2s.

```python
@dataclass
class AbliterationReport:
    risk_score: float          # 0.0–1.0
    evidence: list[str]
    explain_decision: str      # obrigatório, não pode ser vazio
    bias_declaration: BiasDeclaration
```

### Camada 0 — Blacklist Operacional (implementada)

Já em produção via `ops/ci_gate_g0.py` (commit `61a81b9`, 2026-03-08):

```
HereticAI/*, abliterated-*, uncensored-*, jailbreak-*,
no-refusal-*, bypass-*, unrestricted-*
```

Bloqueia modelos conhecidos por nome antes do carregamento. Defesa-em-profundidade, não substitui Camadas 1 e 2.

---

## Alternativas Consideradas

| Alternativa | Descartada por |
|---|---|
| Confiança em nome/tag do modelo | Trivialmente contornável por renomeação |
| Benchmark comportamental completo (HarmBench, MMLU) | Latência >30s; inviável para deploy contínuo |
| TPM/Secure Enclave para attestation de pesos | Dependência de hardware específico; viola Framework Neutrality (ADR-001) |
| Apenas blacklist | Não detecta adulteração de modelos fora da lista |
| Análise estática de pesos (PCA sobre camadas) | Custo O(n²) por camada; sem baseline confiável para comparação |

---

## Consequências

**Positivas:**
- Detecta adulteração pós-deploy independentemente de nome ou comportamento observado.
- `explain_decision` no `AbliterationReport` satisfaz Transparency Radical (princípio core v3.0).
- Contestável: operador pode apresentar manifesto alternativo assinado dentro do SLA 24h (ADR-017).
- Compõe com ADR-036 (RedTeam) sem sobreposição: RedTeam valida comportamento, este ADR valida estrutura.

**Negativas / Riscos:**
- Manifesto deve ser gerado e assinado pelo operador no deploy — adiciona fricção operacional documentada.
- Refusal direction probe requer vetor de referência mantido por família de modelo (Llama, Mistral, Phi) — manutenção contínua pela equipe de Intelligence.
- LoRA merged em pesos base não é detectável por inspeção de `state_dict` — limitação registrada em `BiasDeclaration` com `false_negative_rate: 0.35` para este vetor específico.
- Camada 1 requer que `manifest_path` seja configurável por política (ADR-042) sem hardcode.

---

## Plano de Implementação

| Fase | Status | Artefato | Release |
|---|---|---|---|
| 0 — Blacklist + UNKNOWN→BLOCK | ✅ Concluído 2026-03-08 | `ops/ci_gate_g0.py`, `gatekeeper.rs` | v1.5.x |
| 1 — BLAKE3 manifest verification | 🔲 Pendente | `rust/kernel/src/security/model_integrity.rs` | v1.6.0 |
| 2 — Abliteration detector Python | 🔲 Pendente | `python/buildtovalue/intelligence/abliteration_detector.py` | v1.7.0 |
| 3 — Contestability flow (manifesto alternativo) | 🔲 Pendente | Extensão ADR-017 + ADR-047 | v1.7.0 |

---

## Fundamento Filosófico

Hans Jonas: a responsabilidade pelo agente que age em nome do humano implica verificabilidade do agente em si — não apenas de seus outputs. Um modelo abliterado que passa por um auditor de ética configura violação de segunda ordem: o instrumento de fiscalização torna-se o vetor de risco. A República Algorítmica não pode ter juízes curvados.
ADREOF

