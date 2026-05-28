# ADR-0074: Model Integrity Verification — Structural Abliteration Detection

| Campo | Valor |
|-------|-------|
| **ADR ID** | 0074 |
| **Status** | Aceito |
| **Criado** | 2026-03-08 |
| **Autores** | AI Squad (Arquiteta) |
| **Renomeado de** | ADR-051.md (nomenclatura irregular) |
| **Relacionados** | ADR-027, ADR-033, ADR-036, ADR-049, 0051-model-integrity-abliteration-detection.md |

> **Nota:** Este ADR é a versão com ID sequencial canônico do documento anteriormente catalogado como `ADR-051.md`. O arquivo `0051-model-integrity-abliteration-detection.md` permanece como referência histórica. Em caso de conflito, este documento (0074) prevalece por ter nomenclatura conforme o padrão `NNNN-slug.md`.

---

## Contexto

Modelos de linguagem locais (SLMs) podem sofrer adulteração pós-deployment via três vetores primários:

1. **Abliteration de recusa** — remoção cirúrgica de "refusal directions" no espaço de ativação residual.
2. **LoRA rank-1 injection** — adaptadores de baixo rank inseridos para sobrescrever comportamento de alinhamento.
3. **Weight tampering direto** — modificação de pesos em camadas específicas, detectável apenas por hash criptográfico dos tensores.

O invariante ético central exige que qualquer agente de IA que processe decisões auditáveis pelo BuildToValue seja verificável em integridade estrutural — não apenas por nome ou comportamento observado.

---

## Decisão

Implementar **Model Integrity Verification** em duas camadas complementares.

### Camada 1 — Rust Kernel (hot path, meta: <5ms)

**Artefato:** `rust/kernel/src/security/model_integrity.rs`

```rust
pub struct ModelIntegrityVerifier {
    expected_hash: [u8; 32],   // BLAKE3, 256-bit
    manifest_path: &'static str,
}

impl ModelIntegrityVerifier {
    pub fn verify(&self) -> Result<(), IntegrityViolation>;
}
```

- **BLAKE3 hash de manifesto**: verificação do `.manifest.json` assinado no deploy.
- **Fail-secure**: manifesto ausente ou hash divergente → veredicto `BLOCK` + `MODEL_INTEGRITY_VIOLATION`.
- **Zero heap no hot path**: verificação contra array estático `[u8; 32]`.
- **Ring buffer**: últimos 256 eventos de violação em memória para observabilidade (ADR-041).
- **HMAC-SHA256** no finding gerado para contestabilidade (ADR-017).

### Camada 2 — Python Governance (cold path)

**Artefato:** `python/buildtovalue/governance/abliteration_detector.py`

```python
@dataclass
class AbliterationResult:
    model_id: str
    is_abliterated: bool
    confidence: float
    refusal_rate: float
    false_refusal_rate: float
    probe_count: int
    explanation: str       # obrigatório, nunca vazio
    contestable: bool      # sempre True
    appeal_deadline: int   # timestamp + 24h
    probe_ids_failed: list[str]
```

- **Refusal probe calibrada**: 5 prompts HARMFUL + 3 BENIGN, threshold 80%.
- **LoRA rank detection**: sinaliza adaptador com `rank ≤ 4` não presente no manifesto.
- **`explain_decision` obrigatório** (ADR-038 §4.2, Levinas).
- **BiasDeclaration**: `false_negative_rate: 0.35` para vetor LoRA merged documentado.
- **Fail-secure**: exception → `is_abliterated=True`, `confidence=1.0` (Jonas).

### Camada 0 — Blacklist Operacional (implementada)

Já em produção via `ops/ci_gate_g0.py`:
```
HereticAI/*, abliterated-*, uncensored-*, jailbreak-*, no-refusal-*, bypass-*, unrestricted-*
```

---

## Plano de Implementação

| Fase | Status | Artefato | Release |
|---|---|---|---|
| 0 — Blacklist + UNKNOWN→BLOCK | ✅ Concluído | `ops/ci_gate_g0.py` | v1.5.x |
| 1 — BLAKE3 manifest verification | 🔲 Pendente | `rust/kernel/src/security/model_integrity.rs` | v1.6.0 |
| 2 — Abliteration detector Python | ✅ Concluído | `python/buildtovalue/governance/abliteration_detector.py` | v1.7.0 |
| 3 — Contestability flow | 🔲 Pendente | Extensão ADR-017 + ADR-047 | v1.7.0 |

---

## Fundamento Filosófico

Hans Jonas: a responsabilidade pelo agente que age em nome do humano implica verificabilidade do agente em si. Um modelo abliterado que passa por um auditor de ética configura violação de segunda ordem: o instrumento de fiscalização torna-se o vetor de risco. A República Algorítmica não pode ter juízes curvados.
