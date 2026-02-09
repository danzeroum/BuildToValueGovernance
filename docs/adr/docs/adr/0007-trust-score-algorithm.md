
# ADR-007: Trust Score Algorithm

**Status**: ✅ APROVADO  
**Data**: 22 de janeiro de 2026  
**Autores**: Daniel Camargo, Data Science Team  
**Revisores**: Ethical Committee, Security Architect, DPO  
**Crate v3.0**: `btv-governance` (Python TrustScoreCalculator), `btv-notary` (JWT claims com trust_score)

## Contexto

BTV v1.0 tratava todos os usuários igualmente. Resultado: 22% false positive rate, 18% appeal rate, satisfação 3.2/5.

## Decisão

Trust score multi-fatorial com 5 componentes:

```
trust = w₁·base + w₂·history + w₃·appeals + w₄·(1-decay) + w₅·consistency

Pesos:
  w₁ (base/role)    = 0.20
  w₂ (history)      = 0.30
  w₃ (appeals)      = 0.20
  w₄ (decay)        = 0.15
  w₅ (consistency)  = 0.15
```

| Componente | Lógica | Range |
|-----------|--------|-------|
| **Base** | Score por role: admin=0.9, developer=0.7, user=0.5, guest=0.3, anonymous=0.2 | 0.0–1.0 |
| **History** | Ratio allowed/total requests. Penaliza se ratio < 0.5 | 0.0–1.0 |
| **Appeals** | Bonus: `success_rate × 0.3`. Penaliza: `fail_rate × 0.15`. Net = bonus - penalty | -0.15–0.30 |
| **Decay** | Half-life 30 dias. Inatividade reduz trust gradualmente | 0.0–1.0 |
| **Consistency** | Penaliza spikes de requests (anti-spam). Mede desvio padrão temporal | 0.0–1.0 |

Score final clamped a [0.0, 1.0].

## Fundamento Filosófico

- **Gilligan**: Feedback loop — appeals bem-sucedidos (falsos positivos do sistema) aumentam trust. O sistema reconhece seus erros.
- **Rawls**: Fórmula determinística — mesmo histórico produz mesmo score. Sem favorecimento arbitrário.
- **Levinas**: Privacy-preserving — score não contém PII. Apenas métricas agregadas.
- **Jonas**: Explicabilidade — `explain_score()` retorna breakdown completo de cada componente.

## Anti-Gaming

- Spam detection: > 10 requests/segundo → consistency score penalizado
- Appeal flood: > 5 appeals rejeitados consecutivos → flag para review manual
- Trust never exceeds 0.95 (humility ceiling — sistema admite incerteza)

## Integração v3.0

O trust score é calculado em Python (`btv-governance`) e embarcado no JWT emitido pelo `btv-notary`:

```rust
// crates/btv-notary/src/lib.rs
pub struct Claims {
    pub sub: String,          // user ID
    pub trust_score: f64,     // 0.0–1.0 (calculado por Python)
    pub session_id: String,
    pub exp: usize,
}
```

---
