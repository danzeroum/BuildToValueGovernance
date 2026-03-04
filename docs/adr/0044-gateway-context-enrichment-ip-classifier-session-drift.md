# ADR-044: Gateway Context Enrichment — IP Classifier + Session Drift

**Status:** 🚧 Em Implementação
**Data:** 26 de fevereiro de 2026
**Autores:** IA Arquiteta (Claude Sonnet 4.6)
**Versão alvo:** v1.9.2
**Grupo:** A — Fundamentos Arquiteturais
**Implementa:** ADR-014 (IP & Session Drift — estava Planejado desde v1.7)
**Depende de:** ADR-043 (Unified Verdict Identity), ADR-032 (ScanContextFlags)

**Impacto:**
```
rust/gateway/src/routes/validate.rs  — MODIFICAR: chamar IpClassifier + SessionTracker
rust/gateway/src/routes/decide.rs    — MODIFICAR: idem
rust/gateway/src/state.rs            — MODIFICAR: + IpClassifier + SessionTracker no AppState
```

---

## 1. Contexto

### 1.1 O Gap

O `IpClassifier` e o `SessionTracker` (drift) existem e funcionam no kernel desde v1.7 (ADR-014), com testes passando. O gateway nunca os chama. Consequência: o Python recebe sempre `ip_risk="Low"` e `drift_level="None"` independente da origem real da requisição.

### 1.2 Impacto Concreto

| Cenário | Comportamento atual | Comportamento correto |
|---|---|---|
| IP Tor (`185.220.100.x`) | Python decide como risco baixo | Jonas stage escala para BLOCK |
| IP VPN (`146.70.x.x`) | Python ignora | Python recebe `ip_risk="High"` |
| Sessão com drift alto (exfiltração progressiva) | Python não detecta padrão | Python recebe `drift_level="HIGH"` |
| IP desconhecido | Python recebe "Low" (otimista) | Python recebe "Medium" (fail-secure) |

### 1.3 Por que agora

ADR-043 estabeleceu o contrato de comunicação Rust→Python. Os campos `ip_risk`, `ip_jurisdiction` e `drift_level` já existem em `DecideRequest` (Python) — só precisam ser preenchidos pelo Rust.

---

## 2. Decisão

### 2.1 Onde vive o estado

`IpClassifier` é stateless — instanciado uma vez em `AppState`. `SessionTracker` é stateful (mantém histórico por sessão) — também em `AppState`, protegido por `Mutex`.
```rust
// rust/gateway/src/state.rs — adicionar:
pub struct AppState {
    // ... campos existentes ...
    pub ip_classifier: IpClassifier,               // stateless, sem Mutex
    pub session_tracker: Mutex<SessionTracker>,    // stateful
}
```

### 2.2 Pipeline no handler
```
Rust handler inicia
  │
  ├── verdict_id = VRD-{ULID}                    (ADR-043)
  │
  ├── ip_class = ip_classifier.classify(client_ip)
  │     → ip_risk: "Low"|"Medium"|"High"|"Critical"
  │     → ip_jurisdiction: "BR"|"US"|"EU"|"UK"|"XX"
  │
  ├── scan Executivo (kernel) → evidence
  │
  ├── drift = session_tracker.track(session_id, &evidence)
  │     → drift_level: "None"|"LOW"|"MEDIUM"|"HIGH"
  │
  ├── GovernanceRequest {
  │     ...,
  │     ip_risk,
  │     ip_jurisdiction,
  │     drift_level,
  │   }
  │
  └── Python decide com contexto real
```

### 2.3 Extração do IP do cliente

O IP vem do header `X-Forwarded-For` (primeiro valor) ou do header `X-Real-IP`. Fallback: `"0.0.0.0"` → classificado como `Unknown` → `ip_risk="Medium"` (fail-secure).
```rust
fn extract_client_ip(headers: &HeaderMap) -> String {
    headers.get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers.get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "0.0.0.0".to_string())
}
```

### 2.4 Mapeamento IpRisk → String
```rust
fn ip_risk_to_str(risk: IpRisk) -> &'static str {
    match risk {
        IpRisk::Low      => "Low",
        IpRisk::Medium   => "Medium",
        IpRisk::High     => "High",
        IpRisk::Critical => "Critical",
    }
}
```

### 2.5 Mapeamento DriftLevel → String
```rust
fn drift_level_to_str(level: DriftLevel) -> &'static str {
    match level {
        DriftLevel::Normal  => "None",
        DriftLevel::Low     => "LOW",
        DriftLevel::Medium  => "MEDIUM",
        DriftLevel::High    => "HIGH",
    }
}
```

### 2.6 Campos adicionados ao `GovernanceRequest`
```rust
struct GovernanceRequest {
    // ... campos existentes (ADR-043) ...
    ip_risk: String,          // "Low"|"Medium"|"High"|"Critical"
    ip_jurisdiction: String,  // "BR"|"US"|"EU"|"UK"|"XX"
    drift_level: String,      // "None"|"LOW"|"MEDIUM"|"HIGH"
}
```

---

## 3. Invariantes

1. **Fail-secure IP**: IP não parseável → `ip_risk="Medium"` (nunca "Low" por omissão).
2. **Fail-secure drift**: `SessionTracker` lock falha → `drift_level="None"` (não bloqueia pipeline).
3. **Latência**: `IpClassifier.classify()` é O(n) CIDR scan local, sem I/O — < 1ms garantido.
4. **Privacidade**: IP nunca gravado no ledger. Apenas `ip_risk` e `ip_jurisdiction` são passados ao Python.
5. **Sem mudança no Python**: `DecideRequest` já tem os campos — nenhuma alteração necessária no lado Python.

---

## 4. Fundamento Filosófico

**Jonas (1984):** Responsabilidade proporcional ao poder. Um sistema que ignora que a requisição vem de um nó Tor e trata como residencial está falhando com o princípio de precaução. O conhecimento disponível (IpClassifier já implementado) deve ser usado.

**Levinas:** Proteger o usuário legítimo exige distingui-lo do atacante. Drift alto pode indicar sessão comprometida — identificar isso é dever de cuidado, não punição.

**Rawls:** Blind testing de equidade exige que o mesmo input de um IP residencial e de um nó Tor produza decisões diferentes e justificáveis — não por preconceito, mas por contexto verificável.

---

## 5. O que NÃO está no escopo deste ADR

- Listas dinâmicas de Tor/VPN (atualização em runtime) — v2.0+
- IPv6 — débito técnico existente no `IpClassifier`
- Rate limiting por IP risk — ADR separado
- Persistência do `SessionTracker` entre restarts — v2.0+

---

## 6. Referências

- ADR-014 (IP & Session Drift — spec original, agora implementada)
- ADR-043 (Unified Verdict Identity — contrato GovernanceRequest)
- `rust/kernel/src/network/ip_classifier.rs`
- `rust/kernel/src/session_guard/tracker.rs`
- `rust/kernel/tests/contextual_decisions.rs` — testes de integração existentes