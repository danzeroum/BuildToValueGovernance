# ADR-0059: Fronteiras Rust/Python — Plano de Controle vs. Plano Analítico

**Status:** Aceito  
**Data:** 2026-05-17  
**Autores:** BuildToValue Engineering  
**Relacionados:** ADR-037 (AppealEngine), ADR-040 (Gateway v2.0), ADR-011 (Policy-as-Code)

---

## Contexto

O Trust OS é implementado em dois runtimes: Rust (Gateway Axum) e Python (Governance FastAPI). À medida que a base de código cresce — especialmente com a adição do proxy HTTP transparente (Fase 2) e a migração de contestabilidade — a fronteira entre os dois planos precisava ser formalizada para evitar dívida técnica e duplicação de lógica.

A ausência de uma fronteira clara gerou dois problemas concretos:

1. `governance_url()` estava duplicada em `appeals.rs` e seria duplicada em `proxy.rs` — qualquer mudança de variável de ambiente exigiria alteração em múltiplos arquivos.
2. Lógica de contestação existe tanto em `rust/gateway/routes/appeals.rs` quanto em `python/governance/contestability_loop.py` — a responsabilidade não estava clara.

---

## Decisão

### Rust = Plano de Controle

O Gateway Axum é responsável exclusivamente por:

- **Roteamento e interceptação HTTP** — validar, sanitizar, guardar, proxear
- **Invariantes criptográficas** — HMAC-SHA256, BLAKE3, tipos afins (EvidenceToken, DeliveryToken, InclusionReceipt)
- **Fail-secure no hot path** — qualquer erro → BLOCK, nunca ALLOW por padrão
- **Latência P99 < 50ms** — zero alocações de heap no hot path, ring buffer, stack allocation
- **Proxy HTTP transparente** — interceptação de tráfego LLM sem modificação do agente
- **Endpoints de ingestão** — `appeals.rs` recebe e roteia para Python; não implementa lógica de appeals

O Rust **não deve** conter:
- Chamadas a LLMs ou modelos de ML
- Lógica de escalação semântica
- Implementação do fluxo de contestação (apenas ingestão)
- Avaliação de políticas complexas além do `Gatekeeper` compilado

### Python = Plano Analítico

O Governance FastAPI é responsável por:

- **Motor de políticas** — avaliação de regras YAML, `safe_expression_evaluator`, `sector_loader`
- **Contestability Loop** — AppealEngine, SLA de 24h, escalação para humanos
- **Chamadas a LLMs** — classifiers, NER, `llama-cpp-python`
- **Trust Score** — cálculo analítico de confiança por sessão
- **Conformidade regulatória** — LGPD, GDPR, EU AI Act, HIPAA
- **explain_decision()** — geração de explicações legíveis (Levinas: transparência radical)

### FFI e Comunicação entre Planos

```
Rust → Python : HTTP (BTV_GOVERNANCE_URL)
                POST /v1/validate, /v1/appeals/submit, /v1/trust/{session}

Python → Rust : PyO3 FFI (para BLAKE3, HMAC — performance crítica)
                buildtovalue_kernel bindings via maturin
```

### DRY Enforcement: `common.rs`

Funções compartilhadas entre rotas Rust residem em `routes/common.rs`:
- `governance_url()` — leitura de `BTV_GOVERNANCE_URL`
- `extract_client_ip()` — parsing de X-Forwarded-For / X-Real-IP
- `ip_risk_to_str()` — serialização de enum IpRisk
- `FALLBACK_POLICY` — política mínima de fallback

Qualquer nova função usada por ≥ 2 handlers pertence a `common.rs`.

---

## Autenticação do Proxy HTTP (Fase 2)

O proxy transparente (`/v1/proxy/*path`) introduz duas camadas de autenticação independentes:

| Camada | Header | Quem valida | Propósito |
|--------|--------|-------------|-----------|
| **BTV Auth** | `x-api-key: <btv-key>` | `ApiKeyLayer` no Rust | Autentica o cliente como usuário autorizado do gateway BTV |
| **LLM Provider Auth** | `Authorization: Bearer sk-...` | Upstream (OpenAI, Anthropic, etc.) | Autentica a requisição no provider do LLM |

O header `Authorization` está na **whitelist de forward** de `proxy.rs` e é encaminhado transparentemente ao upstream. O `x-api-key` é **removido** antes do forward (não está na whitelist) para não vazar credenciais BTV ao provider externo.

**Configuração mínima do cliente:**

```bash
# Chave BTV (autenticação do gateway)
export BTV_API_KEY="sua-chave-btv"

# Chave do LLM provider (encaminhada transparentemente)
export OPENAI_API_KEY="sk-..."

# Apontar cliente para o gateway BTV
export OPENAI_BASE_URL="http://btv-gateway:8080/v1/proxy"
```

O cliente OpenAI inclui `Authorization: Bearer sk-...` automaticamente via SDK — nenhuma modificação de código é necessária.

---

## Consequências

**Positivas:**
- Fronteira clara elimina duplicação (`governance_url()` centralizada)
- Contestation é explicitamente Python-authoritative — `appeals.rs` é ingestão, não lógica
- Proxy documentado sem ambiguidade sobre autenticação
- `common.rs` como ponto único de helpers de rota

**Negativas / Trade-offs:**
- Toda lógica analítica exige uma chamada HTTP ao Python (latência de rede)
- Python Governance é um ponto de falha; Gateway deve degradar graciosamente (fail-secure)

---

## Conformidade com Invariantes do Trust OS

Esta decisão preserva todos os invariantes arquiteturais:
- **Fail-Secure**: proxy retorna 451 em qualquer erro do plano analítico
- **TechnicalEvidence**: gerada pelo kernel Rust antes de qualquer resposta
- **Zero Heap no Hot Path**: `proxy.rs` usa `Bytes` (stack), não `Vec` alocado por request
- **Affine Types**: EvidenceToken e afins continuam no kernel Rust, inalterados
- **HMAC-SHA256**: cada verdict é assinado antes de retornar ao cliente
