# ADR-0073: Grant Decision Adapter

| Campo | Valor |
|-------|-------|
| **ADR ID** | 0073 |
| **Status** | Aceito |
| **Criado** | 2025-11-01 |
| **Autores** | BTV Governance Team |
| **Decisores** | Grant Adapter Working Group |
| **Supersede** | — |
| **Renomeado de** | ADR-043-grant-decision-adapter.md (nomenclatura irregular) |
| **Relacionados** | ADR-001 (Adapter Pattern), ADR-007 (Policy-as-Code), ADR-015 (Fail-Secure Defaults), ADR-022 (Mercy Algorithm), ADR-031 (Bias Declaration Integrity) |

---

## Contexto

O projeto BuildToValueGovernance necessita de um adaptador dedicado para governança de propostas de financiamento (grants). Propostas de grant representam um caso de uso de alto risco — envolvem desembolsos financeiros reais (USD 1K–10M+), múltiplas comunidades linguísticas (en-US, pt-BR, es, sw) e requisitos de conformidade regulatória em múltiplas jurisdições (OFAC, EU AML, BCB, etc.).

Adaptadores existentes (LangChain, CrewAI, AutoGen, LlamaIndex) padrão com `use_decide=False` (~3ms Rust-only). Grants exigem a troca oposta: o pipeline ético completo (~30ms) é justificado porque o risco financeiro demanda governança mais profunda.

### Declaração do Problema

1. Nenhum adaptador existente trata os requisitos únicos do domínio de grants.
2. O padrão de 4 elementos do adaptador precisa de extensão para campos específicos de grant.
3. A derivação do Session ID deve evitar colisão com as operações BLAKE3 do kernel Rust.
4. A serialização de entrada deve preservar o idioma original do texto da proposta.

---

## Decisão 1: `use_decide=True` como Padrão

**Status:** Aceito

**Decisão:** GrantGuard usa `use_decide=True` como padrão — pipeline completo via `/v1/decide` (~30ms: Rawls → Levinas → Jonas → Gilligan).

**Justificativa:**
- Propostas de grant envolvem risco financeiro real. Um falso negativo tem consequências monetárias diretas.
- O pipeline completo fornece explicabilidade necessária para fluxos de apelação.
- Latência de 30ms é negligível comparada à revisão humana (horas a dias).
- O estágio de misericórdia de Gilligan (BLOCK → EDUCATE) é crítico para candidatos de primeira vez.

**Consequências:** +27ms de latência, custo de API maior, trilha de auditoria mais profunda.

**Mitigação:** `GrantGuardConfig` permite `use_decide=False` para pré-triagem em lote.

---

## Decisão 2: HMAC-SHA256 para Derivação de Session ID

**Status:** Aceito

**Decisão:**
```python
def to_session_id(self, secret: bytes = b"btv-grant-salt") -> str:
    return hmac.new(secret, self.applicant_id.encode("utf-8"), hashlib.sha256).hexdigest()
```

**Justificativa:**
- Evita colisão BLAKE3 com a camada BTL do kernel Rust.
- HMAC-SHA256 resiste a ataques de extensão de comprimento que SHA-256 simples não resiste.
- Determinístico: mesmo candidato → mesma sessão, permitindo rastreamento de histórico de confiança.
- Rotação de salt por ambiente (dev/staging/prod) é obrigatória.

**Rejeitado:** `hashlib.blake3` (kernel Rust detém o BLAKE3), `uuid.uuid4()` puro (não determinístico).

---

## Decisão 3: Serialização JSON Minificada para `to_btv_input()`

**Status:** Aceito

**Decisão:** JSON compacto: `{"title":"...","description":"...","budget_usd":50000}`

**Justificativa:** Prefixos em inglês ("Title:", "Description:") poluem o detector de idioma do BTV. Uma proposta com título "Monitoramento de Qualidade da Água" prefixada em inglês poderia ser identificada erroneamente como mista/inglês, aplicando perfis de governança incorretos.

---

## Decisão 4: `hard_blocked` Verificado Antes de `action`

**Status:** Aceito

**Decisão:** Ordem de avaliação em `evaluate()`:
```
1. _validate(proposal)        → pré-voo estrutural
2. _sanitize(proposal)        → normalização de entrada
3. client.decide(...)         → chamada ao kernel BTV
4. if verdict.hard_blocked:   → PORTÃO FAIL-SECURE (prioridade 1)
5. if action in block_on:     → PORTÃO DE POLÍTICA (prioridade 2)
6. return verdict             → ALLOW/EDUCATE/INSPECT/LOG
```

**Justificativa:** `hard_blocked=True` é definido pelo gatekeeper Rust para correspondências de lista de negação absoluta (sanções OFAC, golpes conhecidos). Este é um portão absoluto — a misericórdia de Gilligan não pode sobrescrevê-lo.

---

## Decisão 5: `GrantBlockedError` Rico

**Status:** Aceito

**Decisão:** `GrantBlockedError` inclui: `contestable`, `appeal_deadline_hours`, `composite_risk`, `trust_score`, `mercy_applied`, `raw_verdict`.

**Justificativa (princípio SLA Levinas):** Toda entidade bloqueada deve conhecer seus direitos. Informações de contestabilidade devem ser acessíveis sem re-consultar o kernel.

---

## Decisão 6: Bias Nulo para Grupos Não Calibrados (Swahili)

**Status:** Aceito

**Decisão:** `BiasDeclaration` para Swahili DEVE ter `fpr=None` e `fnr=None`. `ValueError` gerado caso contrário.

**Justificativa (princípio de integridade Jonas, ADR-031):** Fabricar dados de calibração de viés viola a responsabilidade com a verdade. `sample_size=0` comunica status honesto de não calibrado.

---

## Decisão 7: Posicionamento da Política YAML em `data/policies/sectors/`

**Status:** Aceito

**Decisão:** Política em `data/policies/sectors/grant-eligibility-v1.yaml`.

---

## Critérios de Validação

1. Todos os 4 elementos do adaptador implementados (exception, guard, validate, sanitize).
2. `hard_blocked=True` gera `GrantBlockedError(contestable=False)`.
3. `action=BLOCK` gera `GrantBlockedError(contestable=True)`.
4. `mercy_applied=True` com `action=EDUCATE` NÃO gera exceção.
5. Propostas pt-BR serializadas como JSON identificadas corretamente como português.
6. `BiasDeclaration(group=SW, fpr=0.05)` gera `ValueError`.
7. Mesmo `applicant_id` produz mesmo `session_id` em chamadas diferentes.
8. 800 testes adversariais passando em todos os 4 grupos linguísticos.
