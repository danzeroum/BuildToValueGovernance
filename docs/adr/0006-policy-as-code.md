
# ADR-006: Policy-as-Code Governance

**Status**: ✅ APROVADO  
**Data**: 20 de janeiro de 2026  
**Autores**: Daniel Camargo, Ethical Committee  
**Revisores**: Security Architect, DPO  
**Crate v3.0**: `btv-common` (config loader), `btv-governance` (ProfileManager)

## Contexto

Policies hardcoded em Rust exigiam recompilação para qualquer mudança. Sem versionamento, sem transparência, sem governança formal.

## Decisão

YAML versionado em Git com herança hierárquica:

```yaml
# profiles/base.yaml (raiz — ninguém herda dele sem ser explícito)
id: base
version: 1.0.0
signature: "hmac-sha256:a7f3c8e9..."
rules:
  - id: BLOCK_CREDIT_CARD_GLOBAL
    action: BLOCK
    priority: 300

  - id: BLOCK_CPF_IN_GENERAL
    action: BLOCK
    priority: 200
```

```yaml
# profiles/medical-agent.yaml (herda de base, override contextual)
id: medical-agent
parent_id: base
version: 2.1.0
rules:
  - id: BLOCK_CPF_IN_GENERAL    # OVERRIDE
    action: EDUCATE             # Abranda de BLOCK → EDUCATE
    domain: medical
    min_trust_score: 0.3
```

## Fundamento Filosófico

- **Rawls**: Blind Policy Testing — testa sem saber se é autor, alvo ou auditor. ≥95% pass rate obrigatório.
- **Gilligan**: Contexto > Regra — CPF é permitido em contexto médico se trust ≥ 0.3.
- **Levinas**: Educate > Block — mensagens contextuais antes de punição.
- **Jonas**: Versionamento Git + assinatura HMAC = responsabilidade rastreável.

## CI/CD Gate (Ethical CI/CD)

Toda mudança de policy passa por:

1. Validação YAML syntax
2. Blind Policy Testing (95%+ pass rate)
3. BiasDeclaration check (calibração < 90 dias)
4. Adversarial testing
5. **Ethical Committee review (2/3 quorum obrigatório)**

Sem aprovação → PR bloqueado.

## Métricas

- Total policies: 5 (base, general, medical, research, legal)
- Total rules: 47 (38% BLOCK, 32% EDUCATE, 21% LOG, 6% REDACT, 2% ALLOW)
- Blind test pass rate: 97.2%
- Adversarial test pass rate: 99.1%
- Ethical Committee approval rate: 83% (2/12 PRs rejeitados)

---
