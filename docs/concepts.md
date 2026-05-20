[BuildToValue](../README.md) › [Documentação](./README.md) › **Conceitos**

![Engenheiro](https://img.shields.io/badge/Trilha-Engenheiro-1f6feb) ![DPO / CISO](https://img.shields.io/badge/Trilha-DPO%20%2F%20CISO-8957e5)

<!-- audience: both -->

---

# Conceitos — A República Algorítmica

O BTV usa metáforas políticas para organizar sua arquitetura. Não é academicismo — é uma forma de deixar claro *quem decide o quê* e *por quê*.

---

## A Separação de Poderes

O BTV tem três "poderes", como numa república:

```
Input do usuário
      │
      ▼
┌─────────────────────────────┐
│  EXECUTIVO (Rust Kernel)    │  < 5ms
│  Aplica regras objetivas    │
│  PII, injections, políticas │
└─────────────┬───────────────┘
              │ encaminha para revisão
              ▼
┌─────────────────────────────┐
│  JUDICIÁRIO (Python)        │  20-80ms
│  Razão ética e misericórdia │
│  Rawls→Levinas→Jonas→Gill.  │
└─────────────┬───────────────┘
              │ verdict assinado
              ▼
┌─────────────────────────────┐
│  LEGISLATIVO (Contestab.)   │
│  Usuário pode recorrer      │
│  LGPD Art. 20 / EU AI Act   │
└─────────────────────────────┘
```

---

## O Pipeline Ético (Judiciário)

Quando o Kernel Rust encontra evidências, o Python aplica quatro filtros filosóficos em sequência:

### 1. Rawls — Fairness (véu da ignorância)

> *"Seria justo aplicar esta regra se não soubéssemos quem é o usuário?"*

Avalia a política de forma cega — sem levar em conta histórico, identidade, ou contexto favorável. Se a regra diz "bloquear CPF", bloqueia.

**Resultado:** ação inicial objetiva (`BLOCK`, `REDACT`, etc.)

---

### 2. Levinas — Dever de cuidado

> *"O outro nos olha. Temos dever de cuidado."*

Considera o impacto da decisão no usuário como pessoa. Um BLOCK brusco sem explicação viola Levinas. O sistema deve *explicar* o que aconteceu e *por quê*.

**Resultado:** rationale articulado, obrigatoriedade de motivo em appeals (mínimo 20 chars)

---

### 3. Jonas — Responsabilidade de longo prazo

> *"Age de forma que os efeitos da tua ação sejam compatíveis com a continuidade da vida humana."*

Avalia risco sistêmico. Um erro isolado é diferente de um padrão que, se generalizado, causa dano em escala. Jonas aumenta o peso de ações que afetam populações vulneráveis.

**Resultado:** ajuste de `composite_risk` por jurisdição e perfil setorial

---

### 4. Gilligan — Ética do cuidado (misericórdia)

> *"O contexto importa. Relações importam. Rigidez sem misericórdia é crueldade."*

O último filtro. Avalia: *o usuário merece uma segunda chance aqui?* Leva em conta trust score, histórico de infrações, primeira vez vs reincidência.

Se o trust score é alto e é a primeira infração, BLOCK pode virar EDUCATE.

**Resultado:** `mercy_applied`, `original_action` vs `action`

---

## Trust Score

Cada sessão acumula um score de confiança [0.0, 1.0]:

```
trust = 0.20 × base
      + 0.30 × histórico_de_compliance
      + 0.20 × appeals_aceitos
      + 0.15 × (1 - decaimento_temporal)
      + 0.15 × consistência_de_comportamento
```

| Score | Nível | Comportamento |
|---|---|---|
| ≥ 0.8 | Alto | Gilligan mais leniente, EDUCATE preferido |
| 0.5–0.8 | Médio | Comportamento padrão |
| < 0.5 | Baixo | Gilligan mais estrito, menos misericórdia |

O score **decai** com o tempo sem atividade e **recupera** com interações limpas.

---

## Ações possíveis

| Ação | Significado |
|---|---|
| `ALLOW` | Input limpo, pode prosseguir |
| `LOG` | Permitido mas registrado para auditoria |
| `EDUCATE` | Risco baixo-médio; usuário é informado (Gilligan aplicado) |
| `REDACT` | PII detectado; output deve ser mascarado |
| `INSPECT` | Requer revisão humana antes de continuar |
| `BLOCK` | Bloqueado (hard ou soft) |

---

## Contestabilidade

Todo verdict `contestable=True` pode ser contestado via appeal:

```python
# O usuário pode contestar dentro do prazo (padrão: 24h)
appeal = btv.appeal(
    verdict.verdict_id,
    reason="Este CPF é de um dataset público de testes.",
    grounds=["technical_error", "false_positive"],
)
```

**Grounds disponíveis:**

| Ground | Quando usar |
|---|---|
| `rawls_equity` | A regra aplicada é discriminatória ou injusta |
| `levinas_protection` | O bloqueio causou dano desproporcional |
| `gilligan_mercy` | O contexto humano não foi considerado |
| `jonas_responsibility` | O risco foi superestimado |
| `technical_error` | Bug ou falso positivo técnico |
| `scope_mismatch` | A regra não se aplica a este contexto |
| `false_positive` | Não era PII / violação real |

Appeals são revisados por humano em até 24h (princípio Jonas de responsabilidade com prazo).

---

## Jurisdições

O BTV suporta múltiplas jurisdições via bitmask no header `X-BTV-Jurisdiction`:

| Código | Regulação |
|---|---|
| `BR` | LGPD (Lei 13.709/2018) |
| `US` | HIPAA, CCPA, SOC 2 |
| `EU` | GDPR, EU AI Act |
| `UK` | UK GDPR, AI Principles |

```python
# Aplicar regras de LGPD + GDPR simultaneamente
verdict = btv.decide(text, jurisdictions=["BR", "EU"])
```

---

## Perfis setoriais

O `profile` ativa políticas específicas do setor:

| Perfil | Políticas extras |
|---|---|
| `general` | Regras base |
| `healthcare` | HIPAA, dados de saúde, consentimento |
| `finance` | PCI-DSS, dados bancários, fraude |
| `legal` | Sigilo profissional, dados sensíveis |
| `research` | Dados anonimizados permitidos com consentimento |
| `education` | Proteção de menores, COPPA |

---

### Próximos passos / Relacionados

- [Compliance — como o BTV se mapeia às normas](./compliance.md)
- [API Reference](./api-reference.md)
- [Arquitetura (Atlas)](./ARCHITECTURE_ATLAS.md)
- [Índice de ADRs](./adr/0000-adr-index.md)

---

<sub>[↑ Hub](./README.md) · [Trilha Engenheiro](./for-engineers.md) · [Trilha DPO/CISO](./for-dpo-ciso.md) · [Links de Referência](./reference-links.md)</sub>
