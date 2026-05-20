[BuildToValue](../README.md) › [Documentação](./README.md) › [Trilha DPO / CISO](./for-dpo-ciso.md) › **Compliance**

![DPO / CISO](https://img.shields.io/badge/Trilha-DPO%20%2F%20CISO-8957e5)

<!-- audience: dpo-ciso -->

---

# Compliance — FAQ

Respostas diretas às perguntas de compliance mais comuns. Sem juridiquês.

---

## LGPD (Brasil)

### O BTV me ajuda a cumprir a LGPD?

Sim, diretamente:

| Artigo LGPD | O que o BTV faz |
|---|---|
| Art. 6 — Finalidade e necessidade | Detecta PII e aplica políticas de mínimo necessário |
| Art. 18 — Direitos do titular | Contestabilidade via appeals + audit trail completo |
| Art. 20 — Revisão de decisões automatizadas | Sistema de appeals com revisão humana (SLA 24h) |
| Art. 46 — Medidas de segurança | Verdict assinado com HMAC, ledger imutável |
| Art. 49 — Proteção desde a concepção | Privacy by design: PII detectado antes de processar |

### O BTV detecta CPF, CNPJ, dados de saúde?

Sim. O kernel Rust tem detectores nativos para:
- CPF e CNPJ (com validação de dígito verificador)
- Email, telefone, endereço
- Dados de saúde (CID, CRM, diagnósticos)
- Cartão de crédito, dados bancários
- Coordenadas geográficas

### O BTV gera logs de auditoria?

Sim. Todo verdict tem:
- `verdict_id` imutável (formato `VRD-{ULID}`)
- `signature` HMAC-SHA256 (não repúdio)
- Timestamp, session_id, input hash, ação tomada
- Ledger SQLite + exportação para SIEM

### Como contestar uma decisão automatizada (Art. 20)?

Via appeal:
```python
appeal = btv.appeal(
    verdict.verdict_id,
    reason="Contexto específico que o modelo não considerou.",
    grounds=["scope_mismatch"],
)
# SLA: revisão humana em até 24h
```

---

## EU AI Act (Europa)

### Em qual categoria o BTV se enquadra?

O BTV é um sistema de **uso de alto risco** que *mitiga* riscos de outros sistemas de IA. Como sistema de governança, ele ajuda operadores de IA a cumprir:

- **Art. 5** — Práticas de IA proibidas (detecta e bloqueia)
- **Art. 9** — Sistema de gestão de risco (pipeline Rawls/Jonas)
- **Art. 12** — Manutenção de registros (ledger de verdicts)
- **Art. 14** — Supervisão humana (sistema de appeals)
- **Art. 86** — Direito de explicação (campo `explain` em todos os verdicts)

### O BTV fornece explicações legíveis por humanos?

Sim. Todo verdict de `/v1/decide` inclui:
```json
"explain": {
  "summary": "Texto simples resumindo a decisão",
  "rawls_rationale": "Por que a política foi aplicada",
  "levinas_rationale": "Impacto no usuário",
  "jonas_rationale": "Risco de longo prazo",
  "gilligan_rationale": "Por que (ou por que não) misericórdia foi aplicada"
}
```

### Suporta múltiplas jurisdições simultaneamente?

Sim. Use o header `X-BTV-Jurisdiction`:
```bash
curl -H "X-BTV-Jurisdiction: BR,EU" ...
```
Ou via SDK:
```python
verdict = btv.decide(text, jurisdictions=["BR", "EU"])
```

---

## HIPAA (EUA — Saúde)

### O BTV protege PHI (Protected Health Information)?

Com o perfil `healthcare` ativo, o BTV aplica políticas extras para:
- Detectar menções a diagnósticos, medicamentos, procedimentos
- Bloquear exposição não autorizada de dados de pacientes
- Gerar audit trail compatível com HIPAA §164.312

```python
verdict = btv.decide(text, profile="healthcare")
```

### O BTV é um Business Associate (BA)?

O BTV é software on-premises — você o opera na sua infraestrutura. Não há transmissão de dados para servidores Anthropic ou BuildToValue. Todos os dados ficam no seu ambiente.

---

## PCI-DSS (Dados de pagamento)

### O BTV detecta dados de cartão?

Sim. O kernel detecta:
- Números de cartão (Luhn validation)
- CVV, datas de expiração
- Dados de PANs em texto livre

Com perfil `finance`:
```python
verdict = btv.decide(text, profile="finance")
```

---

## Perguntas gerais

### O BTV envia meus dados para algum servidor externo?

Não. O BTV é 100% on-premises. O gateway Rust e o judiciário Python rodam na sua infraestrutura. Nenhum dado é enviado para servidores externos.

### Como funciona o sistema de appeals?

1. Verdict contestável é gerado (`contestable=True`)
2. Usuário submete appeal com motivo articulado (≥20 chars, princípio Levinas)
3. Mediador IA faz recomendação (accept/reject/escalate)
4. Revisor humano toma decisão final
5. SLA: 24 horas (princípio Jonas de responsabilidade com prazo)
6. Registro imutável de toda a cadeia decisória

### O que é um "hard block"?

Algumas violações são absolutas e não podem ser contestadas (`hard_blocked=True`). Exemplos típicos: termos explícitos de hard-block definidos nas políticas, CSAM, malware. Para estes casos, `contestable=False` e não há appeal possível.

### Como auditar uma decisão específica?

```python
# Toda decisão tem um verdict_id imutável
verdict_id = "VRD-01ARZ3NDEKTSV4RRFFQ69G5FAV"

# O HMAC-SHA256 da assinatura garante que o verdict não foi alterado
print(verdict.signature)  # "hmac-sha256:abc123..."
```

O ledger SQLite no gateway registra todos os verdicts com timestamp, input hash e assinatura.

---

### Próximos passos / Relacionados

- [Conceitos — o modelo de decisão](./concepts.md)
- [Links de Referência — textos regulatórios](./reference-links.md)
- [Pricing](../PRICING.md)
- [API Reference](./api-reference.md)

---

<sub>[↑ Hub](./README.md) · [Trilha Engenheiro](./for-engineers.md) · [Trilha DPO/CISO](./for-dpo-ciso.md) · [Links de Referência](./reference-links.md)</sub>
