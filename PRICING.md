[BuildToValue](README.md) · [Docs](docs/README.md) › **Pricing**

![Engenheiro](https://img.shields.io/badge/Trilha-Engenheiro-1f6feb) ![DPO / CISO](https://img.shields.io/badge/Trilha-DPO%20%2F%20CISO-8957e5)

<!-- audience: both -->

---

# BuildToValue — Modelo de Precificação

**Métrica de billing:** decisões governadas (interceptações pelo Trust OS).  
**Endpoint:** `OPENAI_BASE_URL=https://buildtovalue-gateway.fly.dev/v1/proxy`

---

## Open Core (gratuito, sempre)

- Rust kernel (`btv-core`) — Apache 2.0, uso irrestrito
- **10.000 decisões/mês** no serviço gerenciado (Fly.io)
- Dashboard básico (Overview, Audit Ledger)
- Policy bundles públicos: `baseline_trust`, `gdpr_art22_chatbot`, `hipaa_phi_audit`
- Evidência criptográfica BLAKE3 + HMAC-SHA256 em cada decisão
- SLA de contestação: **24h** (LGPD Art. 20 / EU AI Act Art. 14)
- Suporte: GitHub Issues

---

## Professional ($199/mês)

- **500.000 decisões/mês**
- Dashboard completo (Overview, Compliance, Appeals, Intelligence)
- Policy bundles premium: HIPAA, SOC 2, ISO 27001
- Contestability Loop habilitado — revisão humana com trilha de evidências
- Uptime: **99,9% SLA**
- SLA de contestação: **24h** (LGPD Art. 20 / EU AI Act Art. 14)
- Suporte: e-mail 8×5, resposta em 8h úteis

---

## Enterprise (sob consulta)

- **Decisões ilimitadas**
- Deploy dedicado: VPC isolada ou on-premise (via `ops/k8s/` — ADR-0060)
- White-label dashboard
- Policy bundles customizados por setor (saúde, financeiro, jurídico)
- Relatórios de conformidade customizados para auditorias regulatórias
- Uptime: **99,99% SLA**
- SLA de contestação: **24h** (LGPD Art. 20 / EU AI Act Art. 14)
- Suporte: 24×7 + gerente técnico dedicado

---

## Comparativo

| Recurso | Open Core | Professional | Enterprise |
|:---|:---:|:---:|:---:|
| Decisões/mês | 10K | 500K | Ilimitado |
| Kernel Rust (btv-core) | ✅ | ✅ | ✅ |
| Evidência criptográfica | ✅ | ✅ | ✅ |
| Dashboard básico | ✅ | ✅ | ✅ |
| Dashboard completo | — | ✅ | ✅ |
| Policy bundles premium | — | ✅ | ✅ |
| Policy bundles custom | — | — | ✅ |
| Contestability Loop | — | ✅ | ✅ |
| Deploy on-premise / VPC | — | — | ✅ |
| White-label | — | — | ✅ |
| Uptime SLA | — | 99,9% | 99,99% |
| SLA contestação | 24h | 24h | 24h |
| Suporte | Issues | E-mail 8×5 | 24×7 dedicado |
| Preço | Grátis | $199/mês | Consulta |

---

## Perguntas Frequentes

**O kernel Rust é sempre gratuito?**  
Sim. `btv-core` é Apache 2.0. Você pode usar o kernel localmente sem qualquer limite de decisões. O billing aplica-se exclusivamente ao serviço gerenciado (`buildtovalue-gateway.fly.dev`).

**O que conta como "decisão"?**  
Cada requisição interceptada pelo proxy `/v1/proxy/*` — independente do veredicto (ALLOW, BLOCK, REDACT, EDUCATE).

**Posso exceder o limite do Open Core?**  
Sim. Requisições além de 10K/mês retornam HTTP 429 com header `Retry-After`. Faça upgrade para Professional antes de atingir o limite para evitar interrupção.

**Os dados saem do Brasil?**  
No serviço gerenciado, `primary_region = "gru"` (São Paulo) garante que o processamento ocorre em território nacional. Clientes Enterprise com deploy on-premise têm controle total sobre residência de dados (LGPD Art. 44).

**Como funciona o Contestability Loop?**  
Cada bloqueio (HTTP 451) retorna `appeal_url` no body. O cliente envia a contestação para essa URL; o AppealEngine notifica um revisor humano e fecha o loop em até 24h com decisão fundamentada e evidência BLAKE3 vinculada.

---

### Próximos passos / Relacionados

- [Compliance — FAQ de conformidade](docs/compliance.md)
- [Conceitos — como o BTV decide](docs/concepts.md)
- [Quickstart](docs/quickstart.md)

---

<sub>[↑ Hub](docs/README.md) · [Trilha Engenheiro](docs/for-engineers.md) · [Trilha DPO/CISO](docs/for-dpo-ciso.md) · [Links de Referência](docs/reference-links.md)</sub>
