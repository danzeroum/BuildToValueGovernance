# BTV-RUN-010: Resposta a Incidentes de Poluição Cruzada entre Tenants (E120)

| Campo | Valor |
|-------|-------|
| **ID do Documento** | BTV-RUN-010 |
| **Versão Ativa** | v1.0.0 |
| **Data** | Maio/2026 |
| **Classificação** | Confidencial / Restrito |
| **Escopo** | Resposta a Incidentes na Fronteira FFI e Quebra de Isolamento Multi-Tenant (E120) |
| **Relacionados** | BTV-RUN-008 (Cripto-Shredding, TEK, OOM), ADR-0009 (Modular Monolith), ADR-0017 (Contestability Loop), ADR-0042 (Policy-as-Code v2) |

---

## 1. Matriz RACI de Resposta a Incidentes Críticos

O acionamento deste runbook é **obrigatório e imediato** assim que a flag `BTV_CROSS_TENANT_POLLUTION_HALT` for registrada pelo SIEM.

| Procedimento | DPO / Compliance | CSIRT / SecOps | SRE / DevOps | Core Security |
|---|---|---|---|---|
| **A: Contenção de Runtime** | I | R | R | C |
| **B: Investigação Forense** | **A** | R | C | R |
| **C: Saneamento e Restabelecimento** | **A** | C | R | C |

> **Legenda RACI canônica:** R = Responsible (Executor), A = Accountable (Aprovador — único por procedimento), C = Consulted (Apoio), I = Informed (Notificado).

---

## 2. Procedimento A: Contenção de Runtime e Isolamento do Perímetro

**Objetivo:** Isolar o container causador para impedir propagação de acessos espúrios.  
**Pré-condição:** Alerta `BTV_CROSS_TENANT_POLLUTION_HALT` disparado. Kernel Rust já executou Hard BLOCK.  
**Janela operacional:** Minutos (fase de contenção imediata).  
**Rollback:** Restaurar label do pod para estado anterior se contenção for falso positivo confirmado.

### 2.1. Execução

1. Identifique o namespace e pod ofensivo via Grafana/Kibana.
2. Isole o pod **sem destruí-lo** (preservar RAM volátil para perícia):

```bash
# Desconecta o pod do Service Mesh sem perder o estado de memória
kubectl label pod POD_NAME_PLACEHOLDER -n btv-interceptor \
  btv-isolation=isolated --overwrite
```

3. Revogue imediatamente os tokens de transporte do microsserviço upstream associado ao tenant afetado.

### 2.2. Validação de Contenção

- Tráfego de entrada para o container isolado deve **zerar** no Istio/Linkerd.
- Novas requisições daquele microsserviço host devem receber **HTTP 403** na API Gateway.

---

## 3. Procedimento B: Análise Forense e Rastreamento de Payload

**Objetivo:** Rastrear a causa raiz (erro de roteamento, vazamento JVM, ou falsificação de token).  
**Pré-condição:** Contenção concluída. Ticket de investigação aberto com severidade máxima.  
**Pós-condição:** Laudo forense assinado pelo Core Security com classificação da causa raiz.

### 3.1. Execução

1. Extraia histórico de eventos de autenticação do CloudTrail nas janelas anteriores ao incidente:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=BTV_TEK_KEY_ARN_PLACEHOLDER \
  --start-time "INCIDENT_TIMESTAMP_MINUS_5MIN" \
  --end-time "INCIDENT_TIMESTAMP_PLUS_5MIN" \
  --output json > /tmp/kms_traffic_audit.json
```

2. Execute o analisador do dump de memória do processo isolado:

```bash
./btv-validator --audit-memory-dump \
  --dump-path="/var/lib/btv/dumps/core_panic.dmp"
```

### 3.2. Pós-condição e Laudo

O Core Security deve atestar no relatório final se a falha decorreu de **violação estrutural de software** ou **tentativa de injeção maliciosa de contexto**. O DPO assina o laudo como Accountable.

---

## 4. Procedimento C: Saneamento, Rotação de Credenciais e Restabelecimento

**Objetivo:** Limpar ambientes temporários e restabelecer operação nominal após correção da vulnerabilidade.  
**Pré-condição:** Causa raiz identificada, laudo assinado pelo DPO, vulnerabilidade mitigada.  
**Rollback:** Manter pod isolado até confirmação de `PRAGMA integrity_check;` = `ok`.

### 4.1. Execução

1. Force rotação emergencial da TEK em **ambos** os tenants envolvidos (originador e target), conforme BTV-RUN-008 Procedimento B.

2. Execute flush total do fosso de cache em ambos os perímetros:

```bash
curl -X POST \
  -H "Authorization: Bearer $(cat /var/run/secrets/btv/mgmt_token)" \
  "https://BTV_MGMT_PRIVATE_IP:8080/mgmt/cache/flush-tenant?id=TARGET_TENANT_ID_PLACEHOLDER"
```

3. Libere deploy das imagens corrigidas e homologadas pelo portão de CI/CD.

### 4.2. Critérios de Encerramento do Incidente

- [ ] `PRAGMA integrity_check;` retorna `ok` em **ambos** os ledgers físicos
- [ ] Nenhuma nova ocorrência de E120 nas 48h subsequentes
- [ ] DPO assina termo de encerramento para prestação de contas à ANPD
- [ ] Evidências coletadas persistidas com HMAC-SHA256 no ledger de auditoria

---

## 5. Tabela de Sinais de Alerta no SIEM (SOC Monitoring)

| Assinatura | Canal | Significado Técnico | Risco | Ação |
|---|---|---|---|---|
| `BTV_CROSS_TENANT_POLLUTION_HALT` | Adaptador JNI (Java) | `tenant_id` da chamada divergiu do `tenant_id` assinado criptograficamente no token | **Crítico** | Bloqueio imediato + Procedimento A |
| `BTV_ABI_BUFFER_OVERFLOW_SHIELD` | Kernel Core (Rust) | Buffer FFI estourou limites de alocação previsíveis | **Alto** | Hard BLOCK imediato, abortar processo |
| `BTV_TOKEN_EXPIRED_REJECTION` | Kernel Core (Rust) | Requisição com credenciais fora da janela de expiração — condição nominal | **Baixo (E101)** | Emitir E101 para reautenticação; **não** acionar este runbook |

> **Nota E101 vs E120:** `BTV_TOKEN_EXPIRED_REJECTION` é uma condição nominal de autenticação (E101), **não** um incidente de isolamento cross-tenant (E120). Estes dois alertas têm tratamentos completamente distintos e não devem ser confundidos no SIEM.

---

_Aprovado por: DPO / Compliance Officer (Accountable — Procedimentos B e C)_  
_Última revisão: 2026-05-27_
