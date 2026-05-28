# BTV-RUN-008: Retenção, Custódia e Cripto-Shredding

| Campo | Valor |
|-------|-------|
| **ID do Documento** | BTV-RUN-008 |
| **Versão Ativa** | v1.0.0 |
| **Data** | Maio/2026 |
| **Classificação** | Confidencial / Restrito |
| **Escopo** | Kernel Rust e Adaptadores JVM do BuildToValue (BTV) v4.0 |
| **Relacionados** | BTV-RUN-010 (Poluição Cross-Tenant E120), ADR-0004 (Ledger Imutável), ADR-0005 (Evidence Protocol v2), ADR-0064 (Policy Reload Ed25519) |

---

## 1. Matriz de Acesso e Responsabilidades (RBAC/SoD)

| Papel Operacional | Escopo de Acesso | Responsabilidade Principal |
|---|---|---|
| **DPO / Compliance Officer** | Console de Governança / Chamados Regulatórios | Aprovação de requisições de Direito ao Esquecimento (Exclusão). |
| **SecOps Engineer** | Hardware Secure Enclave (Cloud HSM / KMS) | Rotação de chaves mestras e gerenciamento de políticas de criptografia. |
| **SRE / DevOps** | Infraestrutura Linux / Volumes de Contêiner | Monitoramento do fosso de cache e volumetria dos arquivos ledger.db. |

---

## 2. Procedimento A: Direito ao Esquecimento (Cripto-Shredding)

> ⚠️ **Aviso de Integridade:** Nunca execute comandos `SQL DELETE FROM` diretamente no `ledger.db` de um tenant. A remoção física de uma linha corromperá a árvore de hashes sequenciais (BLAKE3) verificada pelo VerifierEngine, forçando o sistema a travar o host Java em estado de pânico regulatório.

**Pré-condição:** Chamado aprovado pelo DPO no ServiceNow com `change_ticket_id` preenchido.  
**Pós-condição:** JSON de confirmação persistido no ledger de auditoria.  
**Rollback:** Não aplicável — operação irreversível por design (LGPD Art. 18).

### 2.1. Fluxo de Execução

1. **Localização do Identificador:** Extraia o `ephemeral_key_id` correspondente ao `verdict_id` a partir do painel forense do Jira/ServiceNow.
2. **Acesso ao Enclave:** Autentique-se no KMS/HSM corporativo com credenciais m-of-n.
3. **Disparo via CLI (sob change ticket `CHANGE_TICKET_ID`):**

```bash
./btv-validator --execute-shred \
  --tenant-id="TENANT_ID_PLACEHOLDER" \
  --ephemeral-key-id="EPHEMERAL_KEY_ID_PLACEHOLDER" \
  --change-ticket="CHANGE_TICKET_ID"
```

### 2.2. Critério de Sucesso

```json
{
  "shred_executed": true,
  "ephemeral_key_purged": "EPHEMERAL_KEY_ID_PLACEHOLDER",
  "ledger_hash_chain_intact": true,
  "status": "DATA_DELETED_PERMANENTLY"
}
```

---

## 3. Procedimento B: Rotação Semestral da Chave de Envelope do Tenant (TEK)

**Periodicidade:** A cada 180 dias ou imediatamente em caso de suspeita de vazamento.  
**Janela operacional:** Assíncrona — sem indisponibilidade do microsserviço.

```
[KMS / Nova TEK v2] → [Cifra novos blocos] → [Chave v1 mantida apenas para leitura de blocos antigos]
```

### 3.1. Script de Execução

```bash
# Auditoria prévia via CloudTrail — confirmar estado atual da chave
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=BTV_TEK_KEY_ARN_PLACEHOLDER \
  --output json > /tmp/tek_pre_rotation_audit.json

# Aciona nova versão da chave AES-256-GCM sem quebrar compatibilidade retroativa
aws kms enable-key-rotation \
  --key-id="BTV_TEK_KEY_ARN_PLACEHOLDER"
```

### 3.2. Validação

Monitore `btv-interceptor.log` pela assinatura:

```
INFO [btv-interceptor] BTV_TEK_ROTATION_DETECTOR: Nova versao da TEK assimilada com sucesso. Cache sincronizado para TENANT_ID_PLACEHOLDER.
```

---

## 4. Procedimento C: Mitigação de Pressão de Memória (OOM)

**Gatilho:** Alerta `BTV_CACHE_PRESSURE_HIGH` (RAM >= 88%).

### 4.1. Ações Imediatas (SRE)

**Pré-condição:** Acesso restrito à VPC de infraestrutura.  
**Pós-condição:** `PRAGMA integrity_check;` retornando `ok` em todos os tenants afetados.

1. **Forçar flush de memória:**

```bash
curl -X POST \
  -H "Authorization: Bearer $(cat /var/run/secrets/btv/mgmt_token)" \
  https://BTV_MGMT_PRIVATE_IP:8080/mgmt/cache/flush-all
```

2. **Verificação de consistência pós-flush:**

```bash
sqlite3 /var/lib/btv/data/TENANT_ID_PLACEHOLDER/ledger.db "PRAGMA integrity_check;"
```

> Retorno esperado obrigatório: `ok`

---

## 5. Incident Handling — Tabela de Resolução Regulatória

| Sintoma | Causa Provável | Código | Ação Imediata |
|---|---|---|---|
| `MismatchedInputException` nos logs Java | Payload do kernel Rust omitiu `signature_ref` ou hash forense corrompido em trânsito FFI | **E150** | Hard BLOCK forçado. Isolar transação no SIEM, coletar JSON bruto do buffer JNI, acionar Core Security. |
| Pipeline CI/CD abortado por incompatibilidade de minor | Política YAML requer campos inexistentes no binário compilado | **E160** | Reverter commit do YAML ou atualizar `.so` do contêiner para versão correspondente. |
| Log contendo `BTV_CROSS_TENANT_POLLUTION_HALT` | Microsserviço injetou dados em `tenant_id` diferente do autenticado no JWT | **E120** | **Risco Crítico.** Worker derrubado. Revogar credenciais imediatamente e acionar CSIRT. Ver BTV-RUN-010. |
| Hash chain quebrado detectado pelo VerifierEngine | Sequência de hashes BLAKE3 descontinuada no ledger | **E155** | Hard BLOCK no host Java. Isolar volume do tenant, acionar Core Security e DPO. NÃO executar DELETE. |

---

## 6. Critérios de Encerramento do Incidente

- [ ] `PRAGMA integrity_check;` retorna `ok` em todos os tenants afetados
- [ ] Nenhuma nova ocorrência do código de erro nas 48h subsequentes
- [ ] DPO assina termo de encerramento para fins de prestação de contas à ANPD
- [ ] Evidências coletadas persistidas no ledger de auditoria com HMAC-SHA256

---

_Aprovado por: DPO / Compliance Officer (Accountable)_  
_Última revisão: 2026-05-27_
