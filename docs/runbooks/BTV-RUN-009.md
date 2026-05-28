# BTV-RUN-009: Runbook Operacional de Auditoria de Integridade e Verificação Forense

* **ID do Documento:** BTV-RUN-009
* **Versão Ativa:** v1.0.1 (Maio/2026)
* **Classificação de Segurança:** Confidencial / Restrito
* **Escopo:** Subsistema `VerifierEngine` (Kernel Rust) e Camada de Streaming gRPC do BuildToValue (BTV) v4.0

---

## 1. Matriz de Responsabilidades de Auditoria (RACI)

O acionamento das rotinas de inspeção pode ser motivado por cronograma preventivo interno ou por intimação regulatória formal.

| Procedimento | DPO / Compliance | SecOps | SRE / DevOps | Core Security |
| :--- | :---: | :---: | :---: | :---: |
| **D: Inspeção de Integridade Pontual** | **A** | **C** | **R** | **I** |
| **E: Reconstrução Forense por Fraude** | **A** | **R** | **R** | **C** |
| **F: Exportação de Evidência para Órgãos** | **R** | **C** | **R** | **I** |

> 📌 **Legenda Canônica:** **R**esponsible (Executor), **A**ccountable (Aprovador), **C**onsulted (Apoio), **I**nformed (Notificado).

---

## 2. Procedimento D: Verificação de Integridade da Cadeia BLAKE3 por Tenant

### 2.1. Objetivo e Pré-requisitos

Validar de forma síncrona se a cadeia de blocos de auditoria do tenant sofreu alguma manipulação ad-hoc ou corrupção física em disco, recalculando as hashes de forma encadeada.

A invariante matemática que o `VerifierEngine` valida em memória é:

$$H_i = \text{BLAKE3}(H_{i-1} \parallel \text{Context}_i \parallel \text{Signature}_i)$$

* **Pré-condição:** Identificação do código canônico do cliente (`BTV_TENANT_ID`).
* **Janela Operacional:** Fora do pico transacional devido ao consumo de CPU do processo nativo.

### 2.2. Execução Passo a Passo

1. Conecte-se ao bastion de infraestrutura com a credencial de SRE autorizada via change ticket.
2. Dispare o validador nativo apontando para o diretório isolado do ledger do cliente:

```bash
./btv-validator --verify-chain \
  --tenant-id="tenant_corporate_br" \
  --base-path="/var/lib/btv/data/tenants"
```

### 2.3. Validação e Pós-condição

O utilitário deve retornar o código de saída `exit 0` e o payload JSON sem nós órfãos:

```json
{
  "chain_valid": true,
  "total_blocks_verified": 14502,
  "last_sequence_id": 14502,
  "tamper_evidence_detected": false,
  "status": "CHAIN_INTEGRITY_VERIFIED"
}
```

---

## 3. Procedimento E: Reconstrução Forense Completa do Ledger

### 3.1. Objetivo e Pré-requisitos

Isolar evidências e reatar o encadeamento do ledger caso a rotina preventiva aponte uma quebra de integridade física ou lógica em disco.

* **Pré-condição:** Alerta crítico `BTV_COMPLIANCE_TAMPER_DETECTED` ou crash de escrita ativo.

### 3.2. Execução Passo a Passo

1. Recupere o histórico real de uso da chave criptográfica através do barramento do AWS CloudTrail para cruzamento de metadados:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=BTV_TEK_KEY_ARN \
  --output json > /tmp/kms_receipts.json
```

2. Dispare o motor de reconstrução forense para cruzar o estado físico do SQLite com as assinaturas imutáveis do log de auditoria:

```bash
./btv-validator --reconstruct-forensic \
  --tenant-id="tenant_corporate_br" \
  --kms-history=/tmp/kms_receipts.json
```

### 3.3. Plano de Fallback e Recovery de Memória (SQLite Recovery)

Caso o diagnóstico aponte corrupção física do arquivo por falta de memória volátil (picos de OOM) e não por ataque intencional:

1. Recupere o último snapshot íntegro do `ledger.db` armazenado de forma fria no S3.
2. Force o reprocessamento linear dos blocos transacionais a partir do offset de segurança na stream de mensagens do Kafka:

```bash
./btv-validator --replay-stream \
  --tenant-id="tenant_corporate_br" \
  --start-offset=CHECKPOINT_ID
```

---

## 4. Procedimento F: Exportação de Evidência Auditável para Órgãos Reguladores

### 4.1. Objetivo e Pré-requisitos

Consolidar e assinar digitalmente um pacote de dados imutável para entrega oficial aos inspetores fiscais do Banco Central ou ANPD.

### 4.2. Execução Passo a Passo

1. Dispare a query de extração via CLI, gerando o bundle compactado e chancelado pela chave pública do DPO:

```bash
./btv-validator --export-evidence \
  --tenant-id="tenant_corporate_br" \
  --start-seq=10000 \
  --end-seq=14502 \
  --output-package="/tmp/BTV_EVIDENCE_BACEN_2026.bundle"
```

### 4.3. Validação

Atestar a autenticidade do pacote gerado antes da transmissão externa:

```bash
./btv-validator --verify-package --package-path="/tmp/BTV_EVIDENCE_BACEN_2026.bundle"
```

> O retorno textual obrigatório do console deve ser exatamente:
> `Package signature verified. Hash checksum matches. Document is authentic.`

---

## 5. Tabela de Anomalias de Ledger e Resposta Rápida (Troubleshooting)

| Sintoma Identificado | Causa Raiz | Código Interno | Ação de Contenção Operacional | Critério de Encerramento |
| :--- | :--- | :---: | :--- | :--- |
| Alerta crítico `BTV_COMPLIANCE_TAMPER_DETECTED` ativo. | Um registro histórico do banco `ledger.db` foi alterado de forma ad-hoc por manipulação local. | **E170** | Fail-Closed. Suspender as credenciais de escrita do tenant e acionar o Procedimento E. | Relatório forense emitido e base de dados restaurada via snapshot íntegro. |
| Erro nos logs apontando descontinuidade estrita de blocos. | Salto na numeração autoincremental do banco (ex.: salto da sequência 1400 diretamente para 1402). | **E155** | Bloqueio em estado Hard BLOCK. Avaliar se houve crash de escrita durante flush de cache por pressão de RAM. | Execução do `PRAGMA integrity_check;` retornando `ok` após reprocessamento do offset. |
| Falha de validação criptográfica por hash órfã. | O bloco físico existe no banco e o hash bate, mas a chave efêmera vinculada foi expurgada sem o fluxo regulatório do DPO. | **E110** | Classificar o chamado como "Inconsistência Criptográfica". Congelar rotinas de exclusão automática no tenant. | Localização da chave no log de auditoria ou laudo de quebra de custódia emitido pelo DPO. |
