# ADR-007: Remote Sync Implementation via AWS S3

**Status**: APPROVED  
**Date**: 2026-02-05  
**Deciders**: Staff Engineer, Lead Architect  
**Gate**: G3 (Durability & Recovery)

## Context

A promessa de **99.99% durabilidade** do Immutable Ledger estava comprometida. 
O código v2.2 implementava o `remote_sync_worker` como um **mock**:

```rust
// ❌ MOCK (v2.2) - RISK EXISTENCIAL
async fn remote_sync_worker(mut rx: mpsc::UnboundedReceiver<LedgerEntry>) {
    while let Some(entry) = rx.recv().await {
        // TODO: Implementar upload para S3/Vault
        log::debug!("Remote sync: entry {}", entry.entry_id);
        // ❌ ENTRADA É DESCARTADA
    }
}
```

**Impacto**: Se o container morrer e o disco efêmero do Kubernetes for reciclado, 
o ledger **desaparece**. Violação da promessa do paper.

## Decision

Implementar **S3 Connector real** com:

1. **Upload real via AWS SDK**: `aws-sdk-s3` (crate oficial)
2. **Retry logic**: 3 tentativas, backoff exponencial (100ms → 200ms → 400ms)
3. **Dead Letter Queue (DLQ)**: Falhas persistentes movidas para fila in-memory
4. **Idempotência**: Mesma `entry_id` → mesma chave S3
5. **Key format**: `{prefix}/{year}/{month}/{day}/{entry_id:08x}.bin`

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Ledger Entry                                                 │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ├─► WAL (RAM) ────► < 1ms ────► ✅ Volatile
                  │
                  ├─► Disk (SSD) ───► < 5ms ────► ✅ Persistent
                  │
                  └─► S3 (async) ───► < 10ms ───► ✅ 99.99% Durable
                                                   │
                                                   ├─ Retry 1 (100ms)
                                                   ├─ Retry 2 (200ms)
                                                   ├─ Retry 3 (400ms)
                                                   └─ DLQ (if failed)
```

### S3 Configuration

```rust
pub struct S3Config {
    pub bucket: String,               // "buildtovalue-ledger"
    pub key_prefix: String,           // "ledger/prod/"
    pub storage_class: StorageClass,  // STANDARD (99.99%)
    pub encryption: bool,             // AES256 (server-side)
    pub max_retries: u32,             // 3
    pub initial_retry_timeout_ms: u64,// 100ms
    pub dlq_max_size: usize,          // 1000 entries
}
```

### Key Format (Idempotência)

```
ledger/2026/02/05/00000001.bin
       └─┬─┘ └┬┘ └┬┘ └───┬────┘
         │    │   │      └─ entry_id (hex)
         │    │   └──────── dia
         │    └──────────── mês
         └───────────────── ano
```

**Garantia**: Mesmo entry_id sempre produz mesma chave → S3 PutObject sobrescreve.

## Consequences

### Positivo
- ✅ **99.99% durability**: S3 Standard garante SLA
- ✅ **Resilience**: Retry + DLQ previnem perda de dados
- ✅ **Auditability**: Chaves hierárquicas facilitam consultas (ex: "todas entradas de fevereiro")
- ✅ **Compliance**: LGPD Art. 46 (segurança dos dados)

### Negativo
- ⚠️ **Custo AWS**: S3 Standard = ~$0.023/GB/mês (aceita-se para produção)
- ⚠️ **Latência async**: 10ms não bloqueia `append()`, mas DLQ pode encher
- ⚠️ **Credenciais**: IAM Role obrigatória (não usar Access Keys hardcoded)

### Mitigação de Riscos
- **DLQ Full**: Alertar via CloudWatch quando DLQ > 500 entries
- **S3 Outage**: WAL + Disk garantem dados até 24h sem S3
- **Custos**: Lifecycle policy para Glacier após 90 dias

## Alternatives Considered

| Backend | Durability | Latência | Custo/GB | Veredito |
|---------|-----------|----------|----------|----------|
| **S3 Standard** | 99.99% | ~10ms | $0.023 | ✅ ESCOLHIDO |
| Azure Blob (Hot) | 99.99% | ~12ms | $0.018 | ❌ Lock-in AWS |
| Google Cloud Storage | 99.99% | ~8ms | $0.020 | ❌ Lock-in AWS |
| MinIO (self-hosted) | 99.0% | ~5ms | $0.00* | ❌ Operacional |

\* Custo de infraestrutura não incluído

## Implementation Details

### Credentials (IAM Role Preferred)

```yaml
# EKS Pod IAM Role (Terraform)
resource "aws_iam_role" "ledger_sync" {
  name = "buildtovalue-ledger-sync"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.eks.arn
      }
    }]
  })
}

resource "aws_iam_role_policy" "s3_access" {
  role = aws_iam_role.ledger_sync.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject",
        "s3:GetObject"
      ]
      Resource = "arn:aws:s3:::buildtovalue-ledger/*"
    }]
  })
}
```

### Environment Variables

```bash
# Produção (IAM Role)
BTV_S3_BUCKET=buildtovalue-ledger
AWS_REGION=us-east-1

# Desenvolvimento (Access Keys - NÃO USAR EM PROD)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```

### Monitoring

```yaml
# CloudWatch Alarm (DLQ Size)
alarm:
  name: "BTV-Ledger-DLQ-High"
  metric: "CustomMetrics/DLQSize"
  threshold: 500
  action: "SNS:OnCall"
```

## Testing Strategy

```rust
#[tokio::test]
#[ignore]  // Requer credenciais AWS reais
async fn test_s3_upload_integration() {
    let config = S3Config {
        bucket: "buildtovalue-ledger-test".to_string(),
        ..Default::default()
    };
    
    let connector = S3Connector::new(config).await.unwrap();
    let entry = LedgerEntry { entry_id: 1, ... };
    
    // Upload
    connector.upload(&entry).await.unwrap();
    
    // Verifica no S3
    let key = "ledger/2026/02/05/00000001.bin";
    assert!(s3_key_exists(key).await);
}
```

## Compliance

- **LGPD Art. 46**: Segurança dos dados (encryption at rest)
- **LGPD Art. 48**: Comunicação de incidentes (DLQ alerts)
- **ISO 42001**: AI system data integrity
- **NIST CSF**: Protect (PR.DS-1: Data-at-rest protection)

## Approval

- [x] Staff Engineer: Implementação S3Connector correta
- [x] Lead Architect: Integração com DurableLedger aprovada
- [x] FinOps: Custo S3 aprovado ($500/mês para 20k entries/dia)

**Signature**: `ADR-007-APPROVED-2026-02-05`
