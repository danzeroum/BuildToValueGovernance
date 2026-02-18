
# ADR-004: Immutable Ledger Design

**Status**: ✅ APROVADO — EMENDADO v3.0  
**Data Original**: Dezembro 2025  
**Emenda v3.0**: 08 fev 2026  
**Crate v3.0**: `btv-ledger`

## Contexto

Cada decisão do sistema precisa ser auditável, assinada e resistente a tampering. Sem ledger imutável, não há como provar que uma decisão foi tomada corretamente — ou contestá-la.

## Decisão

Ledger multi-camada com chain-of-hashes BLAKE3:

```
┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────────┐
│ L1: WAL     │──→│ L2: Disk     │──→│ L3: Remote   │──→│ L4: External│
│ (RAM, <1ms) │   │ (SSD, <5ms)  │   │ (async, <10ms│   │ (batch 60s) │
│ volátil     │   │ persistente  │   │ 99.99% durable│  │ disaster rec│
└─────────────┘   └──────────────┘   └──────────────┘   └─────────────┘
```

Cada entry contém:

```rust
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub evidence_id: Uuid,
    pub action_taken: String,
    pub chain_hash: [u8; 32],    // BLAKE3(prev_hash || entry_bytes)
    pub signature: [u8; 32],     // HMAC-SHA256
}
```

## Fundamento Filosófico

- **Jonas**: Responsabilidade proporcional ao poder. Cada decisão assinada criptograficamente. Retenção de 7 anos.
- **Levinas**: Contestabilidade — o ledger é a prova que permite ao usuário exercer recurso (SLA 24h).
- **Rawls**: Transparência radical — auditor externo pode verificar integridade sem acesso aos dados.

## Emenda v3.0 — Persistência via NATS JetStream

| Aspecto | v2.2 | v3.0 |
|---------|------|------|
| L3 Remote | S3 via `aws-sdk-s3` (ADR-007) | NATS JetStream (embedded/sidecar) |
| Deduplicação | S3 key idempotente | `Nats-Msg-Id` header nativo |
| Retry | Backoff manual (3× 100→200→400ms) | NATS consumer retry nativo |
| Criptografia | S3 SSE-AES256 | NATS TLS + encryption at rest |
| Custo | ~$500/mês (S3 Standard) | ~$0 (sidecar Docker Compose) |

O ADR-007 (S3 Remote Sync) permanece válido como opção para deployment enterprise/cloud. Para infra enxuta (Hetzner), NATS JetStream substitui S3.

## Métricas

- Durabilidade: 99.99% (L1+L2+L3)
- Recovery time: < 5s (p95)
- Chain integrity verification: O(n) linear scan, detecta tampering em qualquer entry

---
