# ADR-020: Intelligence Hub (MISP/STIX)

**Status:** ✅ Ativo
**Data:** Fevereiro 2026
**Versão:** v2.0
**Grupo:** G — Intelligence & Compliance

## Contexto

O PolicyEngine detecta ameaças conhecidas via regras estáticas. Para evoluir, o sistema precisa de uma base de conhecimento de ameaças que seja alimentável, consultável e auditável. Organizações de segurança (OWASP, MISP, STIX) publicam indicadores de comprometimento (IOCs) que devem enriquecer a detecção.

## Decisão

Implementar Intelligence Hub como módulo Python com SQLite persistence e API REST.

### Arquitetura
```
Fonte externa (OWASP, MISP, STIX, manual)
  → POST /v1/intelligence/ingest {id, threat_type, severity, source, indicators}
  → SQLite (data/threats.db)
  → BLAKE2b hash para integridade
  → POST /v1/intelligence/query {threat_type?, min_severity?, source?}
  → GET /v1/intelligence/stats
```

### Endpoints

| Método | Path | Função |
|:---|:---|:---|
| POST | `/v1/intelligence/ingest` | Ingerir threat individual |
| POST | `/v1/intelligence/ingest/batch` | Ingerir batch |
| POST | `/v1/intelligence/query` | Consultar por tipo/severity/source |
| GET | `/v1/intelligence/threat/{id}` | Buscar threat específica |
| GET | `/v1/intelligence/stats` | Estatísticas agregadas |

### Schema (SQLite)
```sql
CREATE TABLE threats (
    id TEXT PRIMARY KEY,
    threat_type TEXT NOT NULL,
    severity INTEGER NOT NULL,  -- 1-10
    source TEXT NOT NULL,        -- OWASP, MISP, STIX, manual
    indicators TEXT NOT NULL,    -- JSON array
    description TEXT DEFAULT '',
    mitre_id TEXT DEFAULT '',    -- MITRE ATT&CK reference
    created_at TEXT NOT NULL,
    hash TEXT NOT NULL            -- BLAKE2b integrity
);
```

### Invariantes

- Todo threat recebe hash BLAKE2b no ingest (imutabilidade)
- SQLite persiste via Docker volume (sobrevive restarts)
- Índices em threat_type, severity, source (queries O(log n))
- Sem integração automática com PolicyEngine (v2.1 target)

## Fundamento Filosófico

**Jonas (1984):** A responsabilidade proporcional exige conhecimento atualizado das ameaças. Um sistema de governança que ignora ameaças conhecidas é negligente. O Intelligence Hub é a memória de ameaças do sistema.

## Limitações Atuais

- Ingest é manual (API). Sem pull automático de feeds MISP/STIX.
- Threats não alimentam PolicyEngine automaticamente (bridge planejada para v2.1).
- Sem deduplicação por indicador (apenas por ID).

## Referências

- `python/buildtovalue/intelligence/threat_feed.py`
- `rust/kernel/src/observability/threat_ingestor.rs` (Rust counterpart, WAL-backed)