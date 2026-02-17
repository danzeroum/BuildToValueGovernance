# ADR-023: Threat→Policy Bridge (Intelligence → PolicyEngine)

**Status:** ✅ Ativo
**Data:** Fevereiro 2026
**Versão:** v2.1
**Grupo:** G — Intelligence & Compliance

## Contexto

O Intelligence Hub (ADR-020) armazena threats e o PolicyGenerator gera YAML a partir
de classificações. Porém não existe conexão automática: threats ingeridas não alimentam
o PolicyEngine. Uma empresa que ingere 500 IOCs do MISP não obtém nenhuma mudança na
detecção. O ciclo hoje é inteiramente manual.

## Decisão

Implementar `ThreatPolicyBridge` como orquestrador que conecta:
```
MispIngestor → ThreatClassifier → PolicyGenerator → data/policies/auto-generated/
```

### Regras de auto-geração (severity-driven)

| Severity | Action       | enabled | requires_review |
|:---------|:-------------|:--------|:----------------|
| 8-10     | BLOCK        | false   | true            |
| 5-7      | ESCALATE     | false   | true            |
| 1-4      | MONITOR_ONLY | false   | true            |

### Guardrails

1. **Human-in-the-Loop obrigatório:** Toda policy nasce `enabled: false`. Nenhuma
   policy auto-gerada entra em produção sem aprovação humana explícita.
2. **Deduplicação:** Policies não são re-geradas se já existe uma para o mesmo
   `threat_type` com severity igual ou superior.
3. **Audit trail:** Toda geração é registrada no ledger com `source: "bridge"`.
4. **Limite por sync:** Máximo 50 policies por execução (circuit breaker).
5. **Rollback:** Arquivo de policies é atômico (write-temp + rename).

### Endpoints

| Método | Path                          | Função                     |
|:-------|:------------------------------|:---------------------------|
| POST   | `/v1/intelligence/bridge/sync`| Trigger manual de sync     |
| GET    | `/v1/intelligence/bridge/status`| Status do último sync    |

### Schema de resposta (sync)
```json
{
  "synced_at": "2026-02-17T...",
  "threats_processed": 42,
  "policies_generated": 7,
  "policies_deduplicated": 3,
  "policies_dir": "data/policies/auto-generated/",
  "all_require_review": true
}
```

## Fundamento Filosófico

**Jonas (1984):** A responsabilidade proporcional exige reação a ameaças conhecidas.
Um sistema que armazena threats sem gerar defesas é negligente — viola o imperativo
heurístico de Jonas. O bridge transforma conhecimento em ação defensiva.

**Rawls (1971):** Policies auto-geradas NÃO são ativadas automaticamente. O princípio
do véu de ignorância exige que toda regra passe por blind testing antes de afetar
agentes. `enabled: false` + `requires_review: true` garante este contrato.

**Levinas (1961):** O rosto do Outro (o agente de IA afetado) exige que não
apliquemos punição sem processo. O bridge gera drafts, não sentenças.

## Consequências

- **Positivas:** Intelligence Hub deixa de ser catálogo inerte. Threats alimentam defesas.
- **Negativas:** Requer processo humano de review. Policies acumulam se não revisadas.
- **Futuro:** v2.2 — webhook notifica equipe quando há policies pendentes de review.

## Referências

- ADR-020 (Intelligence Hub)
- ADR-012 (PolicyEngine)
- `python/buildtovalue/intelligence/policy_generator.py`