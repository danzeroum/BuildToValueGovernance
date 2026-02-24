# ADR-041: Observability v2.0 — Métricas da República Algorítmica

**Status:** 🆕 PROPOSTO
**Data:** 24 de fevereiro de 2026
**Autores:** IA Arquiteta (Claude Sonnet 4.6) — validado por Staff Engineer
**Versão alvo:** v1.9.0
**Grupo:** F — API & Observability
**Estende:** ADR-019 (Observability v1.9 — ativo)
**Depende de:** ADR-036 (Bias Guardian), ADR-037 (AppealEngine), ADR-038 (EthicalContextEngine v4.0), ADR-039 (TrustScore v2.0)

**Impacto:**
```
rust/gateway/src/state.rs                        — + 8 novas métricas Rust
python/buildtovalue/observability/metrics.py     — + 6 novas métricas Python
ops/grafana/dashboards/republic_dashboard.json   — novo dashboard
ops/prometheus-rules.yaml                        — + 5 alerting rules
```

---

## 1. Contexto

### 1.1 Gap de observabilidade

O ADR-019 cobre métricas operacionais do sistema (latência, findings, hard blocks). Após os ADRs 036–040, a República Algorítmica tem quatro poderes distintos — mas só o Executivo (Rust kernel) é instrumentado adequadamente. Os outros três são caixas-pretas:

| Poder | Métricas existentes | Gap |
|:---|:---|:---|
| Executivo (Kernel) | `btv_kernel_scan_duration_seconds{module}`, `btv_kernel_findings_total` | Coberto |
| Judiciário (EthicalContextEngine) | `buildtovalue_decisions_total{action}` | Sem breakdown por estágio filosófico |
| Auditivo (Ledger + Appeals) | `buildtovalue_appeals_submitted_total` | Sem SLA compliance rate como gauge |
| Legislativo (BiasDeclaration) | Ausente | Nenhuma métrica de divergência |

### 1.2 Princípio de Jonas aplicado a métricas

Se `BiasDeclaration` é a responsabilidade declarada do sistema, então a **divergência entre declarado e medido** (ADR-036) deve ser visível em tempo real. Uma BiasDeclaration de `FNR=18%` com medição de `26.7%` é um risco operacional — e deve ser visível no mesmo dashboard que a latência.

---

## 2. Decisão

### 2.1 Catálogo completo de métricas v2.0

#### Família 1 — Pipeline Filosófico (Python, novo)

```python
# python/buildtovalue/observability/metrics.py — adições v2.0

from prometheus_client import Counter, Histogram, Gauge

# ── Estágios do pipeline (ADR-038) ────────────────────────────

PIPELINE_STAGE_DURATION = Histogram(
    "btv_pipeline_stage_duration_seconds",
    "Duração de cada estágio filosófico do EthicalContextEngine",
    ["stage"],   # rawls | levinas | jonas | gilligan
    buckets=[0.0001, 0.0005, 0.001, 0.005, 0.010, 0.025, 0.050],
)

PIPELINE_STAGE_MODIFICATIONS = Counter(
    "btv_pipeline_stage_modifications_total",
    "Vezes em que cada estágio modificou a ação de entrada",
    ["stage", "from_action", "to_action"],
)

PIPELINE_ANOMALIES_TOTAL = Counter(
    "btv_pipeline_anomalies_total",
    "Anomalias detectadas pelo estágio Rawls (inconsistência policy/evidence)",
    ["anomaly_type"],   # "allow_high_risk" | "block_zero_findings"
)

# ── Misericórdia — Gilligan (ADR-003/038) ─────────────────────

MERCY_SCENARIO_TOTAL = Counter(
    "btv_mercy_scenario_total",
    "Aplicações de mercy por cenário calibrado",
    ["scenario"],  # S1_CRITICAL_OVERRIDE ... S6_DEFAULT_NO_MERCY
)

MERCY_DOWNGRADE_LEVELS = Histogram(
    "btv_mercy_downgrade_levels",
    "Níveis de downgrade aplicados pela misericórdia",
    buckets=[0, 1, 2],
)

# ── Trust Score (ADR-039) ─────────────────────────────────────

TRUST_SCORE_ADJUSTMENTS = Counter(
    "btv_trust_score_adjustments_total",
    "Ajustes de trust score por origem",
    ["source", "direction"],  # source: appeal_accepted|appeal_rejected, direction: up|down
)

TRUST_SCORE_DISTRIBUTION = Histogram(
    "btv_trust_score_distribution",
    "Distribuição de trust scores no momento da decisão",
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95],
)
```

#### Família 2 — Contestabilidade e SLA (Python, novo)

```python
# ── AppealEngine (ADR-037) ────────────────────────────────────

APPEAL_SLA_COMPLIANCE_RATE = Gauge(
    "btv_appeal_sla_compliance_rate",
    "Taxa de compliance com SLA 24h (0.0–1.0). "
    "Abaixo de 0.95 dispara alerta.",
)

APPEAL_STATUS_CURRENT = Gauge(
    "btv_appeal_status_current",
    "Número atual de appeals por status",
    ["status"],  # pending | under_review | accepted | rejected | expired
)

APPEAL_RESOLUTION_DURATION = Histogram(
    "btv_appeal_resolution_duration_seconds",
    "Tempo entre submissão e resolução de appeals",
    buckets=[
        3600,     # 1h
        7200,     # 2h
        14400,    # 4h
        28800,    # 8h
        43200,    # 12h
        86400,    # 24h (SLA limite)
        172800,   # 48h (violação grave)
    ],
)

SLA_BREACH_TOTAL = Counter(
    "btv_appeal_sla_breach_total",
    "Total de violações do SLA 24h de contestação. "
    "Jonas: cada violação é responsabilidade auditável.",
)
```

#### Família 3 — Bias Guardian (Python, novo)

```python
# ── BiasDeclaration Divergence (ADR-036) ─────────────────────

BIAS_DIVERGENCE_PP = Gauge(
    "btv_bias_divergence_pp",
    "Divergência atual em pontos percentuais: medido − declarado",
    ["module", "metric"],  # metric: fnr | fpr
)

BIAS_DECLARATION_STATUS = Gauge(
    "btv_bias_declaration_status",
    "Status da BiasDeclaration por módulo: 0=ok, 1=warning, 2=block",
    ["module"],
)

BIAS_CALIBRATION_AGE_DAYS = Gauge(
    "btv_bias_calibration_age_days",
    "Dias desde a última calibração de cada módulo",
    ["module"],
)
```

#### Família 4 — Métricas Rust novas (Gateway, adição em `state.rs`)

```rust
// rust/gateway/src/state.rs — lazy_static! additions

pub static ref PIPELINE_LATENCY_MS: HistogramVec = register_histogram_vec!(
    HistogramOpts::new(
        "btv_pipeline_latency_ms",
        "Latência por segmento do pipeline end-to-end"
    ).buckets(vec![0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 50.0]),
    &["segment"]   // kernel | governance | ledger | total
).unwrap();

pub static ref JURISDICTION_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
    opts!(
        "btv_jurisdiction_requests_total",
        "Requests por jurisdição declarada (X-BTV-Jurisdiction)"
    ),
    &["jurisdiction"]  // BR | US | EU | UK | undeclared
).unwrap();

pub static ref TENANT_DECISIONS_TOTAL: IntCounterVec = register_int_counter_vec!(
    opts!(
        "btv_tenant_decisions_total",
        "Decisões por tenant tier (hash anonimizado)"
    ),
    &["tier", "action"]  // tier: free | standard | enterprise
).unwrap();
```

### 2.2 Instrumentação do EthicalContextEngine

```python
# python/buildtovalue/governance/context_engine.py — adições

import time
from buildtovalue.observability.metrics import (
    PIPELINE_STAGE_DURATION,
    PIPELINE_STAGE_MODIFICATIONS,
    PIPELINE_ANOMALIES_TOTAL,
    MERCY_SCENARIO_TOTAL,
    TRUST_SCORE_DISTRIBUTION,
)

class EthicalContextEngine:
    def decide(self, evidence, context) -> EthicalVerdict:
        # ...
        t0 = time.perf_counter()

        r1 = self._rawls.evaluate(evidence, context)
        PIPELINE_STAGE_DURATION.labels("rawls").observe(time.perf_counter() - t0)
        if r1.anomaly_detected:
            for a in r1.metadata.get("anomalies", []):
                PIPELINE_ANOMALIES_TOTAL.labels(
                    "allow_high_risk" if "ALLOW" in a else "block_zero_findings"
                ).inc()

        t1 = time.perf_counter()
        r2 = self._levinas.evaluate(evidence, context, r1)
        PIPELINE_STAGE_DURATION.labels("levinas").observe(time.perf_counter() - t1)
        if r2.modified:
            PIPELINE_STAGE_MODIFICATIONS.labels(
                "levinas", r2.action_in, r2.action_out
            ).inc()

        t2 = time.perf_counter()
        r3 = self._jonas.evaluate(evidence, context, r2)
        PIPELINE_STAGE_DURATION.labels("jonas").observe(time.perf_counter() - t2)
        if r3.modified:
            PIPELINE_STAGE_MODIFICATIONS.labels(
                "jonas", r3.action_in, r3.action_out
            ).inc()

        t3 = time.perf_counter()
        r4 = self._gilligan.evaluate(evidence, context, r3)
        PIPELINE_STAGE_DURATION.labels("gilligan").observe(time.perf_counter() - t3)
        MERCY_SCENARIO_TOTAL.labels(r4.mercy_scenario).inc()

        trust = self._trust_scores.get(context.session_id, 0.5)
        TRUST_SCORE_DISTRIBUTION.observe(trust)
        # ...
```

### 2.3 Instrumentação do AppealEngine

```python
# python/buildtovalue/governance/appeal_engine.py — adições

from buildtovalue.observability.metrics import (
    APPEAL_SLA_COMPLIANCE_RATE,
    APPEAL_STATUS_CURRENT,
    APPEAL_RESOLUTION_DURATION,
    SLA_BREACH_TOTAL,
    TRUST_SCORE_ADJUSTMENTS,
)

class AppealEngine:
    def resolve(self, appeal_id, accepted, reviewer_id, reviewer_notes):
        record = self._get_or_raise(appeal_id)
        # ... lógica existente ...

        # Métricas de resolução
        duration = record.resolved_at - record.request.submitted_at
        APPEAL_RESOLUTION_DURATION.observe(duration)

        direction = "up" if accepted else "down"
        source = "appeal_accepted" if accepted else "appeal_rejected"
        TRUST_SCORE_ADJUSTMENTS.labels(source, direction).inc()

        self._refresh_status_gauges()
        return record

    def expire_overdue(self) -> list[str]:
        expired = []
        # ... lógica existente ...
        for appeal_id in expired:
            SLA_BREACH_TOTAL.inc()
        self._refresh_status_gauges()
        return expired

    def _refresh_status_gauges(self):
        """Atualiza gauges de status após qualquer mutação."""
        from collections import Counter as C
        counts = C(r.status.value for r in self._records.values())
        for status in ("pending", "under_review", "accepted", "rejected", "expired"):
            APPEAL_STATUS_CURRENT.labels(status).set(counts.get(status, 0))

        metrics = self.get_metrics()
        APPEAL_SLA_COMPLIANCE_RATE.set(metrics["sla_compliance_rate"])
```

### 2.4 Instrumentação do BiasGuardian

```python
# python/buildtovalue/governance/bias_guardian.py — adições

from buildtovalue.observability.metrics import (
    BIAS_DIVERGENCE_PP,
    BIAS_DECLARATION_STATUS,
    BIAS_CALIBRATION_AGE_DAYS,
)

class BiasGuardian:
    def evaluate_suite(self) -> BiasGuardianSuiteResult:
        result = super_evaluate_suite()  # lógica existente

        # Atualiza métricas por módulo
        level_to_int = {"ok": 0, "warning": 1, "block": 2}
        for mr in result.module_reports:
            BIAS_DIVERGENCE_PP.labels(mr.module_id, "fnr").set(mr.fnr_divergence_pp)
            BIAS_DIVERGENCE_PP.labels(mr.module_id, "fpr").set(mr.fpr_divergence_pp)
            BIAS_DECLARATION_STATUS.labels(mr.module_id).set(
                level_to_int[mr.divergence_level.value]
            )
            BIAS_CALIBRATION_AGE_DAYS.labels(mr.module_id).set(mr.bias_expiry_days)

        return result
```

### 2.5 Alerting Rules (adição em `ops/prometheus-rules.yaml`)

```yaml
# ops/prometheus-rules.yaml — adições v2.0

groups:
  - name: republic_algorítmica_alerts
    interval: 30s
    rules:

      # ── SLA de contestação (Levinas) ───────────────────────
      - alert: AppealSLABreachRateHigh
        expr: btv_appeal_sla_compliance_rate < 0.95
        for: 5m
        labels:
          severity: critical
          power: judiciario
        annotations:
          summary: "SLA de contestação abaixo de 95%"
          description: >
            Taxa atual: {{ $value | humanizePercentage }}.
            LGPD Art. 20 e EU AI Act Art. 86 exigem resposta em 24h.
            Ethical Committee deve ser notificado imediatamente.

      # ── BiasDeclaration divergência (Jonas) ───────────────
      - alert: BiasDivergenceBlock
        expr: btv_bias_declaration_status == 2
        for: 1m
        labels:
          severity: critical
          power: executivo
        annotations:
          summary: "BiasDeclaration BLOQUEADA: {{ $labels.module }}"
          description: >
            Módulo {{ $labels.module }} declarou limitações inferiores
            às medidas pelo red-team. BiasDeclaration deve ser atualizada
            antes do próximo deploy (Jonas: responsabilidade proporcional).

      - alert: BiasDivergenceWarning
        expr: btv_bias_declaration_status == 1
        for: 15m
        labels:
          severity: warning
          power: executivo
        annotations:
          summary: "BiasDeclaration AVISO: {{ $labels.module }}"
          description: >
            Divergência de {{ $value }}pp acima do threshold de aviso.
            Atualização obrigatória em 14 dias.

      # ── Calibração expirada (Jonas) ───────────────────────
      - alert: BiasCalibrationExpired
        expr: btv_bias_calibration_age_days > 90
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Calibração expirada: {{ $labels.module }} ({{ $value }}d)"
          description: >
            BiasDeclaration de {{ $labels.module }} expirada.
            Último red-team: {{ $value }} dias atrás (limite: 90d).

      # ── Pipeline filosófico lento (ADR-038) ──────────────
      - alert: PipelineStageSlow
        expr: >
          histogram_quantile(0.99,
            rate(btv_pipeline_stage_duration_seconds_bucket[5m])
          ) > 0.008
        for: 5m
        labels:
          severity: warning
          power: judiciario
        annotations:
          summary: "Estágio {{ $labels.stage }} lento (p99 > 8ms)"
          description: >
            O estágio filosófico {{ $labels.stage }} está consumindo
            mais de 8ms p99. Budget total do Judiciário: 10ms.

      # ── Hard blocks anômalos ──────────────────────────────
      - alert: HardBlockSpikeDetected
        expr: rate(btv_hard_blocks_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
          power: executivo
        annotations:
          summary: "Spike de hard blocks: > 10/min"
          description: >
            Taxa de hard blocks acima de 10/min nos últimos 5 minutos.
            Possível ataque coordenado. Verificar logs de auditoria.
```

### 2.6 Dashboard Grafana — República Algorítmica

```
ops/grafana/dashboards/republic_dashboard.json
```

O dashboard é organizado em 4 linhas correspondentes aos 4 poderes, mais 1 linha de SLA global:

```
┌─────────────────────────────────────────────────────────────────┐
│  REPÚBLICA ALGORÍTMICA — Dashboard de Saúde                      │
├──────────────────────────────────┬──────────────────────────────┤
│  ROW 1: EXECUTIVO (Kernel)       │                              │
│  • btv_kernel_scan_duration p99  │  • btv_decisions_total       │
│  • btv_kernel_findings_total     │  • btv_hard_blocks_total      │
│  • Latência por segment          │  • btv_jurisdiction_requests │
├──────────────────────────────────┴──────────────────────────────┤
│  ROW 2: JUDICIÁRIO (Pipeline Filosófico)                         │
│  • Stage duration p50/p99 (rawls|levinas|jonas|gilligan)        │
│  • btv_mercy_scenario_total (barras por cenário S1-S6)          │
│  • btv_pipeline_anomalies_total  • btv_trust_score_distribution │
├─────────────────────────────────────────────────────────────────┤
│  ROW 3: AUDITIVO (Appeals + SLA)                                 │
│  • btv_appeal_sla_compliance_rate (gauge vermelho/verde)        │
│  • btv_appeal_status_current (stacked: pending/resolved)        │
│  • btv_appeal_resolution_duration_seconds histogram             │
│  • btv_appeal_sla_breach_total                                  │
├─────────────────────────────────────────────────────────────────┤
│  ROW 4: LEGISLATIVO (BiasDeclaration)                            │
│  • btv_bias_divergence_pp{module, metric} (heatmap)             │
│  • btv_bias_declaration_status (traffic light por módulo)       │
│  • btv_bias_calibration_age_days (timeline)                     │
├─────────────────────────────────────────────────────────────────┤
│  ROW 5: SLA GLOBAL                                               │
│  • End-to-end p99 < 50ms (SLA contratual)                       │
│  • Appeal SLA compliance rate > 95%                             │
│  • BiasDeclaration violations = 0                               │
└─────────────────────────────────────────────────────────────────┘
```

### 2.7 Invariantes de observabilidade

| Invariante | Valor | Justificativa |
|:---|:---|:---|
| Nenhuma métrica contém PII | Obrigatório | `session_id` nunca é label — apenas hashes |
| Overhead por request | < 0.5ms | Consistente com ADR-019 |
| Gauges de appeal status | Atualizados após toda mutação | `_refresh_status_gauges()` em `resolve()` e `expire_overdue()` |
| `btv_bias_declaration_status` | Atualizado a cada `evaluate_suite()` | Chamado a cada deploy + cron semanal |
| Alertas críticos | PagerDuty/webhook (via ADR-026) | Configuração em `ops/alertmanager.yml` |

---

## 3. Fundamentos Filosóficos

**Jonas (Responsabilidade Pública):** cada métrica do Bias Guardian (`btv_bias_divergence_pp`, `btv_bias_declaration_status`) torna visível a distância entre o que o sistema declara ser e o que é medido. A observabilidade é a forma computacional do princípio "age de modo que os efeitos de tua ação sejam compatíveis com a permanência de uma vida humana genuína."

**Rawls (Transparência Procedimental):** o dashboard expõe os 4 poderes com igual destaque. Não há dashboard privilegiado para o Executivo — o Judiciário, o Auditivo e o Legislativo recebem visibilidade equivalente.

**Levinas (SLA como Dever):** `btv_appeal_sla_compliance_rate` é um Gauge que alerta abaixo de 0.95. O SLA de 24h não é aspiracional — é um dever mensurável em tempo real.

---

## 4. Consequências

### Positivas

Auditores externos (LGPD/EU AI Act) podem verificar compliance operacional consultando uma única URL (`/metrics` + Grafana). O pipeline filosófico deixa de ser uma caixa-preta: cada estágio tem latência e modificações documentadas. Spikes em `btv_mercy_scenario_total{scenario="S1_CRITICAL_OVERRIDE"}` indicam aumento de ataques; spikes em `S2_HIGH_TRUST_VETERAN` indicam usuários legítimos sendo agraciados.

### Negativas e Trade-offs

`_refresh_status_gauges()` é chamado após toda mutação de appeal — em alta carga isso significa O(n) sobre todos os records a cada resolução. Mitigado: a operação é um `Counter` de dict em memória, não uma query SQL. Para v2.0+ com volume alto, converter para atomic counters incrementais.

O dashboard JSON (`republic_dashboard.json`) deve ser versionado e testado no CI via `grafana-dashboard-validator` — sem validação, panels quebram silenciosamente com mudanças de nome de métrica.

---

## 5. Testes Obrigatórios

```
[ ] PIPELINE_STAGE_DURATION.labels("rawls") incrementa após decide()
[ ] PIPELINE_STAGE_DURATION.labels("gilligan") incrementa após decide()
[ ] MERCY_SCENARIO_TOTAL.labels("S1_CRITICAL_OVERRIDE") incrementa em critical
[ ] MERCY_SCENARIO_TOTAL.labels("S2_HIGH_TRUST_VETERAN") incrementa com trust=0.9
[ ] APPEAL_SLA_COMPLIANCE_RATE é atualizado após resolve()
[ ] APPEAL_STATUS_CURRENT{pending} decresce após resolve()
[ ] SLA_BREACH_TOTAL incrementa após expire_overdue()
[ ] BIAS_DIVERGENCE_PP é setado após evaluate_suite()
[ ] BIAS_DECLARATION_STATUS{module} = 2 para divergência > block_threshold
[ ] Nenhuma métrica contém session_id ou user_id em labels
[ ] Overhead de instrumentação: < 0.5ms por request (benchmark)
[ ] prometheus-rules.yaml é válido (promtool check rules)
[ ] Alert AppealSLABreachRateHigh dispara com rate < 0.94
[ ] Alert BiasDivergenceBlock dispara com status == 2
 iteração:** ADR-042 (W3C Distributed Tracing — trace context propagado do Gateway Rust até o EthicalContextEngine Python, conectando `verdict_id` ao `trace_id` para auditoria forense end-to-end), que completa o pilar de observabilidade antes do OSS release.
```