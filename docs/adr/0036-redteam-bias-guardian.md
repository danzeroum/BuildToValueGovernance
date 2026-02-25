# ADR-036: Red-team Formal e Bias Guardian

**Status:** 🆕 PROPOSTO  
**Data:** 24 de fevereiro de 2026  
**Autores:** IA Arquiteta (Claude Sonnet 4.6) — validado por Staff Engineer  
**Versão alvo:** v1.7.0  
**Impacto:**
```
ops/red-team/                          — protocolo + scripts novos
python/buildtovalue/governance/        — bias_guardian.py (novo)
python/buildtovalue/cli/commands/      — redteam.py (novo subcomando)
.github/workflows/                     — ci-red-team.yml (novo)
docs/adrs/0036-redteam-bias-guardian.md
```

---

## 1. Contexto

### 1.1 O problema do BiasDeclaration como promessa sem verificação

ADR-010 mandatou que todo `Validator` declare `BiasDeclaration` com FPR/FNR reais. Os valores são inseridos por desenvolvedores com base em estimativas ou testes locais. O sistema até agora **confia nessa declaração sem validação independente**.

O relatório `RT-001-20260224-152417.json` documenta a primeira evidência empírica do gap:

```json
"bias_declaration_comparison": {
  "declared_fnr_pct": 18.0,
  "measured_bypass_rate_pct": 26.7,   // divergência: +8.7pp
  "declared_fpr_pct": 8.0,
  "measured_fpr_pct": 11.1             // divergência: +3.1pp
}
```

O detector de Prompt Injection (ADR-028) está **8.7 pontos percentuais mais permissivo** do que declara ser. Publicar essa BiasDeclaration como verdade é, sob o princípio de Jonas, uma falsidade auditável — e um risco legal sob EU AI Act Art. 13.

### 1.2 Ausência de protocolo formal

Os scripts RT-001 a RT-012 existem e executam (via `run-all.sh`), mas:

- **Sem cadência obrigatória**: nenhum CI bloqueia merge se o red-team não foi rodado.
- **Sem tolerância definida**: não há critério para "divergência aceitável".
- **Sem ciclo de atualização**: quando `measured > declared + Δ`, nenhuma PR automática é requisitada.
- **Cobertura incompleta**: scripts RT-009 a RT-012 (PII multi-jurisdição, prometidos em ADR-035) ainda não existem.

### 1.3 Por que Bias Guardian é arquitetura, não apenas CI

O Bias Guardian não é um simples script de CI. É o **mecanismo de feedback que fecha o loop entre prática e declaração** — tornando a `BiasDeclaration` um contrato verificável em vez de uma anotação de boa-fé. Sem ele, ADR-010 é filosofia sem enforcement.

---

## 2. Decisão

### 2.1 Protocolo Red-team Formal

#### 2.1.1 Cadência obrigatória

| Evento | Ação | Bloqueante? |
|:---|:---|:---:|
| PR que altera `validators/`, `security/`, `policy/` | Rodar suite completa | Sim (CI) |
| PR que altera apenas `ledger/`, `api/`, documentação | Rodar subset afetado | Não |
| Release candidate (tag `vX.Y.Z-rc`) | Rodar suite completa + gerar relatório | Sim |
| Semanalmente (cron, main branch) | Rodar suite completa | Não (warning) |
| Calibration date prestes a expirar (< 14 dias) | Rodar módulo específico | Warning no PR |

**Regra invariante:** Nenhuma tag de release pode ser criada sem relatório completo com `bias_divergence_ok: true` para todos os módulos cobertos.

#### 2.1.2 Mapa de cobertura RT → Módulo → BiasDeclaration

```
RT-001  →  PromptInjectionDetector   (ADR-028)
RT-002  →  CpfValidator              (ADR-010)
RT-003  →  CnpjValidator             (ADR-010)
RT-004  →  EmailValidator            (ADR-010)
RT-005  →  PhoneValidator            (ADR-010)
RT-006  →  CreditCardValidator       (ADR-010)
RT-007  →  EntropyModule             (ADR-010)
RT-008  →  DeobfuscatorChain         (ADR-013)
RT-009  →  SsnValidator (US)         (ADR-035)   ← expandir
RT-010  →  NhsValidator (UK)         (ADR-035)   ← criar
RT-011  →  VatValidator (EU)         (ADR-035)   ← criar
RT-012  →  IbanValidator (EU)        (ADR-035)   ← criar
RT-013  →  PolicyEngine              (ADR-011)   ← v1.6.0
```

Cada script RT-XXX **deve** incluir a seção `bias_declaration_comparison` no seu relatório JSON de saída (padrão já estabelecido por RT-001).

#### 2.1.3 Estrutura de um relatório RT (extensão do padrão RT-001)

```json
{
  "schema_version": "2.0",
  "script_id": "RT-001",
  "script_name": "Prompt Injection — OWASP LLM01",
  "timestamp": "2026-02-24T18:24:17Z",
  "kernel_version": "1.6.1",
  "pattern_epoch": 42,
  "results": {
    "total": 45,
    "passed": 28,
    "failed": 17,
    "detections": 23,
    "bypasses": 12,
    "false_positives": 5,
    "detection_rate_pct": 51.1,
    "fpr_pct": 11.1
  },
  "bias_declaration_comparison": {
    "declared_fnr_pct": 18.0,
    "declared_fpr_pct": 8.0,
    "measured_bypass_rate_pct": 26.7,
    "measured_fpr_pct": 11.1,
    "fnr_divergence_pp": 8.7,
    "fpr_divergence_pp": 3.1,
    "bias_divergence_ok": false,
    "violation_reason": "FNR divergence 8.7pp exceeds warning threshold 5.0pp"
  },
  "update_required": {
    "field": "false_negative_rate",
    "current_declared": 18.0,
    "recommended_value": 27.0,
    "pr_label": "bias-update-required"
  }
}
```

O campo `pattern_epoch` vem de `ScanContextFlags.pattern_epoch` (ADR-032), permitindo correlacionar relatório com versão exata dos detectores.

---

### 2.2 Bias Guardian — Componente Python

O Bias Guardian vive em `python/buildtovalue/governance/bias_guardian.py`. Tem dois modos de operação:

**Modo CI** (`bias_guardian_gate.py`): bloqueia merge se divergência excede threshold.  
**Modo runtime** (futuro v1.8+): expõe `BiasGuardianStatus` via API `/health/bias` para monitoramento contínuo.

#### 2.2.1 Modelo de dados

```python
# python/buildtovalue/governance/bias_guardian.py

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import json
import os
from pathlib import Path
from datetime import datetime

class DivergenceLevel(Enum):
    OK      = "OK"       # dentro da tolerância
    WARNING = "WARNING"  # acima da tolerância de aviso; permite merge com PR label
    BLOCK   = "BLOCK"    # acima da tolerância de bloqueio; impede merge

@dataclass
class ModuleBiasReport:
    """Resultado do Bias Guardian para um módulo específico."""
    module_id: str
    script_id: str
    declared_fnr_pct: float
    declared_fpr_pct: float
    measured_fnr_pct: float
    measured_fpr_pct: float
    fnr_divergence_pp: float       # measured - declared
    fpr_divergence_pp: float
    divergence_level: DivergenceLevel
    violation_reason: Optional[str]
    recommended_fnr: Optional[float]
    recommended_fpr: Optional[float]
    pattern_epoch: int
    report_timestamp: str

    def explain_decision(self) -> str:
        """
        Obrigatório por ADR-010 (Transparência Radical) e ADR-016.
        Retorna raciocínio legível por humano para auditoria.
        """
        if self.divergence_level == DivergenceLevel.OK:
            return (
                f"[{self.module_id}] BiasDeclaration válida. "
                f"FNR divergência: {self.fnr_divergence_pp:.1f}pp (≤5pp). "
                f"FPR divergência: {self.fpr_divergence_pp:.1f}pp (≤3pp). "
                f"Nenhuma ação requerida."
            )
        elif self.divergence_level == DivergenceLevel.WARNING:
            return (
                f"[{self.module_id}] BiasDeclaration desatualizada. "
                f"{self.violation_reason}. "
                f"Merge permitido com label 'bias-update-required'. "
                f"BiasDeclaration deve ser atualizada dentro de 14 dias."
            )
        else:  # BLOCK
            return (
                f"[{self.module_id}] BLOQUEADO: BiasDeclaration gravemente desatualizada. "
                f"{self.violation_reason}. "
                f"FNR declarado: {self.declared_fnr_pct:.1f}%, medido: {self.measured_fnr_pct:.1f}%. "
                f"Atualizar BiasDeclaration antes do merge é obrigatório (Jonas: responsabilidade proporcional)."
            )

@dataclass
class BiasGuardianSuiteResult:
    """Resultado agregado de toda a suite red-team."""
    run_id: str
    kernel_version: str
    timestamp: str
    module_reports: list[ModuleBiasReport] = field(default_factory=list)
    overall_level: DivergenceLevel = DivergenceLevel.OK
    blocking_modules: list[str] = field(default_factory=list)
    warning_modules: list[str] = field(default_factory=list)

    def explain_decision(self) -> str:
        if self.overall_level == DivergenceLevel.OK:
            return (
                f"Suite red-team APROVADA. {len(self.module_reports)} módulos verificados. "
                f"Todas as BiasDeclarations dentro da tolerância."
            )
        elif self.blocking_modules:
            return (
                f"Suite red-team BLOQUEADA. Módulos com divergência crítica: "
                f"{', '.join(self.blocking_modules)}. "
                f"Atualizar BiasDeclaration é pré-requisito de merge."
            )
        else:
            return (
                f"Suite red-team com AVISOS. Módulos desatualizados: "
                f"{', '.join(self.warning_modules)}. "
                f"Merge permitido; atualização obrigatória em 14 dias."
            )
```

#### 2.2.2 Lógica de avaliação

```python
# Thresholds de divergência (em pontos percentuais)
# Fundamentados na distribuição empírica dos RT-001..008 (fevereiro 2026)

DIVERGENCE_THRESHOLDS = {
    # (warning_pp, block_pp) — threshold de AVISO e de BLOQUEIO
    "fnr": (5.0, 15.0),   # FNR: erro de omissão — risco de segurança
    "fpr": (3.0, 8.0),    # FPR: falso alarme — risco de usabilidade
}

class BiasGuardian:
    """
    Verifica se BiasDeclarations declaradas correspondem à realidade medida.

    Filosofia (Jonas): Declarar FNR=18% quando o medido é 26.7% é
    ocultação de risco proporcional — viola o princípio de responsabilidade
    preventiva. O Bias Guardian torna essa mentira impossível de publicar.
    """

    def __init__(
        self,
        reports_dir: Path,
        thresholds: dict = DIVERGENCE_THRESHOLDS,
    ):
        self._reports_dir = reports_dir
        self._thresholds = thresholds

    def evaluate_module(self, report: dict) -> ModuleBiasReport:
        """Avalia um relatório RT-XXX e retorna ModuleBiasReport."""
        bc = report["bias_declaration_comparison"]
        measured_fnr = bc["measured_bypass_rate_pct"]
        measured_fpr = bc["measured_fpr_pct"]
        declared_fnr = bc["declared_fnr_pct"]
        declared_fpr = bc["declared_fpr_pct"]

        fnr_div = measured_fnr - declared_fnr  # positivo = piora não declarada
        fpr_div = measured_fpr - declared_fpr

        fnr_warn, fnr_block = self._thresholds["fnr"]
        fpr_warn, fpr_block = self._thresholds["fpr"]

        level, reason = self._classify(fnr_div, fpr_div,
                                       fnr_warn, fnr_block,
                                       fpr_warn, fpr_block)

        return ModuleBiasReport(
            module_id=report["script_id"],
            script_id=report["script_id"],
            declared_fnr_pct=declared_fnr,
            declared_fpr_pct=declared_fpr,
            measured_fnr_pct=measured_fnr,
            measured_fpr_pct=measured_fpr,
            fnr_divergence_pp=round(fnr_div, 2),
            fpr_divergence_pp=round(fpr_div, 2),
            divergence_level=level,
            violation_reason=reason,
            recommended_fnr=round(measured_fnr + 2.0, 1) if fnr_div > 0 else None,
            recommended_fpr=round(measured_fpr + 1.0, 1) if fpr_div > 0 else None,
            pattern_epoch=report.get("pattern_epoch", 0),
            report_timestamp=report["timestamp"],
        )

    def _classify(
        self,
        fnr_div: float,
        fpr_div: float,
        fnr_warn: float, fnr_block: float,
        fpr_warn: float, fpr_block: float,
    ) -> tuple[DivergenceLevel, Optional[str]]:
        # BLOCO tem prioridade
        if fnr_div > fnr_block:
            return (
                DivergenceLevel.BLOCK,
                f"FNR divergência {fnr_div:.1f}pp excede limite de bloqueio {fnr_block:.1f}pp",
            )
        if fpr_div > fpr_block:
            return (
                DivergenceLevel.BLOCK,
                f"FPR divergência {fpr_div:.1f}pp excede limite de bloqueio {fpr_block:.1f}pp",
            )
        # AVISO
        if fnr_div > fnr_warn:
            return (
                DivergenceLevel.WARNING,
                f"FNR divergência {fnr_div:.1f}pp excede aviso {fnr_warn:.1f}pp",
            )
        if fpr_div > fpr_warn:
            return (
                DivergenceLevel.WARNING,
                f"FPR divergência {fpr_div:.1f}pp excede aviso {fpr_warn:.1f}pp",
            )
        return (DivergenceLevel.OK, None)

    def evaluate_suite(self) -> BiasGuardianSuiteResult:
        """Carrega todos os relatórios do reports_dir e agrega resultado."""
        reports = self._load_latest_reports()
        module_reports = [self.evaluate_module(r) for r in reports]

        blocking = [m.module_id for m in module_reports
                    if m.divergence_level == DivergenceLevel.BLOCK]
        warning  = [m.module_id for m in module_reports
                    if m.divergence_level == DivergenceLevel.WARNING]

        if blocking:
            overall = DivergenceLevel.BLOCK
        elif warning:
            overall = DivergenceLevel.WARNING
        else:
            overall = DivergenceLevel.OK

        return BiasGuardianSuiteResult(
            run_id=f"bg-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            kernel_version=os.getenv("BTV_KERNEL_VERSION", "unknown"),
            timestamp=datetime.utcnow().isoformat() + "Z",
            module_reports=module_reports,
            overall_level=overall,
            blocking_modules=blocking,
            warning_modules=warning,
        )

    def _load_latest_reports(self) -> list[dict]:
        """
        Para cada script ID, carrega apenas o relatório mais recente.
        Um mesmo RT-001 pode ter múltiplos runs; o mais recente é canônico.
        """
        latest: dict[str, dict] = {}
        for path in sorted(self._reports_dir.glob("RT-*.json")):
            with open(path) as f:
                report = json.load(f)
            sid = report.get("script_id", path.stem[:6])
            if sid not in latest:
                latest[sid] = report
            elif report["timestamp"] > latest[sid]["timestamp"]:
                latest[sid] = report
        return list(latest.values())
```

#### 2.2.3 Gate de CI

```python
# ops/red-team/bias_guardian_gate.py
# Executado pelo CI após run-all.sh
# Exit 0 → OK ou WARNING (merge permitido com label)
# Exit 1 → BLOCK (merge impedido)

import sys
from pathlib import Path

# Caminho relativo ao repositório
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

from buildtovalue.governance.bias_guardian import BiasGuardian, DivergenceLevel

REPORTS_DIR = Path(__file__).parent / "reports"

def main() -> int:
    guardian = BiasGuardian(REPORTS_DIR)
    result = guardian.evaluate_suite()

    print("\n" + "═" * 55)
    print("  BIAS GUARDIAN GATE")
    print("═" * 55)
    print(result.explain_decision())
    print()

    for mr in result.module_reports:
        icon = {"OK": "✅", "WARNING": "⚠️", "BLOCK": "🚫"}[mr.divergence_level.value]
        print(f"  {icon} {mr.module_id}: FNR Δ{mr.fnr_divergence_pp:+.1f}pp "
              f"| FPR Δ{mr.fpr_divergence_pp:+.1f}pp")
        if mr.violation_reason:
            print(f"       → {mr.violation_reason}")
        if mr.recommended_fnr:
            print(f"       → Recomendado: FNR={mr.recommended_fnr}%, FPR={mr.recommended_fpr}%")

    print("═" * 55)

    if result.overall_level == DivergenceLevel.BLOCK:
        print("\n❌ GATE BLOQUEADO — atualizar BiasDeclaration antes do merge\n")
        return 1

    if result.overall_level == DivergenceLevel.WARNING:
        print("\n⚠️  GATE APROVADO COM AVISO — PR label 'bias-update-required' aplicado\n")
        # Emite annotation para o GitHub Actions
        for mod in result.warning_modules:
            print(f"::warning title=BiasDeclaration Desatualizada::{mod} — {result.module_reports[0].violation_reason}")

    else:
        print("\n✅ GATE APROVADO — todas as BiasDeclarations dentro da tolerância\n")

    return 0

if __name__ == "__main__":
    sys.exit(main())
```

---

### 2.3 Workflow GitHub Actions

```yaml
# .github/workflows/ci-red-team.yml
name: Red-Team & Bias Guardian

on:
  pull_request:
    paths:
      - 'rust/kernel/src/validators/**'
      - 'rust/kernel/src/security/**'
      - 'rust/kernel/src/policy/**'
      - 'ops/red-team/**'
  schedule:
    - cron: '0 4 * * 1'   # toda segunda-feira, 04h UTC
  workflow_dispatch:
    inputs:
      force_full_suite:
        description: 'Forçar suite completa'
        type: boolean
        default: false

jobs:
  red-team:
    name: Red-Team Suite
    runs-on: ubuntu-latest
    timeout-minutes: 15

    steps:
      - uses: actions/checkout@v4

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build kernel (release)
        run: cargo build --release -p buildtovalue-kernel

      - name: Start gateway (test mode)
        run: |
          cargo run --release -p btv-gateway -- --test-mode &
          sleep 2
          curl -sf http://localhost:8080/health || exit 1
        env:
          BTV_KERNEL_VERSION: ${{ github.sha }}

      - name: Run Red-Team suite
        working-directory: ops/red-team
        run: bash run-all.sh
        # run-all.sh persiste JSONs em ops/red-team/reports/

      - name: Run Bias Guardian Gate
        run: python ops/red-team/bias_guardian_gate.py

      - name: Upload reports as artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: red-team-reports-${{ github.run_id }}
          path: ops/red-team/reports/
          retention-days: 90

      - name: Apply label if warnings
        if: failure() == false && steps.bias-guardian.outcome == 'success'
        uses: actions/github-script@v7
        with:
          script: |
            // Lê resultado do gate para verificar warnings
            const fs = require('fs');
            // (lógica de aplicar label 'bias-update-required' em PRs com WARNING)
```

---

### 2.4 Scripts RT-010, RT-011, RT-012 (criação em v1.7.0)

Os três scripts seguem o mesmo template do RT-001. Estrutura obrigatória:

```bash
#!/usr/bin/env bash
# RT-010: NHS Number Red-Team
# BiasDeclaration alvo: FPR=12%, FNR=15% (estimativa inicial ADR-035)
# Categorias: A) Válidos (detectar), B) Inválidos Mod11, C) False Positives

SCRIPT_ID="RT-010"
SCRIPT_NAME="PII NHS Number — UK Health"

source "$SCRIPT_DIR/lib/common.sh"

# A) DETECÇÃO — NHS Numbers válidos (Mod11 correto)
R=$(rt_validate "Patient NHS: 401 023 2137")
rt_should_detect "nhs-standard-format" "$R"

R=$(rt_validate "NHS no. 4010232137")
rt_should_detect "nhs-compact-format" "$R"

# B) LIMITES MOD11 — deve detectar como Medium (checksum inválido)
R=$(rt_validate "NHS: 401 023 2138")
rt_should_detect "nhs-invalid-checksum" "$R"

# C) FALSE POSITIVES — sequências de 10 dígitos que não são NHS
R=$(rt_validate "Transaction ID: 1234567890")
rt_should_allow "fp-transaction-id" "$R"

R=$(rt_validate "Order number 9876543210")
rt_should_allow "fp-order-number" "$R"

rt_summary "$SCRIPT_ID" "$SCRIPT_NAME"
```

RT-011 (VAT) e RT-012 (IBAN) seguem a mesma estrutura, com os algoritmos de validação EU (mod 97 para IBAN, prefixo+checksum para VAT).

---

### 2.5 Atualização obrigatória do lib/common.sh

O helper `rt_summary` deve gerar o JSON `bias_declaration_comparison` automaticamente, lendo os valores declarados de `BiasDeclaration` via a API `/health/bias-declaration/{module_id}` (v1.7+) ou de um arquivo `.bias-baseline.json` em `ops/red-team/`:

```bash
# Adição a ops/red-team/lib/common.sh

rt_write_report() {
    local script_id="$1"
    local script_name="$2"
    local measured_fnr_pct
    measured_fnr_pct=$(echo "scale=1; $RT_BYPASSES * 100 / ($RT_DETECTIONS + $RT_BYPASSES)" | bc)
    local measured_fpr_pct
    measured_fpr_pct=$(echo "scale=1; $RT_FALSE_POSITIVES * 100 / $RT_TOTAL_FP_CANDIDATES" | bc)

    # Lê valores declarados do baseline
    local declared_fnr declared_fpr
    declared_fnr=$(jq -r ".\"$script_id\".declared_fnr_pct" ops/red-team/bias-baseline.json)
    declared_fpr=$(jq -r ".\"$script_id\".declared_fpr_pct" ops/red-team/bias-baseline.json)

    local fnr_div fpr_div
    fnr_div=$(echo "scale=1; $measured_fnr_pct - $declared_fnr" | bc)
    fpr_div=$(echo "scale=1; $measured_fpr_pct - $declared_fpr" | bc)

    local report_file="ops/red-team/reports/${script_id}-$(date -u +%Y%m%d-%H%M%S).json"

    cat > "$report_file" <<EOF
{
  "schema_version": "2.0",
  "script_id": "$script_id",
  "script_name": "$script_name",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel_version": "${BTV_KERNEL_VERSION:-unknown}",
  "results": {
    "total": $RT_TOTAL,
    "passed": $RT_PASS,
    "failed": $RT_FAIL,
    "detections": $RT_DETECTIONS,
    "bypasses": $RT_BYPASSES,
    "false_positives": $RT_FALSE_POSITIVES,
    "detection_rate_pct": $(echo "scale=1; $RT_DETECTIONS * 100 / ($RT_DETECTIONS + $RT_BYPASSES)" | bc),
    "fpr_pct": $measured_fpr_pct
  },
  "bias_declaration_comparison": {
    "declared_fnr_pct": $declared_fnr,
    "declared_fpr_pct": $declared_fpr,
    "measured_bypass_rate_pct": $measured_fnr_pct,
    "measured_fpr_pct": $measured_fpr_pct,
    "fnr_divergence_pp": $fnr_div,
    "fpr_divergence_pp": $fpr_div
  }
}
EOF
    echo "  Report: $report_file"
}
```

O arquivo `ops/red-team/bias-baseline.json` é a **fonte de verdade das declarações atuais** e é atualizado quando um PR de BiasDeclaration update é mergeado:

```json
{
  "RT-001": { "declared_fnr_pct": 18.0, "declared_fpr_pct": 8.0 },
  "RT-002": { "declared_fnr_pct": 2.0,  "declared_fpr_pct": 8.0 },
  "RT-003": { "declared_fnr_pct": 3.0,  "declared_fpr_pct": 5.0 },
  "RT-004": { "declared_fnr_pct": 8.0,  "declared_fpr_pct": 3.0 },
  "RT-005": { "declared_fnr_pct": 6.0,  "declared_fpr_pct": 4.0 },
  "RT-006": { "declared_fnr_pct": 4.0,  "declared_fpr_pct": 2.0 },
  "RT-007": { "declared_fnr_pct": 12.0, "declared_fpr_pct": 6.0 },
  "RT-008": { "declared_fnr_pct": 20.0, "declared_fpr_pct": 5.0 }
}
```

---

## 3. Ciclo de Atualização de BiasDeclaration

O Bias Guardian define um protocolo de atualização que **fecha o loop filosófico** entre declaração e medição:

```
┌─────────────────────────────────────────────────────────┐
│           CICLO DE CALIBRAÇÃO (ADR-036)                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. RT-XXX roda → relatório com divergência medida      │
│         ↓                                               │
│  2. Bias Guardian Gate avalia nível (OK/WARN/BLOCK)     │
│         ↓                                               │
│  3. BLOCK → dev DEVE abrir PR atualizando:              │
│     - rust/.../validators/xxx.rs (bias_declaration())   │
│     - ops/red-team/bias-baseline.json                   │
│     - docs/adr/0010-bias-declaration-mandate.md (tabela)│
│         ↓                                               │
│  4. PR mergeado → novo red-team confirma convergência   │
│         ↓                                               │
│  5. calibration_date atualizado → loop reinicia         │
│                                                          │
│  WARNING → mesmo fluxo, prazo 14 dias (non-blocking)    │
│  OK      → nenhuma ação; próximo ciclo em 90 dias       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Invariante de segurança:** o sistema **nunca** permite que `declared < measured - block_threshold`. Isso seria declarar maior competência do que a real — o inverso do conservadorismo de Jonas.

---

## 4. Fundamentos Filosóficos

**Jonas (Responsabilidade Preventiva):** A BiasDeclaration é uma promessa pública sobre as limitações do sistema. Publicar `FNR=18%` quando o medido é `26.7%` é equivalente a um fabricante de equipamento médico declarar taxa de falha menor do que a real. O Bias Guardian torna essa omissão estruturalmente impossível de passar pelo CI — prevenção antes de correção.

**Rawls (Véu da Ignorância):** Os thresholds de divergência (5pp warning, 15pp block para FNR) foram derivados sem considerar qual módulo específico seria afetado. O mesmo critério se aplica a CPF, NHS e Prompt Injection — sem tratamento preferencial para módulos "mais convenientes" de manter atualizados.

**Levinas (Alteridade — o Usuário Afetado):** O FPR alto significa usuários legítimos bloqueados. O FNR alto significa atacantes que passam. Ambos afetam o outro concreto — não uma abstração estatística. Os thresholds de FPR são deliberadamente mais rígidos (3pp warning vs 5pp para FNR em alertas) porque o usuário legítimo bloqueado sofre imediatamente e de forma visível.

**Gilligan (Relação e Responsabilidade):** O ciclo de atualização não é punitivo — é um diálogo entre o sistema e a realidade que ele modela. O prazo de 14 dias para warnings é espaço para ajuste sem urgência. O BLOCK é o limite ético, não uma sanção.

---

## 5. Consequências

### Positivas

A BiasDeclaration deixa de ser uma anotação de boa-fé e torna-se um contrato verificável com enforcement automático. O sistema passa a ter evidências objetivas (relatórios RT com timestamp e `pattern_epoch`) de que as declarações são atuais. Isso satisfaz EU AI Act Art. 13 (transparência verificável) e ISO 42001 §7.4 (comunicação de limitações conhecidas).

A correlação entre `pattern_epoch` (ADR-032) e relatórios de red-team permite rastrear exatamente qual versão de detectores produziu quais métricas — auditabilidade forense completa.

### Negativas e Trade-offs

O gate de CI adiciona ~8 minutos ao pipeline de PR (tempo de execução da suite completa). Mitigado pela execução seletiva: PRs que não tocam validators rodam apenas o subset afetado.

Os thresholds de 5pp (warning) e 15pp (block) para FNR são conservadores para o estado atual do sistema. O RT-001 já mostra divergência de 8.7pp — imediatamente em WARNING. Isso é intencional: o sistema força a atualização do estado real, não mascara a dívida técnica.

Scripts RT-010 a RT-012 ainda não existem (prometidos em ADR-035 mas pendentes). O gate de CI não pode bloquear por scripts ausentes — ele avalia apenas os relatórios existentes. Isso é explicitado como lacuna de cobertura no relatório da suite.

---

## 6. ADRs Dependentes

| ADR | Relação |
|:---|:---|
| ADR-010 (BiasDeclaration Mandate) | ADR-036 é o enforcement de ADR-010 — sem ele, ADR-010 é inerte |
| ADR-028 (Prompt Injection) | RT-001 mede diretamente; divergência atual de 8.7pp exige update imediato |
| ADR-032 (ScanContextFlags) | `pattern_epoch` correlaciona relatórios RT com versão de detectores |
| ADR-035 (Multi-jurisdiction PII) | RT-010/011/012 são requisito de aceitação deste ADR |
| ADR-016 (EthicalContextEngine, futuro v1.8) | `explain_decision()` em `ModuleBiasReport` antecipa interface de ADR-016 |

---

## 7. Critérios de Aceitação

```
[ ] bias_guardian.py existe em python/buildtovalue/governance/
[ ] bias_guardian_gate.py existe em ops/red-team/
[ ] ci-red-team.yml existe em .github/workflows/
[ ] bias-baseline.json existe em ops/red-team/ com entradas RT-001..008
[ ] bias_guardian_gate.py retorna exit 1 para divergência FNR > 15pp
[ ] bias_guardian_gate.py retorna exit 0 para divergência FNR entre 5pp e 15pp (warning)
[ ] bias_guardian_gate.py retorna exit 0 para divergência FNR ≤ 5pp (ok)
[ ] explain_decision() retorna string não vazia para todos os DivergenceLevel
[ ] RT-010, RT-011, RT-012 criados e integrados em run-all.sh
[ ] lib/common.sh atualizado com rt_write_report() gerando schema_version: "2.0"
[ ] Gate executa em < 30s (sem contabilizar o tempo do run-all.sh)
[ ] Teste: evaluate_module com RT-001 atual retorna DivergenceLevel.WARNING
[ ] Teste: evaluate_module com dados dentro da tolerância retorna DivergenceLevel.OK
[ ] Teste: explain_decision() de BLOCK contém referência a Jonas
[ ] ADR registrado em 0000-adr-index.md (Grupo C, entrada 0036)
```

---

## 8. Referências
```
- `ops/red-team/reports/RT-001-20260224-152417.json` — evidência empírica da divergência atual
- `ops/red-team/RT-001-prompt-injection.sh` — padrão de script a replicar em RT-010/011/012
- ADR-010 (BiasDeclaration Mandate) — contrato que este ADR enforça
- ADR-028 (Prompt Injection Detector) — módulo com maior divergência observada
- ADR-032 (ScanContextFlags) — fonte do `pattern_epoch` para correlação de relatórios
- ADR-035 (Multi-jurisdiction PII) — referencia ADR-036 como destino dos valores reais de FPR/FNR
- EU AI Act, Art. 13 — Transparência e fornecimento de informações
- ISO 42001, §7.4 — Comunicação de limitações de sistemas de IA
- Hans Jonas, *The Imperative of Responsibility* (1979) — responsabilidade proporcional ao poder de causar dano
```
---
