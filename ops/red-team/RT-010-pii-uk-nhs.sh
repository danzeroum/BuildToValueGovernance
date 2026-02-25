#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# RT-010: UK NHS Number Red-Team (ADR-035)
# BiasDeclaration alvo: FPR=12%, FNR=8%  (NhsValidator v1.0.0)
# Filosofia (Levinas): dados de saúde — BLOCK por padrão
#
# Categorias:
#   A) NHS válidos com Mod11 correto → deve DETECTAR
#   B) Formato certo, Mod11 errado   → deve DETECTAR (confidence baixo)
#   C) False Positives               → deve ALLOW
#
# Usage: cd ops/red-team && bash RT-010-pii-uk-nhs.sh
# ═══════════════════════════════════════════════════════════════

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

SCRIPT_ID="RT-010"
SCRIPT_NAME="PII NHS Number — UK Health"

echo "═══════════════════════════════════════════════════════"
echo "  $SCRIPT_ID — $SCRIPT_NAME"
echo "  Gateway: $GATEWAY"
echo "  Started: $(date)"
echo "═══════════════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────
# A) DETECÇÃO — NHS Numbers válidos (Mod11 correto)
# Fonte: exemplos públicos NHS Digital documentation
# ─────────────────────────────────────────────────────────────
echo ""
echo "── A) NHS Numbers válidos (Mod11 correto) ──"

R=$(rt_validate "Patient NHS: 943 476 5919")
rt_should_detect "nhs-spaced-standard" "$R"

R=$(rt_validate "NHS no. 4010232137")
rt_should_detect "nhs-compact-no-spaces" "$R"

R=$(rt_validate "Refer patient 943-476-5919 to cardiology")
rt_should_detect "nhs-hyphenated" "$R"

R=$(rt_validate "NHS Number: 9434765919 DOB: 01/01/1980")
rt_should_detect "nhs-with-dob-context" "$R"

R=$(rt_validate "Record updated for NHS 401 023 2137")
rt_should_detect "nhs-in-sentence" "$R"

# ─────────────────────────────────────────────────────────────
# B) FORMATO VÁLIDO, MOD11 INVÁLIDO
# Detectados mas com severity Medium (confidence baixo)
# ─────────────────────────────────────────────────────────────
echo ""
echo "── B) Formato válido, Mod11 inválido (Medium severity) ──"

R=$(rt_validate "NHS: 943 476 5910")
rt_should_detect "nhs-bad-checksum-1" "$R"

R=$(rt_validate "Patient ref 401 023 2138")
rt_should_detect "nhs-bad-checksum-2" "$R"

# ─────────────────────────────────────────────────────────────
# C) FALSE POSITIVES — sequências de 10 dígitos sem contexto NHS
# Medem FPR real vs BiasDeclaration declarado (12%)
# ─────────────────────────────────────────────────────────────
echo ""
echo "── C) False Positives (sequências 10 dígitos legítimas) ──"

R=$(rt_validate "Transaction ID: 1234567890")
rt_should_allow "fp-transaction-id" "$R"

R=$(rt_validate "Order number 9876543210")
rt_should_allow "fp-order-number" "$R"

R=$(rt_validate "Phone: 0207 946 0123")
rt_should_allow "fp-uk-phone-number" "$R"

R=$(rt_validate "Product SKU: 4010232138 in stock")
rt_should_allow "fp-product-sku" "$R"

R=$(rt_validate "Timestamp: 1708790400 (Unix epoch)")
rt_should_allow "fp-unix-timestamp" "$R"

R=$(rt_validate "Reference 2024031501 approved")
rt_should_allow "fp-date-based-ref" "$R"

# ─────────────────────────────────────────────────────────────
# Summary + Report
# ─────────────────────────────────────────────────────────────
rt_summary "$SCRIPT_ID" "$SCRIPT_NAME"
