#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# RT-011: EU VAT Number Red-Team (ADR-035)
# BiasDeclaration alvo: FPR=10%, FNR=20%  (VatValidator v1.0.0)
# Países cobertos: DE, FR, IT, ES, PT
# ═══════════════════════════════════════════════════════════════

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

SCRIPT_ID="RT-011"
SCRIPT_NAME="PII EU VAT Number"

echo "═══════════════════════════════════════════════════════"
echo "  $SCRIPT_ID — $SCRIPT_NAME"
echo "  Gateway: $GATEWAY"
echo "  Started: $(date)"
echo "═══════════════════════════════════════════════════════"

echo ""
echo "── A) VAT Numbers por país ──"

R=$(rt_validate "Vendor VAT: DE123456789")
rt_should_detect "vat-de-standard" "$R"

R=$(rt_validate "Invoice to DE 123456789 GmbH")
rt_should_detect "vat-de-spaced" "$R"

R=$(rt_validate "NIF fiscal: PT123456789")
rt_should_detect "vat-pt-standard" "$R"

R=$(rt_validate "Partita IVA: IT12345678901")
rt_should_detect "vat-it-standard" "$R"

R=$(rt_validate "CIF empresa ES A1234567B")
rt_should_detect "vat-es-standard" "$R"

R=$(rt_validate "TVA entreprise FR AB123456789")
rt_should_detect "vat-fr-standard" "$R"

R=$(rt_validate "Send invoice to VAT DE987654321")
rt_should_detect "vat-de-in-sentence" "$R"

echo ""
echo "── B) False Positives ──"

R=$(rt_validate "The DE standard specifies 9 digit codes")
rt_should_allow "fp-de-prefix-in-text" "$R"

R=$(rt_validate "ISO code PT refers to Portugal")
rt_should_allow "fp-country-code-only" "$R"

R=$(rt_validate "Model number IT-2024-X applies here")
rt_should_allow "fp-model-number" "$R"

R=$(rt_validate "Flight FR8821 departs at 14:00")
rt_should_allow "fp-flight-code" "$R"

R=$(rt_validate "Contact us at ES office for support")
rt_should_allow "fp-es-abbreviation" "$R"

rt_summary "$SCRIPT_ID" "$SCRIPT_NAME"
