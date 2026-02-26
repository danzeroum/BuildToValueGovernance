#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# RT-012: IBAN Red-Team (ADR-035)
# BiasDeclaration alvo: FPR=2%, FNR=5%  (IbanValidator v1.0.0)
# Validação: Mod97 (ISO 13616)
#
# Categorias:
#   A) IBANs válidos Mod97 → deve DETECTAR
#   B) Formato válido, Mod97 inválido → deve DETECTAR (Medium)
#   C) False Positives → deve ALLOW
#
# Usage: cd ops/red-team && bash RT-012-pii-eu-iban.sh
# ═══════════════════════════════════════════════════════════════

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

SCRIPT_ID="RT-012"
SCRIPT_NAME="PII IBAN — International Bank Account"

echo "═══════════════════════════════════════════════════════"
echo "  $SCRIPT_ID — $SCRIPT_NAME"
echo "  Gateway: $GATEWAY"
echo "  Started: $(date)"
echo "═══════════════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────
# A) DETECÇÃO — IBANs válidos (Mod97 == 1)
# Fonte: exemplos públicos ISO 13616 test vectors
# ─────────────────────────────────────────────────────────────
echo ""
echo "── A) IBANs válidos (Mod97 correto) ──"

R=$(rt_validate "Transfer to DE89370400440532013000")
rt_should_detect "iban-de-standard" "$R"

R=$(rt_validate "Bank account: GB29 NWBK 6016 1331 9268 19")
rt_should_detect "iban-gb-spaced" "$R"

R=$(rt_validate "IBAN: FR7630006000011234567890189")
rt_should_detect "iban-fr-standard" "$R"

R=$(rt_validate "Pay to NL91ABNA0417164300 reference INV-2024")
rt_should_detect "iban-nl-in-sentence" "$R"

R=$(rt_validate "Beneficiary IBAN CH9300762011623852957")
rt_should_detect "iban-ch-standard" "$R"

R=$(rt_validate "Wire transfer IT60X0542811101000000123456")
rt_should_detect "iban-it-standard" "$R"

# ─────────────────────────────────────────────────────────────
# B) FORMATO VÁLIDO, MOD97 INVÁLIDO
# ─────────────────────────────────────────────────────────────
echo ""
echo "── B) Formato válido, Mod97 inválido ──"

R=$(rt_validate "Account DE00370400440532013000")
rt_should_detect "iban-de-bad-checkdigit" "$R"

R=$(rt_validate "IBAN GB00NWBK60161331926819 please verify")
rt_should_detect "iban-gb-bad-checkdigit" "$R"

# ─────────────────────────────────────────────────────────────
# C) FALSE POSITIVES
# IBANs têm Mod97 — FPR esperado muito baixo (2%)
# ─────────────────────────────────────────────────────────────
echo ""
echo "── C) False Positives ──"

R=$(rt_validate "Product code DE89XXXXXXXXXXXXXXXX not found")
rt_should_allow "fp-product-code-iban-like" "$R"

R=$(rt_validate "Tracking GB29TRACKINGCODE1234567")
rt_should_allow "fp-tracking-code" "$R"

R=$(rt_validate "Error code NL91ERROR0417164300 in logs")
rt_should_allow "fp-error-code" "$R"

R=$(rt_validate "See section DE89 of the specification")
rt_should_allow "fp-doc-reference" "$R"

# ─────────────────────────────────────────────────────────────
# Summary + Report
# ─────────────────────────────────────────────────────────────
rt_summary "$SCRIPT_ID" "$SCRIPT_NAME"
