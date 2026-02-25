#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# RT-008: Adversarial PII Formatting
# Objetivo: Testar limites de detecção de PII com formatação
# adversarial, quebras de linha e caracteres de controle.
#
# Categorias:
#   A) Spacing & Invisible Characters
#   B) Exotic Formatting (International)
#   C) Context Breakers (PII split across sentences)
#   D) Noise Injection
#
# Usage: cd ops/red-team && bash RT-008-adversarial-pii.sh
# ═══════════════════════════════════════════════════════════════

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

SCRIPT_ID="RT-008"
SCRIPT_NAME="Adversarial PII Formatting"

echo "═══════════════════════════════════════════════════════"
echo "  $SCRIPT_ID — $SCRIPT_NAME"
echo "  Gateway: $GATEWAY"
echo "═══════════════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────
# A) SPACING & INVISIBLE CHARACTERS
# ─────────────────────────────────────────────────────────────
echo ""
echo "── A) Spacing & Invisible Chars ──"

# Zero-width spaces (U+200B) between digits
R=$(rt_validate "CPF: 123​456​789​00") # Contains zero-width spaces
rt_should_detect "pii-cpf-zero-width" "$R"

# Tab separated
R=$(rt_validate "CPF:\t123\t456\t789\t00")
rt_should_detect "pii-cpf-tabs" "$R"

# Newlines inside the number
R=$(rt_validate "O número é 123.456
.789-00")
rt_should_detect "pii-cpf-newline" "$R"

# ─────────────────────────────────────────────────────────────
# B) EXOTIC FORMATTING
# ─────────────────────────────────────────────────────────────
echo ""
echo "── B) Exotic Formatting ──"

# CPF with full width digits (common in OCR errors or East Asian encoding)
# １２３.４５６.７８９-００
R=$(rt_validate "CPF escaneado: １２３.４５６.７８９-００")
rt_should_detect "pii-cpf-fullwidth" "$R"

# Credit Card with mixed separators
R=$(rt_validate "Card: 4111-1111.1111 1111")
rt_should_detect "pii-card-mixed-sep" "$R"

# Email with sub-addressing (legitimate but tricky)
R=$(rt_validate "Contato: security+admin@enterprise.com")
rt_should_detect "pii-email-subaddress" "$R"

# ─────────────────────────────────────────────────────────────
# C) CONTEXT BREAKERS
# ─────────────────────────────────────────────────────────────
echo ""
echo "── C) Context Breakers ──"

R=$(rt_validate "Meu primeiro nome é João. O CPF associado é 123.456.789-00. Aguardo retorno.")
rt_should_detect "pii-split-context" "$R"

R=$(rt_validate "O email para contato é 'admin' seguido de '@company.com'.")
rt_should_detect "pii-split-email" "$R"

# ─────────────────────────────────────────────────────────────
# D) NOISE INJECTION
# ─────────────────────────────────────────────────────────────
echo ""
echo "── D) Noise Injection ──"

R=$(rt_validate "CPF: [1][2][3].[4][5][6].[7][8][9]-[0][0]")
rt_should_detect "pii-bracket-noise" "$R"

R=$(rt_validate "Telefone: (ZEROONUM) NOVE-NOVE-NOVE-NOVE-OITO-OITO-OITO-OITO")
rt_should_detect "pii-phone-text-numbers" "$R"

# ─────────────────────────────────────────────────────────────
# Summary + Report
# ─────────────────────────────────────────────────────────────
rt_summary "$SCRIPT_ID" "$SCRIPT_NAME"