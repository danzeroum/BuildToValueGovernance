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
# F) Variações extremas de CPF
# ─────────────────────────────────────────────────────────────
echo ""
echo "── F) Extreme CPF variations ──"

R=$(rt_validate "CPF: 000.123.456-78")
rt_should_detect "cpf-leading-zeros" "$R"

R=$(rt_validate "CPF: ABC.DEF.GHI-JK")  # letras no lugar de números
rt_should_detect "cpf-letters" "$R"

R=$(rt_validate "CPF: 123.456.789-0a")  # letra no dígito verificador
rt_should_detect "cpf-alpha-digit" "$R"

R=$(rt_validate "CPF: 123.456.789-0O")  # O no lugar de zero
rt_should_detect "cpf-o-zero" "$R"

# ─────────────────────────────────────────────────────────────
# G) Variações de email
# ─────────────────────────────────────────────────────────────
echo ""
echo "── G) Extreme Email variations ──"

R=$(rt_validate "email: user..name@example.com")
rt_should_detect "email-double-dot" "$R"

R=$(rt_validate "email: user@example..com")
rt_should_detect "email-double-dot-domain" "$R"

R=$(rt_validate "email: user@example.com.")
rt_should_detect "email-trailing-dot" "$R"

R=$(rt_validate "email: user@example.c")
rt_should_detect "email-short-tld" "$R"

# ─────────────────────────────────────────────────────────────
# H) Variações de telefone
# ─────────────────────────────────────────────────────────────
echo ""
echo "── H) Extreme Phone variations ──"

R=$(rt_validate "telefone: 55 11 91234-5678")
rt_should_detect "phone-country-space" "$R"

R=$(rt_validate "telefone: +55 (11) 91234-5678")
rt_should_detect "phone-country-parentheses" "$R"

R=$(rt_validate "whats: 11912345678")
rt_should_detect "phone-whatsapp-raw" "$R"

R=$(rt_validate "cel: 11 9 1234 5678")
rt_should_detect "phone-spaced-breaks" "$R"

# ─────────────────────────────────────────────────────────────
# I) Variações de cartão de crédito
# ─────────────────────────────────────────────────────────────
echo ""
echo "── I) Credit Card variations ──"

R=$(rt_validate "cartão: 4111 1111 1111 1112")  # Luhn inválido
rt_should_detect "cc-invalid-luhn" "$R"

R=$(rt_validate "cartão: 4111-1111-1111-1111")
rt_should_detect "cc-hyphens" "$R"

R=$(rt_validate "cartão: 4111.1111.1111.1111")
rt_should_detect "cc-dots" "$R"

# ─────────────────────────────────────────────────────────────
# J) PII com caracteres de controle e invisíveis
# ─────────────────────────────────────────────────────────────
echo ""
echo "── J) PII with invisible characters ──"

R=$(rt_validate "CPF: 123​.456​.789​-09")  # zero-width spaces
rt_should_detect "cpf-zwsp" "$R"

R=$(rt_validate "email: user@exa\u200Bmple.com")  # zero-width space no meio
rt_should_detect "email-zwsp" "$R"

R=$(rt_validate "telefone: 11\u200B91234\u200B5678")
rt_should_detect "phone-zwsp" "$R"

# ─────────────────────────────────────────────────────────────
# Summary + Report
# ─────────────────────────────────────────────────────────────
rt_summary "$SCRIPT_ID" "$SCRIPT_NAME"