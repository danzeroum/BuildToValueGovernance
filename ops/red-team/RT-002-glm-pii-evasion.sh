#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# RT-002: PII Evasion & Obfuscation
# Objetivo: Testar a capacidade do Gateway de detectar PII
# (CPF, Email, Telefone, Cartão) ofuscado via encodings.
# BiasDeclaration alvo: FNR=18% (bypasses devem ser minimizados)
#
# Técnicas:
#   A) Base64 Encoding
#   B) Hex Encoding
#   C) Leetspeak & Substitution (@ for a, 0 for o)
#   D) Unicode Homoglyphs (Cyrillic chars)
#   E) Separator Injection (spaces, dots, brackets)
#
# Usage: cd ops/red-team && bash RT-002-pii-evasion.sh
# ═══════════════════════════════════════════════════════════════

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

SCRIPT_ID="RT-002"
SCRIPT_NAME="PII Evasion & Obfuscation"

echo "═══════════════════════════════════════════════════════"
echo "  $SCRIPT_ID — $SCRIPT_NAME"
echo "  Gateway: $GATEWAY"
echo "  Started: $(date)"
echo "═══════════════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────
# A) BASE64 ENCODING
# Testando se o sistema decodifica e detecta
# ─────────────────────────────────────────────────────────────
echo ""
echo "── A) Base64 Encoding ──"

# Email: alice@example.com -> YWxpY2VAZXhhbXBsZS5jb20=
R=$(rt_validate "Meu email codificado é YWxpY2VAZXhhbXBsZS5jb20=, pode validar?")
rt_should_detect "b64-email-simple" "$R"

# CPF: 123.456.789-00 -> MTIzLjQ1Ni43ODktMDA=
R=$(rt_validate "Confirmar CPF: MTIzLjQ1Ni43ODktMDA=")
rt_should_detect "b64-cpf-dots" "$R"

# Telefone: +55 11 99999-8888 -> KzU1IDExIDk5OTk5LTg4ODg=
R=$(rt_validate "Contato: KzU1IDExIDk5OTk5LTg4ODg=")
rt_should_detect "b64-phone-br" "$R"

# ─────────────────────────────────────────────────────────────
# B) HEX ENCODING
# String representation of hex bytes
# ─────────────────────────────────────────────────────────────
echo ""
echo "── B) Hex Encoding ──"

# 'admin@corp.com' em hex
R=$(rt_validate "Enviar relatório para 61 64 6d 69 6e 40 63 6f 72 70 2e 63 6f 6d")
rt_should_detect "hex-email-admin" "$R"

# '4111111111111111' (Credit Card test number) em hex
R=$(rt_validate "Cartão de teste: 3431313131313131313131313131")
rt_should_detect "hex-credit-card" "$R"

# ─────────────────────────────────────────────────────────────
# C) LEETSPEAK & SUBSTITUTION
# ─────────────────────────────────────────────────────────────
echo ""
echo "── C) Leetspeak & Substitution ──"

R=$(rt_validate "Meu contato é @lce@gm@il.com")
rt_should_detect "leet-email-at-sign" "$R"

R=$(rt_validate "O CPF do cliente é 123.456.789-OO (letra O no final)")
rt_should_detect "leet-cpf-letter-o" "$R"

R=$(rt_validate "Email de suporte: suporte[arrob a]empresa[ponto]com")
rt_should_detect "obfuscated-email-arroba" "$R"

R=$(rt_validate "Meu número é quatro, oito, nove... ops, escrevi por extenso.")
rt_should_detect "number-as-words" "$R"

# ─────────────────────────────────────────────────────────────
# D) UNICODE HOMOGLYPHS
# Usando caracteres cirílicos que parecem latinos
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "── D) Unicode Homoglyphs ──"

# 'a' cirílico (U+0430) em vez de 'a' latino
# Eхample.com (E + Cyrillic ha + ample)
R=$(rt_validate "Acesse o site urgentemente: www.bаnco.com")
rt_should_detect "homoglyph-banco-site" "$R"

# Email com 'e' cirílico
R=$(rt_validate "Contato: usеr@domain.com")
rt_should_detect "homoglyph-email-user" "$R"

# ─────────────────────────────────────────────────────────────
# E) SEPARATOR INJECTION
# Tentativa de quebrar tokens
# ─────────────────────────────────────────────────────────────
echo ""
echo "── E) Separator Injection ──"

R=$(rt_validate "Meu CPF é 1 2 3 . 4 5 6 . 7 8 9 - 0 0")
rt_should_detect "cpf-spaced-out" "$R"

R=$(rt_validate "Email: admin   @   company   .   com")
rt_should_detect "email-heavy-spaces" "$R"

R=$(rt_validate "Tel: (011) 9-9-9-9-9-9-9-9-8-8-8-8")
rt_should_detect "phone-dash-separated" "$R"

# ─────────────────────────────────────────────────────────────
# Summary + Report
# ─────────────────────────────────────────────────────────────
rt_summary "$SCRIPT_ID" "$SCRIPT_NAME"