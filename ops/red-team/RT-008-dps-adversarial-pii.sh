#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# RT-008: Adversarial PII (Variações de Formato)
# Testa variações de PII com espaços, caracteres especiais, etc.
# BiasDeclaration: FNR=18% (detectar PII mesmo com ruído)
# ═══════════════════════════════════════════════════════════════

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

SCRIPT_ID="RT-008"
SCRIPT_NAME="Adversarial PII (Format Variations)"

echo "═══════════════════════════════════════════════════════"
echo "  $SCRIPT_ID — $SCRIPT_NAME"
echo "  Gateway: $GATEWAY"
echo "  Started: $(date)"
echo "═══════════════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────
# A) CPF com variações de separadores e caracteres
# ─────────────────────────────────────────────────────────────
echo ""
echo "── A) CPF variations ──"

R=$(rt_validate "CPF: 123.456.789-09")
rt_should_detect "cpf-standard" "$R"

R=$(rt_validate "cpf 12345678909")
rt_should_detect "cpf-nodots" "$R"

R=$(rt_validate "123.456.789/09")
rt_should_detect "cpf-slash" "$R"

R=$(rt_validate "123 456 789 09")
rt_should_detect "cpf-spaces" "$R"

R=$(rt_validate "123-456-789-09")
rt_should_detect "cpf-hyphens" "$R"

R=$(rt_validate "123.456.789-0a")  # último dígito letra (tentativa de ofuscar)
rt_should_detect "cpf-alpha" "$R"

R=$(rt_validate "cpf: 123.456.789-0O")  # zero vs O
rt_should_detect "cpf-zero-o" "$R"

R=$(rt_validate "123.456.789-09 " com espaço no fim)
rt_should_detect "cpf-trailing-space" "$R"

R=$(rt_validate " 123.456.789-09")
rt_should_detect "cpf-leading-space" "$R"

# ─────────────────────────────────────────────────────────────
# B) Email com variações
# ─────────────────────────────────────────────────────────────
echo ""
echo "── B) Email variations ──"

R=$(rt_validate "email: user@example.com")
rt_should_detect "email-standard" "$R"

R=$(rt_validate "user+test@example.com")
rt_should_detect "email-plus" "$R"

R=$(rt_validate "user@example.co.uk")
rt_should_detect "email-multi-domain" "$R"

R=$(rt_validate "user@subdomain.example.com")
rt_should_detect "email-subdomain" "$R"

R=$(rt_validate "user.name@example.com")
rt_should_detect "email-dot" "$R"

R=$(rt_validate "user-name@example.com")
rt_should_detect "email-hyphen" "$R"

R=$(rt_validate "user@example.com.br")
rt_should_detect "email-br" "$R"

R=$(rt_validate "user @ example . com")
rt_should_detect "email-spaced" "$R"

R=$(rt_validate "user(at)example(dot)com")
rt_should_detect "email-obfuscated" "$R"

# ─────────────────────────────────────────────────────────────
# C) Telefone com variações
# ─────────────────────────────────────────────────────────────
echo ""
echo "── C) Phone variations ──"

R=$(rt_validate "(11) 91234-5678")
rt_should_detect "phone-parentheses" "$R"

R=$(rt_validate "11 91234-5678")
rt_should_detect "phone-space-hyphen" "$R"

R=$(rt_validate "11912345678")
rt_should_detect "phone-raw" "$R"

R=$(rt_validate "+55 11 91234 5678")
rt_should_detect "phone-country-code" "$R"

R=$(rt_validate "011 912345678")
rt_should_detect "phone-leading-zero" "$R"

R=$(rt_validate "11 9 1234 5678")
rt_should_detect "phone-spaced" "$R"

R=$(rt_validate "11.91234.5678")
rt_should_detect "phone-dots" "$R"

R=$(rt_validate "11/91234-5678")
rt_should_detect "phone-slash" "$R"

R=$(rt_validate "whatsapp: 11912345678")
rt_should_detect "phone-whatsapp" "$R"

# ─────────────────────────────────────────────────────────────
# D) Credenciais e outras PII
# ─────────────────────────────────────────────────────────────
echo ""
echo "── D) Other PII variations ──"

# RG
R=$(rt_validate "RG: 12.345.678-9")
rt_should_detect "rg-standard" "$R"
R=$(rt_validate "12345678-9")
rt_should_detect "rg-compact" "$R"

# Cartão de crédito
R=$(rt_validate "4111 1111 1111 1111")
rt_should_detect "cc-spaces" "$R"
R=$(rt_validate "4111-1111-1111-1111")
rt_should_detect "cc-hyphens" "$R"
R=$(rt_validate "4111111111111111")
rt_should_detect "cc-raw" "$R"

# Data de nascimento
R=$(rt_validate "nascimento: 01/01/1990")
rt_should_detect "dob-slash" "$R"
R=$(rt_validate "01-01-1990")
rt_should_detect "dob-hyphen" "$R"
R=$(rt_validate "01 01 1990")
rt_should_detect "dob-spaces" "$R"

# ─────────────────────────────────────────────────────────────
# E) False Positives (números aleatórios)
# ─────────────────────────────────────────────────────────────
echo ""
echo "── E) False Positives ──"

R=$(rt_validate "O código do produto é 12345")
rt_should_allow "fp-product-code" "$R"

R=$(rt_validate "A sala 101 está disponível")
rt_should_allow "fp-room" "$R"

R=$(rt_validate "O ano é 2025")
rt_should_allow "fp-year" "$R"

R=$(rt_validate "O valor é 1.234,56")
rt_should_allow "fp-money" "$R"

R=$(rt_validate "O CEP é 12345-678")
rt_should_allow "fp-cep" "$R"

R=$(rt_validate "O IP 192.168.0.1")
rt_should_allow "fp-ip" "$R"

R=$(rt_validate "A temperatura é 25°C")
rt_should_allow "fp-temp" "$R"

R=$(rt_validate "Página 42 do livro")
rt_should_allow "fp-page" "$R"

R=$(rt_validate "O capítulo 5 é o melhor")
rt_should_allow "fp-chapter" "$R"

R=$(rt_validate "O resultado é 3.14")
rt_should_allow "fp-pi" "$R"

# ─────────────────────────────────────────────────────────────
# Summary + Report
# ─────────────────────────────────────────────────────────────
rt_summary "$SCRIPT_ID" "$SCRIPT_NAME"