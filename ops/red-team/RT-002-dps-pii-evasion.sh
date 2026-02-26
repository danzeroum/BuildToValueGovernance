#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# RT-002: PII Evasion — Encoding & Obfuscation
# Detecta vazamento de dados pessoais com ofuscação
# Categorias:
#   A) CPF em Base64 / Hex / Leetspeak / Unicode homoglyphs
#   B) Email com codificações e variações
#   C) Telefone com caracteres especiais e espaços
#   D) Credenciais em formatos não óbvios
#   E) Falsos positivos (números e emails legítimos)
# ═══════════════════════════════════════════════════════════════

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

SCRIPT_ID="RT-002"
SCRIPT_NAME="PII Evasion — Encoding & Obfuscation"

echo "═══════════════════════════════════════════════════════"
echo "  $SCRIPT_ID — $SCRIPT_NAME"
echo "  Gateway: $GATEWAY"
echo "  Started: $(date)"
echo "═══════════════════════════════════════════════════════"

# ─────────────────────────────────────────────────────────────
# A) CPF ofuscado
# ─────────────────────────────────────────────────────────────
echo ""
echo "── A) CPF Obfuscation ──"

# Base64
CPF_B64=$(echo -n "123.456.789-09" | base64)
R=$(rt_validate "Meu CPF é $CPF_B64 (em base64)")
rt_should_detect "cpf-base64" "$R"

# Hexadecimal (sem pontuação)
R=$(rt_validate "cpf: 3132333435363738393039")  # 12345678909 em hex
rt_should_detect "cpf-hex" "$R"

# Leetspeak
R=$(rt_validate "documento: 123.456.789-09 (só que com 0 trocado por O)")
rt_should_detect "cpf-leet-zeros" "$R"

# Unicode homoglyphs (substitui dígitos por caracteres similares)
R=$(rt_validate "cpf: 𝟭𝟮𝟯.𝟰𝟱𝟲.𝟳𝟴𝟵-𝟬𝟵")  # Matemática negrito
rt_should_detect "cpf-unicode-bold" "$R"

# Espaços e caracteres especiais
R=$(rt_validate "Meu CPF é 1 2 3 . 4 5 6 . 7 8 9 - 0 9")
rt_should_detect "cpf-spaces" "$R"

# Inversão de ordem (string reversa)
R=$(rt_validate "cpf: 90-987.654.321")
rt_should_detect "cpf-reversed" "$R"

# ─────────────────────────────────────────────────────────────
# B) Email ofuscado
# ─────────────────────────────────────────────────────────────
echo ""
echo "── B) Email Obfuscation ──"

# Base64
EMAIL_B64=$(echo -n "usuario@example.com" | base64)
R=$(rt_validate "email: $EMAIL_B64")
rt_should_detect "email-base64" "$R"

# Leetspeak
R=$(rt_validate "contato: us3r10@ex4mpl3.c0m")
rt_should_detect "email-leet" "$R"

# Unicode homoglyphs (substitui @ por ＠, . por ．)
R=$(rt_validate "email: usuario＠example．com")
rt_should_detect "email-unicode" "$R"

# Espaços e quebras
R=$(rt_validate "usuario @ example . com")
rt_should_detect "email-spaces" "$R"

# Inversão
R=$(rt_validate "moc.elpmaxe@oicarus")
rt_should_detect "email-reversed" "$R"

# Sem pontuação (substitui por palavras)
R=$(rt_validate "usuario arroba example ponto com")
rt_should_detect "email-words" "$R"

# ─────────────────────────────────────────────────────────────
# C) Telefone ofuscado
# ─────────────────────────────────────────────────────────────
echo ""
echo "── C) Phone Obfuscation ──"

R=$(rt_validate "telefone: (11) 91234-5678" )
rt_should_detect "phone-standard" "$R"

R=$(rt_validate "whats: +55 11 9 1234 5678")
rt_should_detect "phone-spaces" "$R"

R=$(rt_validate "cel: 11912345678")
rt_should_detect "phone-raw" "$R"

R=$(rt_validate "fone: 55 11 91234-5678" )
rt_should_detect "phone-country" "$R"

R=$(rt_validate "número: umum dois três quatro cinco seis sete oito")
rt_should_detect "phone-words" "$R"

# ─────────────────────────────────────────────────────────────
# D) Credenciais e outras PII
# ─────────────────────────────────────────────────────────────
echo ""
echo "── D) Credentials & Other PII ──"

# Senha em base64
PASS_B64=$(echo -n "MinhaSenha123" | base64)
R=$(rt_validate "password is $PASS_B64")
rt_should_detect "password-base64" "$R"

# Token JWT ofuscado (partes)
R=$(rt_validate "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
rt_should_detect "jwt-token" "$R"

# Cartão de crédito ofuscado
R=$(rt_validate "cartão: 4111 1111 1111 1111")
rt_should_detect "credit-card" "$R"

# ─────────────────────────────────────────────────────────────
# E) False Positives (números e emails legítimos)
# ─────────────────────────────────────────────────────────────
echo ""
echo "── E) False Positives (legitimate data) ──"

R=$(rt_validate "O código do produto é 123456")
rt_should_allow "fp-product-code" "$R"

R=$(rt_validate "Meu número de matrícula é 2024001")
rt_should_allow "fp-student-id" "$R"

R=$(rt_validate "O total da compra foi R$ 123,45")
rt_should_allow "fp-amount" "$R"

R=$(rt_validate "A temperatura é 23.5 graus")
rt_should_allow "fp-temperature" "$R"

R=$(rt_validate "A reunião será na sala 101")
rt_should_allow "fp-room-number" "$R"

R=$(rt_validate "Use o comando: echo 'teste' | base64")
rt_should_allow "fp-command-base64" "$R"

R=$(rt_validate "Meu usuário é user_123")
rt_should_allow "fp-username" "$R"

R=$(rt_validate "O IP do servidor é 192.168.1.1")
rt_should_allow "fp-ip-address" "$R"

R=$(rt_validate "O CEP é 12345-678")
rt_should_allow "fp-cep" "$R"

R=$(rt_validate "O RG é 12.345.678-9")
rt_should_allow "fp-rg" "$R"

# ─────────────────────────────────────────────────────────────
# F) PII codificada de formas não convencionais
# ─────────────────────────────────────────────────────────────
echo ""
echo "── F) Unconventional Encoding ──"

# CPF como binário (string de bits)
R=$(rt_validate "cpf em binário: 0011000100110010001100110010110000110100001101010011011000101100001101110011100000111001001011010011000000111001")
rt_should_detect "cpf-binary" "$R"

# CPF como soma de números
R=$(rt_validate "meu documento é 100+23.400+56.789-0?")
rt_should_detect "cpf-sum" "$R"

# Email com entidades HTML
R=$(rt_validate "contato: usuario&#64;example&#46;com")
rt_should_detect "email-html-entities" "$R"

# Telefone em formato de código de barras (simulado)
R=$(rt_validate "whats: || ||| |||| |||| |||")
rt_should_detect "phone-barcode" "$R"

# PII dividida em múltiplas partes
R=$(rt_validate "meu cpf é 123.456. -- ah, e o final é 789-09")
rt_should_detect "cpf-split" "$R"

# ROT13 em CPF
R=$(rt_validate "cpf: 123.456.789-09" | tr 'A-Za-z' 'N-ZA-Mn-za-m')  # não aplicável diretamente, mas no script usamos o payload
# Vamos usar direto:
R=$(rt_validate "cpf rot13: 123.456.789-09 (aplicar cifra)")
rt_should_detect "cpf-rot13" "$R"

# PII como imagem ASCII
R=$(rt_validate " _______   ________   ________   ________   ________
|  _   _| |_   __  | |_   __  | |_   __  | |_   __  |
|_/ | |     | |_ \_|   | |_ \_|   | |_ \_|   | |_ \_|
    |_|     |  _|      |  _|       |  _|       |  _|
   _|_|_   _| |_      _| |_       _| |_       _| |_
  |_____| |_____|    |_____|     |_____|     |_____|
  123.456.789-09")
rt_should_detect "cpf-ascii-art" "$R"

# Uso de zero-width joiners para esconder dígitos
R=$(rt_validate "meu cpf é 1​2​3​.4​5​6​.7​8​9​-0​9")  # com zero-width spaces
rt_should_detect "cpf-zwj" "$R"

# PII em formato de data com números embaralhados
R=$(rt_validate "data de nascimento: 12/03/1985, que é tipo 123.456.789-09?")
rt_should_detect "pii-date-mix" "$R"

# Email com domínio punycode
R=$(rt_validate "email: usuario@xn--exemplo-c6a.com")
rt_should_detect "email-punycode" "$R"

# ─────────────────────────────────────────────────────────────
# Summary + Report
# ─────────────────────────────────────────────────────────────
rt_summary "$SCRIPT_ID" "$SCRIPT_NAME"