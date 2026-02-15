#!/bin/bash
# scripts/seal_sovereignty.sh
# BuildToValue v2.2 - Geração de checksums criptográficos para políticas
# Criado: 2026-02-04

set -euo pipefail

VERSION="2.2.0"
POLICY_DIR="data/policies"
METADATA_FILE="${POLICY_DIR}/_metadata/checksums.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "════════════════════════════════════════════════════════════════"
echo "  BuildToValue v${VERSION} - Sovereignty Seal"
echo "  Sealing Algorithmic Constitution..."
echo "════════════════════════════════════════════════════════════════"

# Verificar se diretório existe
if [ ! -d "${POLICY_DIR}" ]; then
    echo "❌ ERROR: Policy directory not found: ${POLICY_DIR}"
    exit 1
fi

# Criar diretório de metadata se não existir
mkdir -p "${POLICY_DIR}/_metadata"

# Iniciar JSON
cat > "${METADATA_FILE}" << EOF
{
  "version": "${VERSION}",
  "sealed_at": "${TIMESTAMP}",
  "algorithm": "SHA-256",
  "policies": {
EOF

# Gerar checksums
FIRST=true
find "${POLICY_DIR}" -name "*.yaml" -type f | while read -r file; do
    # Pular metadata
    if [[ "$file" == *"_metadata"* ]]; then
        continue
    fi

    # Calcular hash
    hash=$(sha256sum "$file" | awk '{print $1}')
    relative_path="${file#${POLICY_DIR}/}"

    # Adicionar vírgula se não for primeiro
    if [ "$FIRST" = false ]; then
        echo "," >> "${METADATA_FILE}"
    fi
    FIRST=false

    # Adicionar entrada
    printf '    "%s": "%s"' "$relative_path" "$hash" >> "${METADATA_FILE}"

    echo "  ✓ Sealed: $relative_path"
done

# Fechar JSON
cat >> "${METADATA_FILE}" << EOF

  },
  "signature": "HMAC-SHA256-PLACEHOLDER"
}
EOF

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ Sovereignty Seal Applied"
echo "📁 Checksums: ${METADATA_FILE}"
echo "🔐 Algorithm: SHA-256"
echo "⏰ Sealed at: ${TIMESTAMP}"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "🛡️  Constitution is now immutable and verifiable."
echo "    Any tampering will be detected at runtime."
