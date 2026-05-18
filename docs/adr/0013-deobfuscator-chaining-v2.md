# ADR-013: Deobfuscation Chaining Strategy (v2)

**Status:** ✅ Implementado (v1.7.0)
**Crate:** `btv-kernel` (deobfuscator module)
**Atualizado em:** 18 de maio de 2026

## Decisão (v2 — ADR-0013-v2)

O `DeobfuscatorChain` implementa deobfuscação em camadas com `max_depth = 3`.

### Decoders suportados (em ordem)
1. **Base64** (whole-string): decode se input inteiro é base64 válido
2. **Hex** (whole-string): decode se input inteiro é hex válido
3. **Leetspeak** (depth==0 apenas, skip se normalização rodou)
4. **Embedded tokens** (depth==0): extrai e substitui tokens base64/hex embarcados em texto maior

### Cláusula de Normalização (v2)
- `Normalizer::normalize()` roda **antes** do loop de decoders
- Se a normalização **alterou** o texto (`norm_changed = true`), uma layer `"normalize"` é adicionada ao `layers[]`
- A gate do Stage 3.5 (`!chain_result.layers.is_empty() && chain_result.final_text != input`) dispara para texto Unicode/espaçado
- Leet decode é **suprimido** quando normalização rodou para evitar falsa-leet em dígitos de CPF/telefone normalizados

### Embedded Token Decode (v2 — novo)
- `try_decode_embedded_tokens()` usa `LazyLock<Regex>` (compilado uma vez, zero-alloc no hot path)
- Regex B64: `[A-Za-z0-9+/]{16,}={0,2}` (min 16 chars evita colisão com hex puro)
- Regex HEX: `\b[0-9a-fA-F]{20,}\b` (min 20 chars = 10 bytes)
- Uma substituição por chamada; loop de profundidade encadeia múltiplas

### Evasão Ativa
- `is_evasion = layers.len() >= 3` → Finding `ACTIVE_EVASION_DETECTED` com `Critical(255)`

## Invariantes de Segurança
- Nenhum `.unwrap()` em hot paths — regexes em `LazyLock::new(|| Regex::new(...).expect(...))`
- Timeout 5ms por chain call (`CHAIN_OVERHEAD_LIMIT_US = 5_000`)
- Leet decode restrito a depth==0 E apenas se normalização não rodou