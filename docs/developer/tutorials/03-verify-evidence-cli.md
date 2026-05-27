---
title: "Tutorial 03 — Verificação Criptográfica (`btv-cli`)"
---

# Tutorial 03 — Modo Inspetor: `btv-cli verify`

A confiança no BTV não depende do navegador. Toda evidência pode ser auditada
**fora do sistema** com o binário `btv-cli`, residente em
[`rust/cli/`](https://github.com/danzeroum/BuildToValueGovernance/tree/main/rust/cli).

## Pré-requisitos

- Rust toolchain (`rustup`).
- Uma evidência exportada do playground ou do gateway (JSON).

## Passo 1 — Compilar o CLI

```bash
cd rust && cargo build --release -p btv-cli
```

## Passo 2 — Verificar

O comando `verify` exige **dois insumos**: o hash da evidência e a assinatura
HMAC. Isso ensina o integrador o princípio fundamental da República
Algorítmica: **dado sem prova não tem valor**.

```bash
./target/release/btv-cli verify \
  --hash <hash hex extraído do header X-BTV-Evidence-Hash> \
  --signature <hmac hex>
```

Resposta esperada:

```
OK: assinatura válida.
  Tamanho da evidência: <valor constitucional, ver reference/index.md>
  Merkle root: <hex>
```

## Passo 3 — Falsificar para entender

Altere um caractere da assinatura e rode novamente. O CLI deve responder
`ERRO: assinatura inválida` com exit code `!= 0`. **Este é o comportamento
correto.**

## Próximo

- [Trilha do Legislador / Juiz — Tutorial 04](04-propose-policy.md).
- [Protocolo CAP](../cap-protocol.md).
