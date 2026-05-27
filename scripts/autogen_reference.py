#!/usr/bin/env python3
"""
autogen_reference.py — Gerador fail-secure da referência técnica do Portal do Desenvolvedor.

Lê constantes canônicas dos crates Rust (`rust/kernel`, `rust/btv-types`) e produz
`docs/developer/reference/index.md`. Se qualquer invariante esperado estiver ausente,
o script falha com exit code != 0 — aplica o princípio fail-secure à própria
infraestrutura de documentação (ver CHANGELOG_PHILOSOPHICAL.md e ADR-063).

Uso:
    python scripts/autogen_reference.py [--check]

    --check  Não escreve; falha se o arquivo gerado divergiria do existente.

Tratamento como artefato de Governança (Analista 3 #1):
- Acesso somente leitura ao Kernel.
- Sem credenciais HMAC/Ledger no runtime.
- Sujeito ao mesmo rigor de code review que componentes do gateway.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL_TYPES = ROOT / "rust" / "kernel" / "src" / "core" / "types.rs"
BTV_TYPES = ROOT / "rust" / "btv-types" / "src" / "lib.rs"
CARGO_TOML = ROOT / "rust" / "kernel" / "Cargo.toml"
OUT_PT = ROOT / "docs" / "developer" / "reference" / "index.md"
OUT_EN = ROOT / "docs" / "developer" / "reference" / "index.en.md"


class InvariantMissing(SystemExit):
    def __init__(self, name: str, path: Path):
        super().__init__(
            f"ERRO: invariante {name} não encontrado em {path.relative_to(ROOT)}\n"
            f"      fail-secure: abortando geração da referência."
        )


def read(path: Path) -> str:
    if not path.is_file():
        raise SystemExit(f"ERRO: arquivo de origem ausente: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def extract_const(src: str, name: str, path: Path) -> int:
    m = re.search(rf"pub\s+const\s+{re.escape(name)}\s*:\s*usize\s*=\s*(\d+)", src)
    if not m:
        raise InvariantMissing(name, path)
    return int(m.group(1))


def extract_size_assert(src: str, type_name: str, path: Path) -> int:
    pattern = (
        rf"std::mem::size_of::<(?:[\w:]+::)?{re.escape(type_name)}>\s*\(\s*\)\s*==\s*(\d+)"
    )
    m = re.search(pattern, src)
    if not m:
        raise InvariantMissing(f"const_assert_eq!(size_of::<{type_name}>())", path)
    return int(m.group(1))


def git_sha() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def kernel_version() -> str:
    try:
        with CARGO_TOML.open("rb") as f:
            data = tomllib.load(f)
        return data.get("package", {}).get("version", "unknown")
    except Exception:
        return "unknown"


def _extract_all() -> dict:
    kernel_src = read(KERNEL_TYPES)
    types_src = read(BTV_TYPES)
    evidence_size = extract_const(kernel_src, "EVIDENCE_SIZE", KERNEL_TYPES)
    hash_size = extract_const(kernel_src, "HASH_SIZE", KERNEL_TYPES)
    max_finding = extract_const(kernel_src, "MAX_FINDING_SIZE", KERNEL_TYPES)
    kernel_assert = extract_size_assert(kernel_src, "TechnicalEvidence", KERNEL_TYPES)
    wire_assert = extract_size_assert(types_src, "TechnicalEvidence", BTV_TYPES)
    if kernel_assert != evidence_size:
        raise SystemExit(
            f"ERRO: divergência interna no kernel: EVIDENCE_SIZE={evidence_size} "
            f"≠ const_assert={kernel_assert}. Corrija o código antes de gerar docs."
        )
    return dict(
        evidence_size=evidence_size,
        hash_size=hash_size,
        max_finding=max_finding,
        kernel_assert=kernel_assert,
        wire_assert=wire_assert,
        sha=git_sha(),
        version=kernel_version(),
    )


def build_doc_pt() -> str:
    v = _extract_all()
    evidence_size = v["evidence_size"]; hash_size = v["hash_size"]
    max_finding = v["max_finding"]; kernel_assert = v["kernel_assert"]
    wire_assert = v["wire_assert"]; sha = v["sha"]; version = v["version"]

    return f"""---
title: Referência Técnica
---

# Referência Técnica (gerada)

> **Gerado automaticamente** por `scripts/autogen_reference.py` a partir dos crates
> Rust. **Não edite manualmente.** Qualquer alteração será sobrescrita no próximo
> build.
>
> - Commit: `{sha}`
> - Versão do kernel: `{version}`
> - Fonte: [`rust/kernel/src/core/types.rs`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/rust/kernel/src/core/types.rs), [`rust/btv-types/src/lib.rs`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/rust/btv-types/src/lib.rs)

## Anatomia da `TechnicalEvidence`

A struct `TechnicalEvidence` possui **dois tamanhos canônicos coexistentes** —
cada um servindo um propósito arquitetural distinto. Esta dualidade é uma decisão
deliberada documentada no [ADR-063](../../adr/0063-technical-evidence-size-invariant.md)
e detalhada no [`CHANGELOG_PHILOSOPHICAL.md`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/CHANGELOG_PHILOSOPHICAL.md).

| Atributo | Kernel (Operacional) | `btv-types` (Constitucional) |
| --- | --- | --- |
| **Tamanho** | **{kernel_assert} bytes** | **{wire_assert} bytes** |
| **Arquivo** | `rust/kernel/src/core/types.rs` | `rust/btv-types/src/lib.rs` |
| **Propósito** | Estado operacional completo no kernel | Formato de wire transmitido entre componentes |
| **Validação** | `const_assert_eq!(size_of::<TechnicalEvidence>() == {kernel_assert})` | `const_assert_eq!(size_of::<TechnicalEvidence>() == {wire_assert})` |
| **Produzido por** | Construção interna do kernel | `Verdict::to_technical_evidence()` |

!!! warning "Qual valor usar?"
    Se você está **integrando** com o gateway (consumindo evidências por HTTP/IPC),
    use o tamanho **constitucional** ({wire_assert} bytes). Se você está
    **contribuindo** para o kernel, use o tamanho **operacional** ({kernel_assert} bytes).
    Documentação que referencie "o tamanho" sem qualificador deve ser tratada como
    incompleta — exija a qualificação antes de agir.

## Constantes do Kernel

| Constante | Valor | Significado |
| --- | --- | --- |
| `EVIDENCE_SIZE` | `{evidence_size}` | Tamanho operacional da `TechnicalEvidence` |
| `HASH_SIZE` | `{hash_size}` | Bytes de um hash canônico (BLAKE3/SHA-256) |
| `MAX_FINDING_SIZE` | `{max_finding}` | Limite superior de um finding individual |

## Verificação fora do navegador

```bash
# Conferir o tamanho operacional in situ
cargo run -p btv-cli -- verify --hash <HASH_HEX> --signature <HMAC_HEX>
```

Veja o [tutorial de verificação criptográfica](../tutorials/03-verify-evidence-cli.md).
"""


def build_doc_en() -> str:
    v = _extract_all()
    evidence_size = v["evidence_size"]; hash_size = v["hash_size"]
    max_finding = v["max_finding"]; kernel_assert = v["kernel_assert"]
    wire_assert = v["wire_assert"]; sha = v["sha"]; version = v["version"]

    return f"""---
title: Technical Reference
---

# Technical Reference (generated)

> **Auto-generated** by `scripts/autogen_reference.py` from the Rust crates.
> **Do not edit manually.** Any change will be overwritten on the next build.
>
> - Commit: `{sha}`
> - Kernel version: `{version}`
> - Source: [`rust/kernel/src/core/types.rs`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/rust/kernel/src/core/types.rs), [`rust/btv-types/src/lib.rs`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/rust/btv-types/src/lib.rs)

## Anatomy of `TechnicalEvidence`

The `TechnicalEvidence` struct has **two coexisting canonical sizes** — each
serving a distinct architectural purpose. This duality is a deliberate decision
documented in [ADR-063](../../adr/0063-technical-evidence-size-invariant.md)
and detailed in [`CHANGELOG_PHILOSOPHICAL.md`](https://github.com/danzeroum/BuildToValueGovernance/blob/main/CHANGELOG_PHILOSOPHICAL.md).

| Attribute | Kernel (Operational) | `btv-types` (Constitutional) |
| --- | --- | --- |
| **Size** | **{kernel_assert} bytes** | **{wire_assert} bytes** |
| **File** | `rust/kernel/src/core/types.rs` | `rust/btv-types/src/lib.rs` |
| **Purpose** | Complete operational state inside the kernel | Wire format transmitted between components |
| **Validation** | `const_assert_eq!(size_of::<TechnicalEvidence>() == {kernel_assert})` | `const_assert_eq!(size_of::<TechnicalEvidence>() == {wire_assert})` |
| **Produced by** | Internal kernel construction | `Verdict::to_technical_evidence()` |

!!! warning "Which value should I use?"
    If you are **integrating** with the gateway (consuming evidence over HTTP/IPC),
    use the **constitutional** size ({wire_assert} bytes). If you are
    **contributing** to the kernel, use the **operational** size ({kernel_assert} bytes).
    Documentation that mentions "the size" without a qualifier must be treated as
    incomplete — demand the qualifier before acting.

## Kernel constants

| Constant | Value | Meaning |
| --- | --- | --- |
| `EVIDENCE_SIZE` | `{evidence_size}` | Operational size of `TechnicalEvidence` |
| `HASH_SIZE` | `{hash_size}` | Bytes of a canonical hash (BLAKE3/SHA-256) |
| `MAX_FINDING_SIZE` | `{max_finding}` | Upper bound of an individual finding |

## Out-of-browser verification

```bash
# Inspect the operational size in situ
cargo run -p btv-cli -- verify --hash <HASH_HEX> --signature <HMAC_HEX>
```

See the [cryptographic verification tutorial](../tutorials/03-verify-evidence-cli.md).
"""


def _write_or_check(path: Path, content: str, check: bool) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    if check:
        if not path.is_file():
            print(f"ERRO: {path.relative_to(ROOT)} não existe; rode sem --check.", file=sys.stderr)
            return 1
        if path.read_text(encoding="utf-8") != content:
            print(f"ERRO: {path.relative_to(ROOT)} está desatualizado.", file=sys.stderr)
            return 1
        print(f"OK: {path.relative_to(ROOT)} está sincronizado.")
        return 0
    path.write_text(content, encoding="utf-8")
    print(f"OK: gerado {path.relative_to(ROOT)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Falha se o arquivo divergir.")
    args = parser.parse_args()

    rc_pt = _write_or_check(OUT_PT, build_doc_pt(), args.check)
    rc_en = _write_or_check(OUT_EN, build_doc_en(), args.check)
    return rc_pt or rc_en


if __name__ == "__main__":
    raise SystemExit(main())
