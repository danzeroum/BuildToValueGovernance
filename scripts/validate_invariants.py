#!/usr/bin/env python3
"""
validate_invariants.py — Verifica que invariantes documentais batem com a fonte Rust
e que toda página referenciada no nav do mkdocs tem par .en.md.

Roda no CI antes de `mkdocs build`. Falha (exit != 0) se:
- `autogen_reference.py --check` reportar drift.
- Markdown da seção `developer/` mencionar literais 9596 ou 9632 que não estejam
  em arquivos gerados (sinal de que alguém digitou manualmente um invariante).
- Qualquer arquivo `.md` referenciado pelo `nav` do `mkdocs.yml` não tiver
  par `.en.md` (R16 do RISK_REGISTER — quebra UX em /en/).

A regra de "nunca digite manualmente" implementa o Insight 4 do Analista 3.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
DEV = DOCS / "developer"
MKDOCS_YML = ROOT / "mkdocs.yml"
GENERATED = {
    DEV / "reference" / "index.md",
    DEV / "reference" / "index.en.md",
}
INVARIANT_LITERALS = re.compile(r"\b(9596|9632)\b")
NAV_REF = re.compile(r"(?m)^[\s-]*[^:#\n]*:\s*([A-Za-z][^\s]*\.md)\s*$")


def _check_invariant_literals() -> int:
    if not DEV.is_dir():
        return 0
    bad: list[tuple[Path, int, str]] = []
    for md in DEV.rglob("*.md"):
        if md in GENERATED:
            continue
        for i, line in enumerate(md.read_text(encoding="utf-8").splitlines(), 1):
            if INVARIANT_LITERALS.search(line):
                bad.append((md, i, line.strip()))
    if bad:
        print("ERRO: literais de invariante (9596/9632) digitados manualmente:", file=sys.stderr)
        for path, lineno, text in bad:
            print(f"  {path.relative_to(ROOT)}:{lineno}: {text}", file=sys.stderr)
        print("Use referência ao arquivo gerado em reference/index.md.", file=sys.stderr)
        return 1
    return 0


def _check_en_pairs() -> int:
    """R16: toda página referenciada pelo nav do mkdocs.yml deve ter par .en.md."""
    if not MKDOCS_YML.is_file():
        return 0
    text = MKDOCS_YML.read_text(encoding="utf-8")
    refs = set(NAV_REF.findall(text))
    missing: list[str] = []
    for ref in sorted(refs):
        if ref.endswith(".en.md"):
            continue
        pt = DOCS / ref
        en = DOCS / (ref[:-3] + ".en.md")
        if pt.is_file() and not en.is_file():
            missing.append(f"docs/{ref}  →  docs/{en.relative_to(DOCS)} (ausente)")
    if missing:
        print("ERRO: páginas referenciadas pelo nav sem par .en.md:", file=sys.stderr)
        for m in missing:
            print(f"  {m}", file=sys.stderr)
        print("Crie a versão inglesa antes de mergear (R16 do RISK_REGISTER).", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    rc = subprocess.call(
        [sys.executable, str(ROOT / "scripts" / "autogen_reference.py"), "--check"]
    )
    if rc != 0:
        return rc
    rc = _check_invariant_literals()
    if rc != 0:
        return rc
    rc = _check_en_pairs()
    if rc != 0:
        return rc
    print("OK: invariantes consistentes e cobertura i18n completa.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
