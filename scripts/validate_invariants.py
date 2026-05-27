#!/usr/bin/env python3
"""
validate_invariants.py — Verifica que invariantes documentais batem com a fonte Rust.

Roda no CI antes de `mkdocs build`. Falha (exit != 0) se:
- `autogen_reference.py --check` reportar drift.
- Markdown da seção `developer/` mencionar literais 9596 ou 9632 que não estejam
  em arquivos gerados (sinal de que alguém digitou manualmente um invariante).

A regra de "nunca digite manualmente" implementa o Insight 4 do Analista 3.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "docs" / "developer"
GENERATED = {DEV / "reference" / "index.md"}
INVARIANT_LITERALS = re.compile(r"\b(9596|9632)\b")


def main() -> int:
    rc = subprocess.call(
        [sys.executable, str(ROOT / "scripts" / "autogen_reference.py"), "--check"]
    )
    if rc != 0:
        return rc

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

    print("OK: invariantes consistentes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
