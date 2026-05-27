#!/usr/bin/env python3
"""
validate_policy_schema.py — Valida YAMLs de política contra policy.schema.json.

Usado pelo workflow `alignment_regression.yml` e pela Governance Console
(camada server-side antes de chamar `policy_signer.py`).

Fail-secure: exit code != 0 sempre que houver:
  - YAML mal formado;
  - Schema não encontrado;
  - Política rejeitada pelo schema (com mensagem detalhada).

Modo `--require-constitutional` torna `bias_declaration` e `jurisdiction`
obrigatórios — usado para PRs em `data/policies/` criados via Governance
Console (Painel 1, Fase 4).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "demo" / "dpo-ciso" / "schemas" / "policy.schema.json"


def load_schema() -> dict:
    if not SCHEMA_PATH.is_file():
        raise SystemExit(f"ERRO: schema ausente: {SCHEMA_PATH.relative_to(ROOT)}")
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate(path: Path, schema: dict, require_constitutional: bool) -> list[str]:
    try:
        import yaml
    except ImportError:
        raise SystemExit("ERRO: PyYAML não instalado. `pip install pyyaml`")
    try:
        import jsonschema
    except ImportError:
        raise SystemExit("ERRO: jsonschema não instalado. `pip install jsonschema`")

    if not path.is_file():
        return [f"{path}: arquivo não encontrado"]

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return [f"{path}: YAML inválido: {e}"]

    if not isinstance(doc, dict):
        return [f"{path}: documento raiz não é mapping"]

    errors: list[str] = []
    validator = jsonschema.Draft202012Validator(schema)
    for e in validator.iter_errors(doc):
        loc = "/".join(str(p) for p in e.absolute_path) or "<root>"
        errors.append(f"{path}: [{loc}] {e.message}")

    if require_constitutional:
        for field in ("bias_declaration", "jurisdiction"):
            if field not in doc:
                errors.append(
                    f"{path}: campo constitucional '{field}' obrigatório em "
                    f"--require-constitutional (CAP / ADR-072)"
                )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="YAML(s) a validar")
    parser.add_argument(
        "--require-constitutional",
        action="store_true",
        help="Falha se bias_declaration ou jurisdiction estiverem ausentes",
    )
    args = parser.parse_args()

    schema = load_schema()
    all_errors: list[str] = []
    for p in args.paths:
        errors = validate(p, schema, args.require_constitutional)
        if errors:
            all_errors.extend(errors)
        else:
            print(f"OK: {p}")

    if all_errors:
        print("", file=sys.stderr)
        for e in all_errors:
            print(f"ERRO: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
