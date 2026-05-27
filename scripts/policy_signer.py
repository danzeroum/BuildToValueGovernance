#!/usr/bin/env python3
"""
policy_signer.py — Assina YAMLs de política conforme ADR-064 (Ed25519).

Esta ferramenta NUNCA toca o runtime do BTV. Ela:
  1. Valida estaticamente o YAML (front-matter mínimo, presença de campos
     constitucionais quando aplicável).
  2. Calcula HMAC-SHA256 do conteúdo (cadeia de integridade local).
  3. Produz arquivo `.sig` com assinatura Ed25519 da Ethics Committee.

Fluxo de uso (do plano do Governance Console, Fase 0/4):

    UI (DPO) → JSON Schema → validate_policy_schema.py → policy_signer.py
        → PR em data/policies/ → CI (alignment_regression + policy-blind-test)
        → merge manual → kernel faz reload Ed25519 (ADR-064)

ADR-064: a chave privada Ed25519 mora exclusivamente com a Ethics Committee;
o servidor verifica com a chave pública e nunca tem a privada.

Tratamento como artefato de Governança (R9 do RISK_REGISTER):
- Sem credenciais HMAC/Ledger no runtime.
- Code-review obrigatório em qualquer mudança aqui.
- Exit code != 0 sempre que houver ambiguidade — fail-secure.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERRO: PyYAML não instalado. `pip install pyyaml`", file=sys.stderr)
    raise SystemExit(2)

# Campos constitucionais: warning-only por compatibilidade com YAMLs legados.
# A partir de novas políticas (CAP — Protocolo de Emenda Constitucional),
# bias_declaration e jurisdiction são REQUIRED — validate_policy_schema.py
# bloqueia o merge.
SOFT_REQUIRED_FIELDS = ("bias_declaration", "jurisdiction")


def warn(msg: str) -> None:
    print(f"AVISO: {msg}", file=sys.stderr)


def err(msg: str, code: int = 1) -> "SystemExit":
    return SystemExit(f"ERRO: {msg}")


def load_yaml(path: Path) -> dict:
    if not path.is_file():
        raise err(f"arquivo não encontrado: {path}")
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise err(f"YAML inválido em {path}: {e}")


def check_soft_fields(doc: dict, path: Path) -> None:
    for field in SOFT_REQUIRED_FIELDS:
        if field not in doc and not _contains_key(doc, field):
            warn(f"{path}: campo recomendado ausente: '{field}'")


def _contains_key(node, key: str) -> bool:
    if isinstance(node, dict):
        if key in node:
            return True
        return any(_contains_key(v, key) for v in node.values())
    if isinstance(node, list):
        return any(_contains_key(v, key) for v in node)
    return False


def hmac_sha256(content: bytes, key: bytes) -> str:
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def ed25519_sign(content: bytes, private_key_pem: bytes) -> bytes:
    """Assina com Ed25519. Requer `cryptography`."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise err("chave privada não é Ed25519")
    return key.sign(content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("yaml_path", type=Path, help="YAML de política a assinar")
    parser.add_argument(
        "--private-key",
        type=Path,
        default=None,
        help="Chave privada Ed25519 PEM. Default: $BTV_POLICY_SIGNING_KEY. "
             "Sem chave, opera em modo dry-run (apenas HMAC local).",
    )
    parser.add_argument(
        "--hmac-key",
        default=os.environ.get("BTV_POLICY_HMAC_KEY", ""),
        help="Chave HMAC para cadeia de integridade local. "
             "Default: $BTV_POLICY_HMAC_KEY.",
    )
    parser.add_argument(
        "--out-sig",
        type=Path,
        default=None,
        help="Caminho do arquivo .sig. Default: <yaml_path>.sig",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Falha (exit 1) se campos constitucionais estiverem ausentes.",
    )
    args = parser.parse_args()

    doc = load_yaml(args.yaml_path)
    missing = [f for f in SOFT_REQUIRED_FIELDS if not _contains_key(doc, f)]
    if missing and args.strict:
        raise err(
            f"{args.yaml_path}: campos constitucionais ausentes em modo --strict: "
            f"{', '.join(missing)}"
        )
    check_soft_fields(doc, args.yaml_path)

    content = args.yaml_path.read_bytes()

    hmac_key = args.hmac_key.encode("utf-8") if args.hmac_key else b""
    hmac_hex = hmac_sha256(content, hmac_key) if hmac_key else "(sem HMAC: defina $BTV_POLICY_HMAC_KEY)"

    if args.private_key is None:
        env_key = os.environ.get("BTV_POLICY_SIGNING_KEY", "")
        if env_key and Path(env_key).is_file():
            args.private_key = Path(env_key)

    sig_path = args.out_sig or args.yaml_path.with_suffix(args.yaml_path.suffix + ".sig")

    if args.private_key is None:
        print(f"[dry-run] HMAC-SHA256: {hmac_hex}")
        print(f"[dry-run] Para emitir assinatura real, forneça --private-key "
              f"ou exporte $BTV_POLICY_SIGNING_KEY.", file=sys.stderr)
        return 0

    sig = ed25519_sign(content, args.private_key.read_bytes())
    sig_path.write_bytes(sig)

    print(f"OK: assinado {args.yaml_path}")
    print(f"    Ed25519 sig: {sig_path} ({len(sig)} bytes)")
    print(f"    HMAC-SHA256: {hmac_hex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
