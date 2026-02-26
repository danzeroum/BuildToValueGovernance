"""
PolicyTester Runner v1.0.0 — CLI para CI/CD (ADR-042).

Uso:
    python -m buildtovalue.governance.policy_tester_runner \\
        --policy data/policies/core/default.yaml \\
        --epoch-file /tmp/epoch_state.json \\
        --fail-on-gate-fail

Exit codes: 0 = passou | 1 = gate falhou ou erro fatal

≤ 200 linhas
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PolicyTester CI Runner (ADR-042)")
    p.add_argument("--policy",            required=True,  help="Caminho para YAML da policy")
    p.add_argument("--epoch-file",        required=True,  help="JSON com {epoch, last_test_epoch}")
    p.add_argument("--fail-on-gate-fail", action="store_true")
    p.add_argument("--cases",             type=int, default=200)
    p.add_argument("--gateway",           default="http://localhost:8080")
    p.add_argument("--output",            default=None,   help="Salvar relatório JSON")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    policy_path = Path(args.policy)
    if not policy_path.exists():
        print(f"[PolicyTester] ERRO: policy não encontrada: {policy_path}", file=sys.stderr)
        return 1

    epoch_path = Path(args.epoch_file)
    if not epoch_path.exists():
        epoch_data: dict = {"epoch": 0, "last_test_epoch": -1}
    else:
        epoch_data = json.loads(epoch_path.read_text())

    current_epoch   = epoch_data.get("epoch", 0)
    last_test_epoch = epoch_data.get("last_test_epoch", -1)

    # Epoch binding: pular se epoch não mudou
    if current_epoch == last_test_epoch:
        print(f"[PolicyTester] Epoch {current_epoch} já testado. Pulando.")
        return 0

    # Importações lazy (não penaliza startup do CLI em outros contextos)
    from buildtovalue.governance.policy_tester import PolicyTester
    from buildtovalue.governance.pattern_registry_client import get_current_epoch

    policy_yaml_text = policy_path.read_text(encoding="utf-8")
    policy_id        = policy_path.stem

    tester = PolicyTester(gateway_url=args.gateway)

    try:
        report = tester.run_blind_test(
            policy_name=policy_id,
            seed=current_epoch ^ hash(policy_id) & 0xFFFF_FFFF,
            epoch=str(current_epoch),
        )
    except Exception as exc:
        # Fail-secure: qualquer erro → exit 1 (nunca bypass silencioso)
        print(f"[PolicyTester] FALHA inesperada: {exc}", file=sys.stderr)
        return 1

    print(report.explain_decision())

    if args.output:
        Path(args.output).write_text(
            json.dumps(report.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        print(f"[PolicyTester] Relatório salvo em {args.output}")

    # Atualizar epoch para próxima execução
    epoch_data["last_test_epoch"] = current_epoch
    epoch_path.write_text(json.dumps(epoch_data, indent=2))

    if not report.ci_gate_passed:
        print("[PolicyTester] ❌ CI GATE FAILED", file=sys.stderr)
        return 1 if args.fail_on_gate_fail else 0

    print("[PolicyTester] ✅ CI GATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())