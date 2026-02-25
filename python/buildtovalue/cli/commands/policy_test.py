"""
CLI: btv policy-test — Rawls Blind Testing (ADR-042).

Uso:
    btv policy-test --policy default --seed 42
    btv policy-test --policy medical --ci   # exit 1 se gate falhar
"""

import json
import sys
import click
from buildtovalue.governance.policy_tester import PolicyTester


@click.command("policy-test")
@click.option("--policy",  default="default", show_default=True,
              help="Nome da policy a testar")
@click.option("--seed",    default=42,        show_default=True, type=int,
              help="Seed determinístico do dataset")
@click.option("--epoch",   default="current", show_default=True,
              help="Epoch do PatternRegistry (ADR-033)")
@click.option("--gateway", default="http://localhost:8080", show_default=True,
              help="URL do gateway Axum")
@click.option("--ci",      is_flag=True,
              help="Modo CI: exit 1 se ci_gate_passed=False")
@click.option("--output",  type=click.Path(), default=None,
              help="Salvar relatório JSON em arquivo")
@click.option("--verbose", is_flag=True, help="Mostrar todos os casos")
def policy_test_cmd(policy, seed, epoch, gateway, ci, output, verbose):
    """Rawls Blind Testing — testa policy com dataset sintético determinístico."""
    click.echo(f"🔍 Rawls Blind Testing: policy={policy} seed={seed} epoch={epoch}")

    tester = PolicyTester(gateway_url=gateway)
    report = tester.run_blind_test(policy_name=policy, seed=seed, epoch=epoch)

    # ── Sumário ───────────────────────────────────────────────
    status = "✅ PASS" if report.ci_gate_passed else "❌ FAIL"
    click.echo(f"\n{status} — {report.passed}/{report.total_cases} casos")
    click.echo(f"  pass_rate:   {report.pass_rate:.1%}")
    click.echo(f"  coverage:    {report.coverage_pct:.1%}")
    click.echo(f"  equity_ok:   {report.equity_ok}")
    click.echo(f"  duration:    {report.duration_ms:.1f}ms")
    click.echo(f"  fingerprint: {report.blake3_fingerprint}")

    if report.equity_details:
        click.echo(f"  fpr_by_group: {report.equity_details.get('fpr_by_group', {})}")
        click.echo(f"  max_divergence: {report.equity_details.get('max_divergence', 0):.4f}")

    # ── Verbose: casos com falha ───────────────────────────────
    if verbose or not report.ci_gate_passed:
        failed = [r for r in report.results if not r.passed]
        if failed:
            click.echo(f"\n  Falhas ({len(failed)}):")
            for r in failed:
                click.echo(
                    f"    [{r.case_id}] {r.category.value}: "
                    f"expected={r.expected_action} actual={r.actual_action}"
                    + (f" error={r.error}" if r.error else "")
                )

    # ── Output JSON ───────────────────────────────────────────
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
        click.echo(f"\n  Relatório salvo em: {output}")

    # ── CI gate ───────────────────────────────────────────────
    if ci and not report.ci_gate_passed:
        click.echo(
            "\n❌ CI gate falhou: "
            f"pass_rate={report.pass_rate:.1%} (mínimo 95%) "
            f"equity_ok={report.equity_ok}"
        )
        sys.exit(1)
