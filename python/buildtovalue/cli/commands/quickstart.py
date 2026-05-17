"""btv demo — lança o Trust OS em modo quickstart local."""
import subprocess
import sys
import time
import urllib.request
import os
import pathlib

import click

REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
COMPOSE_FILE = REPO_ROOT / "ops" / "docker-compose.quickstart.yml"
AGENT_MOCK = REPO_ROOT / "scripts" / "demo" / "agent_mock.py"

GATEWAY_URL = "http://localhost:8080"
DASHBOARD_URL = "http://localhost:8501"

BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def _check_docker() -> bool:
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _compose_up(compose_file: pathlib.Path) -> bool:
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "up", "-d", "--build"],
        capture_output=False,
    )
    return result.returncode == 0


def _wait_healthy(url: str, label: str, timeout: int = 90) -> bool:
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=3)
            click.echo(f"  {GREEN}✓{RESET} {label}")
            return True
        except Exception:
            attempt += 1
            click.echo(f"  aguardando {label}... ({attempt})", nl=False)
            click.echo("\r", nl=False)
            time.sleep(3)
    click.echo(f"  {RED}✗{RESET} {label} não respondeu em {timeout}s")
    return False


def _run_agent_mock() -> None:
    env = os.environ.copy()
    env["BTV_GATEWAY_URL"] = GATEWAY_URL
    subprocess.run([sys.executable, str(AGENT_MOCK)], env=env)


@click.command("demo")
@click.option(
    "--skip-build",
    is_flag=True,
    default=False,
    help="Pula o build das imagens Docker (usa imagens já construídas).",
)
@click.option(
    "--no-mock",
    is_flag=True,
    default=False,
    help="Não executa o agent_mock.py automaticamente após subir.",
)
def demo_cmd(skip_build: bool, no_mock: bool) -> None:
    """Lança o Trust OS localmente em modo demo (< 15 minutos)."""
    click.echo(f"\n{BOLD}BTV Trust OS — Quickstart{RESET}")
    click.echo(f"Compose: {COMPOSE_FILE.relative_to(REPO_ROOT)}\n")

    if not _check_docker():
        click.echo(
            f"{RED}Docker não encontrado ou não está rodando.{RESET}\n"
            "Instale em: https://docs.docker.com/get-docker/"
        )
        sys.exit(1)

    if not COMPOSE_FILE.exists():
        click.echo(f"{RED}Arquivo não encontrado: {COMPOSE_FILE}{RESET}")
        sys.exit(1)

    click.echo("Subindo serviços...")
    if skip_build:
        ok = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"],
            capture_output=False,
        ).returncode == 0
    else:
        ok = _compose_up(COMPOSE_FILE)

    if not ok:
        click.echo(f"{RED}Falha ao subir os containers. Verifique os logs acima.{RESET}")
        sys.exit(1)

    click.echo("\nAguardando health checks:")
    if not _wait_healthy(f"{GATEWAY_URL}/health", "gateway (8080)"):
        sys.exit(1)

    if not no_mock:
        click.echo("\nExecutando cenário de demo...")
        _run_agent_mock()

    click.echo(
        f"\n{GREEN}{BOLD}Tudo pronto!{RESET}\n"
        f"  Dashboard : {DASHBOARD_URL}\n"
        f"  Gateway   : {GATEWAY_URL}\n\n"
        "Para parar:\n"
        f"  docker compose -f ops/docker-compose.quickstart.yml down\n"
    )
