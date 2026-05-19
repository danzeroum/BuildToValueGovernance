"""BuildToValue CLI entrypoint"""
import click

from buildtovalue.cli.commands.arena_demo import arena_demo_cmd
from buildtovalue.cli.commands.quickstart import demo_cmd


@click.group()
@click.version_option(version="0.1.0a1")
def cli():
    """BuildToValue Sovereign Trust OS CLI"""
    pass

@cli.command()
def version():
    """Show version"""
    click.echo("BuildToValue v2.2.0")


cli.add_command(arena_demo_cmd)
cli.add_command(demo_cmd)


if __name__ == "__main__":
    cli()
