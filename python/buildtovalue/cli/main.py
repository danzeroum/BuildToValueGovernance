"""BuildToValue CLI entrypoint"""
import click

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """BuildToValue Sovereign Trust OS CLI"""
    pass

@cli.command()
def version():
    """Show version"""
    click.echo("BuildToValue v2.2.0")

if __name__ == "__main__":
    cli()
