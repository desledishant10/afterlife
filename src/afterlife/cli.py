from pathlib import Path

import typer
from rich.console import Console

from afterlife import db

app = typer.Typer(
    help="Afterlife — surface credentials that outlive their owners.",
    no_args_is_help=True,
)
scan_app = typer.Typer(help="Collect data from a source.", no_args_is_help=True)
app.add_typer(scan_app, name="scan")
console = Console()

DEFAULT_DB = Path("afterlife.db")


@app.command()
def init(db_path: Path = DEFAULT_DB) -> None:
    """Initialize the local database."""
    db.init_db(db_path)
    console.print(f"[green]OK[/green] initialized {db_path}")


@scan_app.command("aws")
def scan_aws(
    profile: str = typer.Option("default", help="AWS profile name"),
    region: str = typer.Option("us-east-1", help="AWS region"),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull IAM users, roles, access keys, and OAuth grants from AWS."""
    from afterlife.collectors.aws import AWSCollector

    n = AWSCollector(profile=profile, region=region, db_path=db_path).run()
    console.print(f"[green]OK[/green] collected {n} AWS records")


@scan_app.command("github")
def scan_github(
    token: str = typer.Option(..., envvar="GITHUB_TOKEN"),
    org: str = typer.Option(..., envvar="GITHUB_ORG"),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull org members, PATs, deploy keys, and OAuth apps from GitHub."""
    from afterlife.collectors.github import GitHubCollector

    n = GitHubCollector(token=token, org=org, db_path=db_path).run()
    console.print(f"[green]OK[/green] collected {n} GitHub records")


@scan_app.command("idp")
def scan_idp(
    provider: str = typer.Option("google", help="google | okta"),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull user inventory from the identity provider."""
    from afterlife.collectors.idp import build_idp_collector

    n = build_idp_collector(provider, db_path=db_path).run()
    console.print(f"[green]OK[/green] collected {n} identity records")


@app.command()
def analyze(db_path: Path = DEFAULT_DB) -> None:
    """Run all detection rules against collected data."""
    from afterlife.rules.registry import run_all

    findings = run_all(db_path)
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    console.print(f"\n[bold]{len(findings)}[/bold] findings")
    for sev, color in (
        ("critical", "red"),
        ("high", "magenta"),
        ("medium", "yellow"),
        ("low", "cyan"),
    ):
        if sev in by_severity:
            console.print(f"  [{color}]{by_severity[sev]:>4}[/{color}]  {sev}")


@app.command("list-rules")
def list_rules() -> None:
    """List all available detection rules."""
    from afterlife.rules.registry import all_rules

    for r in all_rules():
        console.print(
            f"[bold cyan]{r.id}[/bold cyan]  "
            f"[dim]{r.default_severity.value}[/dim]  {r.title}"
        )
        console.print(f"  [dim]{r.description}[/dim]")


@app.command()
def report(
    db_path: Path = DEFAULT_DB,
    fmt: str = typer.Option("json", "--format", help="json | html"),
) -> None:
    """Generate a report of findings."""
    from afterlife.reporting.json_report import write_json_report

    if fmt == "json":
        console.print(write_json_report(db_path))
    else:
        console.print("[yellow]HTML report planned for Week 9.[/yellow]")


if __name__ == "__main__":
    app()
