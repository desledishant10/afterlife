from pathlib import Path

import typer
from rich.console import Console

from afterlife import db

app = typer.Typer(
    help="Afterlife: surface credentials that outlive their owners.",
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
    from afterlife.scan_runs import record_run

    with record_run(db_path, "aws") as run:
        n = AWSCollector(profile=profile, region=region, db_path=db_path).run()
        run["records_collected"] = n
    console.print(f"[green]OK[/green] collected {n} AWS records")


@scan_app.command("github")
def scan_github(
    token: str = typer.Option(..., envvar="GITHUB_TOKEN"),
    org: str = typer.Option(..., envvar="GITHUB_ORG"),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull org members, PATs, deploy keys, and OAuth apps from GitHub."""
    from afterlife.collectors.github import GitHubCollector
    from afterlife.scan_runs import record_run

    with record_run(db_path, "github") as run:
        n = GitHubCollector(token=token, org=org, db_path=db_path).run()
        run["records_collected"] = n
    console.print(f"[green]OK[/green] collected {n} GitHub records")


@scan_app.command("idp")
def scan_idp(
    provider: str = typer.Option("google", help="google | okta"),
    service_account_file: Path | None = typer.Option(
        None,
        envvar="GOOGLE_SERVICE_ACCOUNT_JSON",
        help="Path to Google service account JSON (Google Workspace only).",
    ),
    admin_email: str | None = typer.Option(
        None,
        envvar="GOOGLE_ADMIN_EMAIL",
        help="Workspace super-admin to impersonate (Google Workspace only).",
    ),
    okta_domain: str | None = typer.Option(
        None,
        envvar="OKTA_DOMAIN",
        help="Okta domain (Okta only), e.g. myorg.okta.com.",
    ),
    okta_token: str | None = typer.Option(
        None,
        envvar="OKTA_API_TOKEN",
        help="Okta SSWS API token (Okta only).",
    ),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull user inventory from the identity provider."""
    from afterlife.collectors.idp import build_idp_collector
    from afterlife.scan_runs import record_run

    kwargs: dict = {}
    if provider == "google":
        kwargs["service_account_file"] = service_account_file
        kwargs["admin_email"] = admin_email
    elif provider == "okta":
        kwargs["domain"] = okta_domain
        kwargs["api_token"] = okta_token
    with record_run(db_path, provider) as run:
        n = build_idp_collector(provider, db_path=db_path, **kwargs).run()
        run["records_collected"] = n
    console.print(f"[green]OK[/green] collected {n} identity records")


@app.command()
def analyze(
    db_path: Path = DEFAULT_DB,
    allowlist: Path | None = typer.Option(
        None, "--allowlist", "-a",
        help="Path to a YAML allowlist of suppressions (see docs).",
    ),
) -> None:
    """Run all detection rules against collected data."""
    from afterlife.rules.registry import run_all

    findings = run_all(db_path, allowlist_path=allowlist)
    by_severity: dict[str, int] = {}
    suppressed_count = 0
    for f in findings:
        if f.suppressed:
            suppressed_count += 1
            continue
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    active_total = len(findings) - suppressed_count
    console.print(f"\n[bold]{active_total}[/bold] active findings"
                  f"{f' ({suppressed_count} suppressed)' if suppressed_count else ''}")
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
def identities(
    db_path: Path = DEFAULT_DB,
    cross_source_only: bool = typer.Option(
        False,
        "--cross-source-only/--all",
        help="Show only identities linked across 2+ source systems.",
    ),
) -> None:
    """Show identities grouped by linked person."""
    from afterlife.graph.identity_graph import IdentityGraph

    graph = IdentityGraph.from_db(db_path)
    persons = list(graph.persons())
    if cross_source_only:
        persons = [p for p in persons if p.is_cross_source]
    persons.sort(
        key=lambda p: (not p.is_cross_source, p.canonical_email or "zzz", -len(p.identities))
    )

    cross = sum(1 for p in persons if p.is_cross_source)
    sources = sorted({s for p in persons for s in p.sources})
    header = f"[bold]{len(persons)}[/bold] "
    header += "cross-source identities" if cross_source_only else "identities"
    header += f". Sources: [dim]{', '.join(sources) or 'none'}[/dim]"
    console.print(f"\n{header}")
    if not cross_source_only:
        console.print(f"  [green]{cross}[/green] cross-source")
        console.print(f"  [dim]{len(persons) - cross}[/dim] single-source")
    console.print()

    for person in persons:
        if person.canonical_email:
            label = f"[bold]{person.canonical_email}[/bold]"
            if person.is_cross_source:
                label += " [green](cross-source)[/green]"
            console.print(label)
            for identity in person.identities:
                console.print(
                    f"  [cyan]{identity.source:<7}[/cyan] {identity.source_id} "
                    f"[dim]({identity.status})[/dim]"
                )
        else:
            i = person.identities[0]
            console.print(
                f"[bold]{i.name or i.source_id}[/bold] "
                f"[dim]({i.source}, no email, unlinkable)[/dim]"
            )
        console.print()


@app.command()
def serve(
    db_path: Path = DEFAULT_DB,
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8000, help="Bind port."),
) -> None:
    """Launch the local web dashboard at http://host:port."""
    import uvicorn

    from afterlife.web import create_app

    if not db_path.exists():
        console.print(
            f"[red]DB not found at {db_path}.[/red] Run `afterlife init` first."
        )
        raise typer.Exit(1)

    web_app = create_app(db_path)
    console.print(
        f"[green]Afterlife dashboard:[/green] http://{host}:{port}  "
        f"[dim](Ctrl+C to stop)[/dim]"
    )
    uvicorn.run(web_app, host=host, port=port, log_level="warning")


@app.command()
def report(
    db_path: Path = DEFAULT_DB,
    fmt: str = typer.Option(
        "json", "--format", help="json | html | sarif | pdf"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write to a file instead of stdout."
    ),
) -> None:
    """Generate a report of findings."""
    if fmt == "pdf":
        from afterlife.reporting.pdf_report import (
            PdfDependencyError,
            write_pdf_report,
        )

        if output is None:
            console.print(
                "[red]PDF output requires --output (binary cannot be printed to stdout).[/red]"
            )
            raise typer.Exit(1)
        try:
            pdf_bytes = write_pdf_report(db_path)
        except PdfDependencyError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(1)
        output.write_bytes(pdf_bytes)
        console.print(f"[green]OK[/green] wrote {output} ({len(pdf_bytes)} bytes)")
        return

    if fmt == "json":
        from afterlife.reporting.json_report import write_json_report
        content = write_json_report(db_path)
    elif fmt == "html":
        from afterlife.reporting.html_report import write_html_report
        content = write_html_report(db_path)
    elif fmt == "sarif":
        from afterlife.reporting.sarif_report import write_sarif_report
        content = write_sarif_report(db_path)
    else:
        console.print(f"[red]Unknown format: {fmt}[/red]")
        raise typer.Exit(1)

    if output:
        output.write_text(content)
        console.print(f"[green]OK[/green] wrote {output}")
    else:
        # plain print: don't let rich inject ANSI codes into HTML/JSON/SARIF
        print(content)


if __name__ == "__main__":
    app()
