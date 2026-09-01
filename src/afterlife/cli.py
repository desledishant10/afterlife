import os
from pathlib import Path

import typer
from rich.console import Console

from afterlife import __version__, db

app = typer.Typer(
    help="Afterlife: surface credentials that outlive their owners.",
    no_args_is_help=True,
)
scan_app = typer.Typer(help="Collect data from a source.", no_args_is_help=True)
app.add_typer(scan_app, name="scan")
console = Console()

DEFAULT_DB = Path("afterlife.db")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"afterlife {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the Afterlife version and exit.",
    ),
) -> None:
    """Afterlife: surface credentials that outlive their owners."""


@app.command()
def init(db_path: Path = DEFAULT_DB) -> None:
    """Initialize the local database."""
    db.init_db(db_path)
    console.print(f"[green]OK[/green] initialized {db_path}")


@scan_app.command("aws")
def scan_aws(
    profile: str | None = typer.Option(
        None, envvar="AWS_PROFILE",
        help="AWS profile name (default: boto3 credential chain).",
    ),
    region: str | None = typer.Option(
        None, envvar="AWS_REGION",
        help="AWS region (default: boto3 default region).",
    ),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull IAM users, roles, and access keys from AWS."""
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
    """Pull org members, outside collaborators, App installations, and deploy keys from GitHub."""
    from afterlife.collectors.github import GitHubCollector
    from afterlife.scan_runs import record_run

    with record_run(db_path, "github") as run:
        n = GitHubCollector(token=token, org=org, db_path=db_path).run()
        run["records_collected"] = n
    console.print(f"[green]OK[/green] collected {n} GitHub records")


@scan_app.command("vault")
def scan_vault(
    token: str = typer.Option(..., envvar="VAULT_TOKEN"),
    api_url: str = typer.Option(..., envvar="VAULT_ADDR",
                                help="Base URL of the Vault server."),
    namespace: str | None = typer.Option(
        None, envvar="VAULT_NAMESPACE",
        help="Vault Enterprise namespace (optional).",
    ),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull identity entities and their cross-system aliases from Vault."""
    from afterlife.collectors.vault import VaultCollector
    from afterlife.scan_runs import record_run

    with record_run(db_path, "vault") as run:
        n = VaultCollector(
            db_path=db_path,
            token=token,
            api_url=api_url,
            namespace=namespace,
        ).run()
        run["records_collected"] = n
    console.print(f"[green]OK[/green] collected {n} Vault records")


@scan_app.command("slack")
def scan_slack(
    token: str = typer.Option(..., envvar="SLACK_TOKEN"),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull workspace members from Slack (users.list)."""
    from afterlife.collectors.slack import SlackCollector
    from afterlife.scan_runs import record_run

    with record_run(db_path, "slack") as run:
        n = SlackCollector(token=token, db_path=db_path).run()
        run["records_collected"] = n
    console.print(f"[green]OK[/green] collected {n} Slack records")


@scan_app.command("gcp")
def scan_gcp(
    project: str = typer.Option(..., envvar="GCP_PROJECT"),
    service_account_file: Path | None = typer.Option(
        None,
        envvar="GCP_SERVICE_ACCOUNT_JSON",
        help="Path to a service account JSON with iam.serviceAccounts.list permission.",
    ),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull service accounts and SA keys from one GCP project."""
    from afterlife.collectors.gcp_iam import GCPIAMCollector
    from afterlife.scan_runs import record_run

    with record_run(db_path, "gcp") as run:
        n = GCPIAMCollector(
            db_path=db_path,
            project=project,
            service_account_file=service_account_file,
        ).run()
        run["records_collected"] = n
    console.print(f"[green]OK[/green] collected {n} GCP records")


@scan_app.command("gitlab")
def scan_gitlab(
    token: str = typer.Option(..., envvar="GITLAB_TOKEN"),
    group: str = typer.Option(..., envvar="GITLAB_GROUP"),
    api_url: str = typer.Option(
        "https://gitlab.com/api/v4",
        envvar="GITLAB_API_URL",
        help="Base URL for self-hosted GitLab.",
    ),
    db_path: Path = DEFAULT_DB,
) -> None:
    """Pull group members and project deploy keys from a GitLab group."""
    from afterlife.collectors.gitlab import GitLabCollector
    from afterlife.scan_runs import record_run

    with record_run(db_path, "gitlab") as run:
        n = GitLabCollector(
            token=token, group=group, db_path=db_path, api_url=api_url
        ).run()
        run["records_collected"] = n
    console.print(f"[green]OK[/green] collected {n} GitLab records")


@scan_app.command("idp")
def scan_idp(
    provider: str = typer.Option(
        "google", envvar="IDP_PROVIDER", help="google | okta | azure"
    ),
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
    azure_tenant_id: str | None = typer.Option(
        None, envvar="AZURE_TENANT_ID",
        help="Entra ID tenant id (Azure only).",
    ),
    azure_client_id: str | None = typer.Option(
        None, envvar="AZURE_CLIENT_ID",
        help="Entra ID app registration client id (Azure only).",
    ),
    azure_client_secret: str | None = typer.Option(
        None, envvar="AZURE_CLIENT_SECRET",
        help="Entra ID app registration client secret (Azure only).",
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
    elif provider == "azure":
        kwargs["tenant_id"] = azure_tenant_id
        kwargs["client_id"] = azure_client_id
        kwargs["client_secret"] = azure_client_secret
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
    notify: bool = typer.Option(
        False, "--notify",
        help="Alert on new/reopened findings via channels configured in the "
             "environment (AFTERLIFE_SLACK_WEBHOOK / AFTERLIFE_WEBHOOK_URL / SMTP).",
    ),
    slack_webhook: str | None = typer.Option(
        None, "--slack-webhook",
        help="Slack Incoming Webhook URL (implies --notify).",
    ),
    webhook: str | None = typer.Option(
        None, "--webhook",
        help="Generic webhook URL to POST alerts to (implies --notify).",
    ),
    notify_min_severity: str | None = typer.Option(
        None, "--notify-min-severity",
        help="Minimum severity to alert on: critical | high | medium | low "
             "(default high, or AFTERLIFE_NOTIFY_MIN_SEVERITY).",
    ),
) -> None:
    """Run all detection rules against collected data."""
    from afterlife.rules.registry import run_analysis

    findings, delta = run_analysis(db_path, allowlist_path=allowlist)
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

    # Since-last-scan delta: the monitoring signal. New/reopened findings are
    # what a reviewer (or an alert) should act on; resolved ones are progress.
    changes = []
    if delta.new:
        changes.append(f"[green]+{delta.new} new[/green]")
    if delta.reopened:
        changes.append(f"[yellow]+{delta.reopened} reopened[/yellow]")
    if delta.resolved:
        changes.append(f"[dim]-{delta.resolved} resolved[/dim]")
    if changes:
        console.print("\nSince last analyze: " + ", ".join(changes))
    else:
        console.print("\n[dim]No change since last analyze.[/dim]")

    if notify or slack_webhook or webhook:
        _dispatch_alerts(findings, delta, slack_webhook, webhook, notify_min_severity)


def _dispatch_alerts(findings, delta, slack_webhook, webhook, min_severity_str) -> None:
    from afterlife.models import Severity
    from afterlife.notify import NotifyConfig, notify_findings

    config = NotifyConfig.from_env()
    if slack_webhook:
        config.slack_webhook = slack_webhook
    if webhook:
        config.webhook_url = webhook
    if min_severity_str:
        try:
            config.min_severity = Severity(min_severity_str.strip().lower())
        except ValueError:
            console.print(
                f"[yellow]Ignoring unknown --notify-min-severity "
                f"'{min_severity_str}'[/yellow]"
            )

    if not config.has_channels():
        console.print(
            "\n[yellow]Notifications requested but no channels configured.[/yellow] "
            "Set AFTERLIFE_SLACK_WEBHOOK / AFTERLIFE_WEBHOOK_URL / SMTP env vars, "
            "or pass --slack-webhook / --webhook."
        )
        return

    results = notify_findings(findings, delta, config)
    if not results:
        console.print(
            f"\n[dim]Nothing to alert on (no new/reopened findings at or above "
            f"{config.min_severity.value}).[/dim]"
        )
        return
    console.print()
    for channel, status in results.items():
        color = "green" if status == "sent" else "red"
        console.print(f"  [{color}]notify:{channel}[/{color}]  {status}")


def _build_run_config(
    config_path: Path | None,
    sources: list[str],
    db_path: Path | None,
    allowlist: Path | None,
    notify: bool,
    interval: int | None,
):
    from afterlife.notify import NotifyConfig
    from afterlife.runner import RunConfig, detect_sources

    env = dict(os.environ)
    cfg = RunConfig.from_yaml(config_path, env) if config_path else RunConfig(sources=[])
    if sources:
        cfg.sources = list(sources)
    if not cfg.sources:
        cfg.sources = detect_sources(env)
    if db_path is not None:
        cfg.db_path = db_path
    if allowlist is not None:
        cfg.allowlist = allowlist
    if interval is not None:
        cfg.interval_seconds = interval
    if notify:
        cfg.notify = True
    if cfg.notify and cfg.notify_config is None:
        cfg.notify_config = NotifyConfig.from_env(env)
    return cfg


def _emit(msg: str) -> None:
    console.print(f"  [dim]•[/dim] {msg}")


@app.command()
def run(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="YAML run config (sources, notify, interval)."
    ),
    source: list[str] = typer.Option(
        [], "--source", "-s",
        help="Source to scan (repeatable): aws, github, gitlab, slack, vault, "
             "gcp, idp. Overrides config; defaults to whatever the environment "
             "has credentials for.",
    ),
    db_path: Path | None = typer.Option(None, "--db-path"),
    allowlist: Path | None = typer.Option(None, "--allowlist", "-a"),
    notify: bool = typer.Option(False, "--notify"),
) -> None:
    """Scan configured sources, analyze, and optionally notify. One pass."""
    from afterlife.runner import run_pipeline

    cfg = _build_run_config(config, source, db_path, allowlist, notify, None)
    console.print(
        f"[bold]run[/bold] db={cfg.db_path} sources={', '.join(cfg.sources) or '(none)'}"
    )
    result = run_pipeline(cfg, emit=_emit)
    failed = [s.source for s in result.sources if s.error]
    if failed:
        console.print(f"[yellow]{len(failed)} source(s) skipped/failed: "
                      f"{', '.join(failed)}[/yellow]")


@app.command()
def watch(
    config: Path | None = typer.Option(
        None, "--config", "-c", help="YAML run config (sources, notify, interval)."
    ),
    source: list[str] = typer.Option(
        [], "--source", "-s", help="Source to scan (repeatable). Overrides config."
    ),
    db_path: Path | None = typer.Option(None, "--db-path"),
    allowlist: Path | None = typer.Option(None, "--allowlist", "-a"),
    notify: bool = typer.Option(False, "--notify"),
    interval: int | None = typer.Option(
        None, "--interval", "-i", help="Seconds between cycles (default 3600)."
    ),
) -> None:
    """Continuously scan, analyze, and notify on an interval (Ctrl-C to stop)."""
    from afterlife.runner import watch as run_watch

    cfg = _build_run_config(config, source, db_path, allowlist, notify, interval)
    console.print(
        f"[green]watching[/green] {', '.join(cfg.sources) or '(none)'} "
        f"every {cfg.interval_seconds}s. Ctrl-C to stop."
    )
    try:
        run_watch(cfg, emit=_emit)
    except KeyboardInterrupt:
        console.print("\n[dim]stopped.[/dim]")


@app.command("license")
def license_cmd() -> None:
    """Show the current edition and license status."""
    from afterlife.licensing import PRO_FEATURES, current_license

    lic = current_license()
    if lic and lic.is_pro:
        console.print("[green]Edition: Pro[/green]")
        console.print(f"  Licensed to: {lic.customer or '(unnamed)'}")
        console.print(
            f"  Expires: {lic.expires_at.date() if lic.expires_at else 'never'}"
        )
        console.print("  Pro features enabled:")
        for fid in lic.features or list(PRO_FEATURES):
            console.print(f"    - {PRO_FEATURES.get(fid, fid)}")
        return

    console.print("[bold]Edition: Free[/bold]")
    console.print(
        "  Detection, monitoring, alerting, run/watch, reports, and the local "
        "dashboard are all included."
    )
    console.print("\n  Pro adds:")
    for desc in PRO_FEATURES.values():
        console.print(f"    - {desc}")
    console.print(
        "\n  Activate with AFTERLIFE_LICENSE=<token> or AFTERLIFE_LICENSE_FILE=<path>."
    )


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
    require_auth: bool = typer.Option(
        False, "--require-auth",
        help="Password-protect the dashboard (Pro). Needed before exposing it "
             "beyond localhost.",
    ),
    password: str | None = typer.Option(
        None, "--password", envvar="AFTERLIFE_DASHBOARD_PASSWORD",
        help="Dashboard password, used with --require-auth.",
    ),
) -> None:
    """Launch the local web dashboard at http://host:port."""
    import uvicorn

    from afterlife.web import create_app

    if not db_path.exists():
        console.print(
            f"[red]DB not found at {db_path}.[/red] Run `afterlife init` first."
        )
        raise typer.Exit(1)

    auth_password = None
    if require_auth:
        from afterlife.licensing import FEATURE_DASHBOARD_AUTH, has_feature

        if not has_feature(FEATURE_DASHBOARD_AUTH):
            console.print(
                "[red]Dashboard authentication is a Pro feature.[/red] "
                "Run `afterlife license` for status; set AFTERLIFE_LICENSE to enable."
            )
            raise typer.Exit(1)
        if not password:
            console.print(
                "[red]--require-auth needs a password[/red] "
                "(--password or AFTERLIFE_DASHBOARD_PASSWORD)."
            )
            raise typer.Exit(1)
        auth_password = password
        console.print("[dim]Dashboard authentication: enabled (Pro).[/dim]")

    web_app = create_app(db_path, auth_password=auth_password)
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
            raise typer.Exit(1) from None
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
