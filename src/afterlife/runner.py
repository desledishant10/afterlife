"""Pipeline runner: scan configured sources, analyze, and notify.

This is the engine behind `afterlife run` (one shot) and `afterlife watch`
(on an interval). It reuses the same collectors, analysis, and notification
code as the individual CLI commands, driven by a declarative config: which
sources to scan (credentials read from the environment), whether to alert,
and, for watch, how often to repeat.

A source that fails or is not configured is reported and skipped; the rest of
the pipeline still runs, so one broken credential never stops the monitor.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from afterlife import db
from afterlife.collectors.aws import AWSCollector
from afterlife.collectors.base import Collector
from afterlife.collectors.gcp_iam import GCPIAMCollector
from afterlife.collectors.github import GitHubCollector
from afterlife.collectors.gitlab import GitLabCollector
from afterlife.collectors.idp import build_idp_collector
from afterlife.collectors.slack import SlackCollector
from afterlife.collectors.vault import VaultCollector
from afterlife.db import ReconcileSummary
from afterlife.notify import NotifyConfig, notify_findings
from afterlife.rules.registry import run_analysis
from afterlife.scan_runs import record_run

Env = dict[str, str]
Builder = Callable[[Path, Env], Collector]


class SourceNotConfigured(Exception):
    """Raised when a source is requested but its required env vars are absent."""

    def __init__(self, source: str, missing: str):
        self.source = source
        self.missing = missing
        super().__init__(f"{source} needs {missing}")


def _require(env: Env, source: str, *keys: str) -> None:
    absent = [k for k in keys if not env.get(k)]
    if absent:
        raise SourceNotConfigured(source, ", ".join(absent))


def _build_aws(db_path: Path, env: Env) -> Collector:
    # AWS always builds: with nothing set, boto3's default chain resolves.
    return AWSCollector(
        db_path=db_path,
        profile=env.get("AWS_PROFILE") or None,
        region=env.get("AWS_REGION") or None,
    )


def _build_github(db_path: Path, env: Env) -> Collector:
    _require(env, "github", "GITHUB_TOKEN", "GITHUB_ORG")
    return GitHubCollector(
        db_path=db_path, token=env["GITHUB_TOKEN"], org=env["GITHUB_ORG"]
    )


def _build_gitlab(db_path: Path, env: Env) -> Collector:
    _require(env, "gitlab", "GITLAB_TOKEN", "GITLAB_GROUP")
    return GitLabCollector(
        db_path=db_path,
        token=env["GITLAB_TOKEN"],
        group=env["GITLAB_GROUP"],
        api_url=env.get("GITLAB_API_URL", "https://gitlab.com/api/v4"),
    )


def _build_slack(db_path: Path, env: Env) -> Collector:
    _require(env, "slack", "SLACK_TOKEN")
    return SlackCollector(db_path=db_path, token=env["SLACK_TOKEN"])


def _build_vault(db_path: Path, env: Env) -> Collector:
    _require(env, "vault", "VAULT_TOKEN", "VAULT_ADDR")
    return VaultCollector(
        db_path=db_path,
        token=env["VAULT_TOKEN"],
        api_url=env["VAULT_ADDR"],
        namespace=env.get("VAULT_NAMESPACE"),
    )


def _build_gcp(db_path: Path, env: Env) -> Collector:
    _require(env, "gcp", "GCP_PROJECT")
    saf = env.get("GCP_SERVICE_ACCOUNT_JSON")
    return GCPIAMCollector(
        db_path=db_path,
        project=env["GCP_PROJECT"],
        service_account_file=Path(saf) if saf else None,
    )


def _build_idp(db_path: Path, env: Env) -> Collector:
    provider = env.get("IDP_PROVIDER", "google")
    if provider == "google":
        _require(env, "idp:google", "GOOGLE_SERVICE_ACCOUNT_JSON", "GOOGLE_ADMIN_EMAIL")
        kwargs = {
            "service_account_file": Path(env["GOOGLE_SERVICE_ACCOUNT_JSON"]),
            "admin_email": env["GOOGLE_ADMIN_EMAIL"],
        }
    elif provider == "okta":
        _require(env, "idp:okta", "OKTA_DOMAIN", "OKTA_API_TOKEN")
        kwargs = {"domain": env["OKTA_DOMAIN"], "api_token": env["OKTA_API_TOKEN"]}
    elif provider == "azure":
        _require(
            env, "idp:azure",
            "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        )
        kwargs = {
            "tenant_id": env["AZURE_TENANT_ID"],
            "client_id": env["AZURE_CLIENT_ID"],
            "client_secret": env["AZURE_CLIENT_SECRET"],
        }
    else:
        raise SourceNotConfigured("idp", f"a valid IDP_PROVIDER (got {provider!r})")
    return build_idp_collector(provider, db_path=db_path, **kwargs)


SOURCE_BUILDERS: dict[str, Builder] = {
    "aws": _build_aws,
    "github": _build_github,
    "gitlab": _build_gitlab,
    "slack": _build_slack,
    "vault": _build_vault,
    "gcp": _build_gcp,
    "idp": _build_idp,
}


def detect_sources(env: Env, builders: dict[str, Builder] | None = None) -> list[str]:
    """Sources whose required env vars are present (buildable right now)."""
    builders = builders or SOURCE_BUILDERS
    found = []
    for name, build in builders.items():
        try:
            build(Path("unused.db"), env)
        except SourceNotConfigured:
            continue
        except Exception:
            # A build that fails for a non-config reason still counts as
            # configured; the real run will surface the error.
            found.append(name)
        else:
            found.append(name)
    return found


@dataclass
class RunConfig:
    sources: list[str]
    db_path: Path = Path("afterlife.db")
    allowlist: Path | None = None
    notify: bool = False
    notify_config: NotifyConfig | None = None
    interval_seconds: int = 3600

    @classmethod
    def from_yaml(cls, path: Path, env: Env | None = None) -> RunConfig:
        env = env if env is not None else dict(os.environ)
        data: dict[str, Any] = yaml.safe_load(Path(path).read_text()) or {}
        notify = bool(data.get("notify", False))
        return cls(
            sources=list(data.get("sources") or []),
            db_path=Path(data.get("db_path", "afterlife.db")),
            allowlist=Path(data["allowlist"]) if data.get("allowlist") else None,
            notify=notify,
            notify_config=NotifyConfig.from_env(env) if notify else None,
            interval_seconds=int(data.get("interval_seconds", 3600)),
        )


@dataclass
class SourceResult:
    source: str
    records: int | None = None
    error: str | None = None


@dataclass
class PipelineResult:
    sources: list[SourceResult] = field(default_factory=list)
    delta: ReconcileSummary | None = None
    notify_results: dict[str, str] = field(default_factory=dict)


def run_pipeline(
    config: RunConfig,
    env: Env | None = None,
    *,
    builders: dict[str, Builder] | None = None,
    emit: Callable[[str], None] | None = None,
) -> PipelineResult:
    """Scan every configured source, then analyze, then notify. One cycle."""
    env = env if env is not None else dict(os.environ)
    builders = builders or SOURCE_BUILDERS
    say = emit or (lambda _msg: None)
    result = PipelineResult()

    # Self-initializing: run/watch are automation entrypoints, so the caller
    # should not have to run `afterlife init` first. Idempotent.
    db.init_db(config.db_path)

    for name in config.sources:
        build = builders.get(name)
        if build is None:
            result.sources.append(SourceResult(name, error="unknown source"))
            say(f"skip {name}: unknown source")
            continue
        try:
            collector = build(config.db_path, env)
        except SourceNotConfigured as exc:
            result.sources.append(SourceResult(name, error=f"not configured ({exc.missing})"))
            say(f"skip {name}: not configured ({exc.missing})")
            continue

        label = collector.source
        try:
            with record_run(config.db_path, label) as run:
                count = collector.run()
                run["records_collected"] = count
            result.sources.append(SourceResult(label, records=count))
            say(f"scanned {label}: {count} records")
        except Exception as exc:
            result.sources.append(SourceResult(label, error=str(exc)))
            say(f"scan {label} failed: {exc}")

    findings, delta = run_analysis(config.db_path, allowlist_path=config.allowlist)
    result.delta = delta
    say(
        f"analyzed: {delta.open_total} open "
        f"(+{delta.new} new, +{delta.reopened} reopened, -{delta.resolved} resolved)"
    )

    if config.notify and config.notify_config and config.notify_config.has_channels():
        result.notify_results = notify_findings(findings, delta, config.notify_config)
        for channel, status in result.notify_results.items():
            say(f"notify:{channel} {status}")

    return result


def watch(
    config: RunConfig,
    env: Env | None = None,
    *,
    builders: dict[str, Builder] | None = None,
    emit: Callable[[str], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    max_cycles: int | None = None,
) -> int:
    """Run the pipeline repeatedly every `interval_seconds`.

    Loops until `max_cycles` (used by tests) or forever. `sleep` is injectable
    so tests do not actually wait. Returns the number of cycles run.
    """
    say = emit or (lambda _msg: None)
    cycles = 0
    while True:
        say(f"--- cycle {cycles + 1} ---")
        run_pipeline(config, env, builders=builders, emit=emit)
        cycles += 1
        if max_cycles is not None and cycles >= max_cycles:
            return cycles
        say(f"sleeping {config.interval_seconds}s")
        sleep(config.interval_seconds)
