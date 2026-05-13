"""Self-contained Afterlife demo against an in-memory AWS environment.

Plants a synthetic mix of fresh and stale IAM resources, runs the AWSCollector
against the in-process moto backend, then runs the rules engine and prints
findings. No Docker, no LocalStack, no real AWS account needed.

Run with: `python demo/run.py` (or `make demo`).
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from freezegun import freeze_time
from moto import mock_aws
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from afterlife import db
from afterlife.collectors.aws import AWSCollector
from afterlife.rules.registry import run_all

console = Console()

DEMO_NOW = datetime(2026, 5, 13, 12, 0, tzinfo=timezone.utc)
MOTO_ACCOUNT_ID = "123456789012"
TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


@dataclass
class UserSpec:
    name: str
    email: str
    created_days_ago: int
    key_last_used_days_ago: int | None
    note: str


@dataclass
class RoleSpec:
    name: str
    created_days_ago: int
    note: str


USERS = [
    UserSpec("alice", "alice@example.com", 30, 5, "fresh key, last used 5d ago"),
    UserSpec("bob", "bob@example.com", 200, 120, "key 200d old, last used 120d ago"),
    UserSpec("carol", "carol@example.com", 90, None, "key 90d old, never used"),
    UserSpec("dave", "dave@example.com", 250, 5, "key 250d old, last used 5d ago"),
    UserSpec("eve", "eve@example.com", 10, None, "key 10d old, never used (control)"),
]

ROLES = [
    RoleSpec("LegacyDeployRole", 300, "300d old, never assumed"),
    RoleSpec("ForgottenAuditRole", 250, "250d old, never assumed"),
]

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "magenta",
    "medium": "yellow",
    "low": "cyan",
}


def _backdate_key_last_used(account_id: str, user_name: str, days_ago: int) -> None:
    """Backdate AccessKey.last_used by reaching into moto's internal state.

    AWS doesn't expose an API to set LastUsedDate (it's populated when the key
    is used), so we manipulate the moto backend directly. Brittle to moto
    internals but acceptable for a demo script.
    """
    from moto.iam.models import AccessKeyLastUsed, iam_backends

    backend = iam_backends[account_id]["global"]
    user = backend.users[user_name]
    target = DEMO_NOW - timedelta(days=days_ago)
    for key in user.access_keys:
        key.last_used = AccessKeyLastUsed(
            timestamp=target, service="iam", region="us-east-1"
        )


def seed(iam) -> None:
    for u in USERS:
        with freeze_time(DEMO_NOW - timedelta(days=u.created_days_ago)):
            iam.create_user(
                UserName=u.name,
                Tags=[{"Key": "email", "Value": u.email}],
            )
            iam.create_access_key(UserName=u.name)
        if u.key_last_used_days_ago is not None:
            _backdate_key_last_used(MOTO_ACCOUNT_ID, u.name, u.key_last_used_days_ago)

    for role in ROLES:
        with freeze_time(DEMO_NOW - timedelta(days=role.created_days_ago)):
            iam.create_role(
                RoleName=role.name,
                AssumeRolePolicyDocument=TRUST_POLICY,
            )


def _render_header() -> None:
    body = (
        "A self-contained run against an in-memory AWS account.\n"
        "Plants 5 IAM users and 2 IAM roles with mixed credential ages,\n"
        "then runs the full scan → analyze pipeline."
    )
    console.print(Panel.fit(body, title="Afterlife — Synthetic Demo", border_style="cyan"))
    console.print()


def _render_seed_summary() -> None:
    console.print("[bold][1/3][/bold] Seeding synthetic AWS environment...")
    for u in USERS:
        console.print(f"  [dim]●[/dim]  {u.name:<8}  [dim]({u.note})[/dim]")
    for role in ROLES:
        console.print(f"  [dim]●[/dim]  role:{role.name}  [dim]({role.note})[/dim]")
    console.print()


def _render_findings(findings) -> None:
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f.severity.value] += 1

    table = Table(show_header=True, header_style="bold", border_style="dim")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Target")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda x: (severity_order[x.severity.value], x.rule_id)):
        sev = f.severity.value
        target = f.evidence.get("credential_id", "?")
        # Compact AWS ARNs for readability
        if isinstance(target, str) and target.startswith("arn:aws:iam::"):
            target = target.split(":", 5)[-1]
        extra = ""
        if f.rule_id == "UNUSED-CREDENTIAL":
            extra = f" (unused since {f.evidence.get('last_used_at', '?')[:10]})"
        elif f.rule_id == "NEVER-USED":
            extra = f" (created {f.evidence.get('created_at', '?')[:10]})"
        elif f.rule_id == "UNROTATED-KEY":
            extra = f" (created {f.evidence.get('created_at', '?')[:10]})"
        table.add_row(
            f.rule_id,
            f"[{SEVERITY_STYLE[sev]}]{sev}[/{SEVERITY_STYLE[sev]}]",
            f"{target}[dim]{extra}[/dim]",
        )
    console.print(table)
    console.print()
    console.print(f"[bold]{len(findings)} findings[/bold]")
    for sev in ("critical", "high", "medium", "low"):
        style = SEVERITY_STYLE[sev]
        console.print(f"  [{style}]{by_sev[sev]:>2}[/{style}] {sev}")
    console.print()
    console.print(
        "[dim]Quiet (no findings): alice (fresh), eve (within NEVER-USED grace period).[/dim]"
    )
    console.print(
        "[dim]\nThe missing rule here is OFFBOARDED-OWNER, which fires once IdP[/dim]\n"
        "[dim]identities are correlated to AWS principals (Week 5).[/dim]"
    )


def main() -> None:
    _render_header()

    db_path = Path(tempfile.gettempdir()) / "afterlife-demo.db"
    if db_path.exists():
        db_path.unlink()

    with freeze_time(DEMO_NOW), mock_aws():
        iam = boto3.client(
            "iam",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        seed(iam)
        _render_seed_summary()

        console.print("[bold][2/3][/bold] [dim]$[/dim] afterlife scan aws")
        db.init_db(db_path)
        session = boto3.Session(
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        n = AWSCollector(
            db_path=db_path, profile="default", region="us-east-1", session=session
        ).run()
        console.print(f"  [green]OK[/green] collected {n} AWS records")
        console.print()

        console.print("[bold][3/3][/bold] [dim]$[/dim] afterlife analyze")
        findings = run_all(db_path)
        console.print()
        _render_findings(findings)


if __name__ == "__main__":
    main()
