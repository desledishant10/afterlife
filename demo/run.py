"""Self-contained Afterlife demo against in-memory AWS and GitHub.

Plants a synthetic mix of fresh and stale IAM resources via moto, plus a
small synthetic GitHub org via respx, then runs the real AWS and GitHub
collectors, the rules engine, and the identity graph. No Docker, no
LocalStack, no real AWS account, no real GitHub token.

Leaves the populated DB at ./.afterlife-demo.db so subsequent CLI
commands (`afterlife identities`, `afterlife report`, etc.) can be run
against it.

Run with: `python demo/run.py` (or `make demo`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
import httpx
import respx
from freezegun import freeze_time
from moto import mock_aws
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from afterlife import db
from afterlife.collectors.aws import AWSCollector
from afterlife.collectors.azure_entra import AzureEntraIDCollector
from afterlife.collectors.github import GitHubCollector
from afterlife.collectors.gitlab import GitLabCollector
from afterlife.collectors.google_workspace import GoogleWorkspaceCollector
from afterlife.graph.identity_graph import IdentityGraph
from afterlife.reporting.html_report import write_html_report
from afterlife.rules.registry import run_all
from afterlife.scan_runs import record_run

console = Console()

DEMO_NOW = datetime(2026, 5, 13, 12, 0, tzinfo=timezone.utc)
MOTO_ACCOUNT_ID = "123456789012"
GH_ORG = "test-org"
GOOGLE_DOMAIN = "example.com"

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

# Foreign-account trust used by the ExternalAuditorRole below to demonstrate
# CROSS-ACCOUNT-TRUST. 999999999999 is the "external" account in the demo.
EXTERNAL_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "magenta",
    "medium": "yellow",
    "low": "cyan",
}


# ---------- AWS seed specs ----------


@dataclass
class UserSpec:
    name: str
    email: str
    created_days_ago: int
    key_last_used_days_ago: int | None
    note: str
    policies: tuple[str, ...] = ()


@dataclass
class RoleSpec:
    name: str
    created_days_ago: int
    note: str
    policies: tuple[str, ...] = ()
    trust_policy: str = TRUST_POLICY


AWS_USERS = [
    UserSpec("alice", "alice@example.com", 30, 5,
             "fresh key, last used 5d ago",
             policies=("ReadOnlyAccess",)),
    UserSpec("bob", "bob@example.com", 200, 120,
             "key 200d old, last used 120d ago",
             policies=("AdministratorAccess",)),
    UserSpec("carol", "carol@example.com", 90, None,
             "key 90d old, never used",
             policies=("IAMFullAccess", "AmazonS3FullAccess")),
    UserSpec("dave", "dave@example.com", 250, 5,
             "key 250d old + AdministratorAccess + Google admin: fires ADMIN-CONCENTRATION",
             policies=("AdministratorAccess",)),
    UserSpec("eve", "eve@example.com", 10, None,
             "key 10d old, never used (control)",
             policies=()),
    UserSpec("contractor-jane", "jane@vendor.com", 60, 5,
             "external contractor with AWS key",
             policies=("ReadOnlyAccess",)),
]

AWS_ROLES = [
    RoleSpec("LegacyDeployRole", 300, "300d old, never assumed",
             policies=("PowerUserAccess",)),
    RoleSpec("ForgottenAuditRole", 250, "250d old, never assumed",
             policies=("ReadOnlyAccess",)),
    RoleSpec("ExternalAuditorRole", 120,
             "trusted by external account 999...999, fires CROSS-ACCOUNT-TRUST",
             policies=("ReadOnlyAccess",),
             trust_policy=EXTERNAL_TRUST_POLICY),
]

# Customer-managed-policy stand-ins (moto does not preload AWS managed
# policies, so we create them under the demo account with the same names
# so blast-radius scoring sees the realistic AdministratorAccess label).
_DEMO_POLICY_DOCS = {
    "AdministratorAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    },
    "PowerUserAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
        ],
    },
    "ReadOnlyAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}
        ],
    },
    "IAMFullAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
    },
    "AmazonS3FullAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
    },
}


# ---------- GitHub seed specs ----------


@dataclass
class GHMemberSpec:
    login: str
    email: str | None
    name: str | None
    is_outside: bool = False
    note: str = ""


GH_MEMBERS = [
    GHMemberSpec("alice", "alice@example.com", "Alice", note="links to AWS alice via email"),
    GHMemberSpec("bob123", None, None, note="private email, won't link"),
    GHMemberSpec(
        "dave-engineer", "dave@example.com", "Dave", note="links to AWS dave via email"
    ),
]

GH_OUTSIDE = [
    GHMemberSpec(
        "contractor-jane",
        "jane@vendor.com",
        "Jane",
        is_outside=True,
        note="external vendor, GitHub only",
    ),
]


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


GH_INSTALLATIONS = [
    {
        "id": 42,
        "app_slug": "dependabot",
        "created_at": _iso(DEMO_NOW - timedelta(days=400)),
        "permissions": {"contents": "read", "pull_requests": "write", "metadata": "read"},
        "events": ["push", "pull_request"],
    }
]

GH_REPOS = [
    {"id": 1, "name": "main-app", "full_name": f"{GH_ORG}/main-app"},
    {"id": 2, "name": "infra", "full_name": f"{GH_ORG}/infra"},
]

# ---------- GitLab seed specs ----------

GL_GROUP = "demo-group"


@dataclass
class GLMemberSpec:
    username: str
    name: str
    email: str | None
    state: str = "active"
    note: str = ""


GL_MEMBERS = [
    GLMemberSpec("alice", "Alice Example", "alice@example.com",
                 note="5-way cross-source: AWS + GitHub + Google + Azure + GitLab"),
    GLMemberSpec("priya", "Priya Singh", "priya@example.com",
                 note="GitLab only"),
]


GL_PROJECTS = [
    {"id": 9001, "name": "demo-service", "path_with_namespace": f"{GL_GROUP}/demo-service"},
]

# A single project deploy key, fresh enough to stay quiet — its only job here
# is to demonstrate GitLab credential collection working end-to-end.
GL_DEPLOY_KEYS_RAW = [
    {
        "id": 4242,
        "title": "ci-deploy",
        "created_days_ago": 40,
        "last_used_days_ago": 5,
        "can_push": False,
    }
]


GH_DEPLOY_KEYS = {
    f"{GH_ORG}/main-app": [
        {
            "id": 901,
            "title": "ci-deploy",
            "created_at": _iso(DEMO_NOW - timedelta(days=60)),
            "last_used": _iso(DEMO_NOW - timedelta(days=5)),
            "read_only": False,
            "verified": True,
        },
        {
            "id": 902,
            "title": "legacy-deploy",
            "created_at": _iso(DEMO_NOW - timedelta(days=300)),
            "last_used": _iso(DEMO_NOW - timedelta(days=120)),
            "read_only": False,
            "verified": True,
        },
    ],
    f"{GH_ORG}/infra": [],
}


# ---------- Google Workspace seed specs ----------


@dataclass
class GoogleUserSpec:
    primary_email: str
    full_name: str
    suspended: bool = False
    archived: bool = False
    is_admin: bool = False
    is_enforced_in_2sv: bool = True
    last_login_days_ago: int = 5
    note: str = ""


# ---------- Azure / Entra ID seed specs ----------


@dataclass
class AzureUserSpec:
    upn: str  # userPrincipalName
    display_name: str
    enabled: bool = True
    last_sign_in_days_ago: int | None = 5
    note: str = ""


AZURE_USERS = [
    AzureUserSpec(
        "alice@example.com", "Alice Example",
        note="4-way cross-source: AWS + GitHub + Google + Azure",
    ),
    AzureUserSpec(
        "dave@example.com", "Dave Example",
        note="3-way: AWS + GitHub + Azure (also in Google as inactive admin)",
    ),
    AzureUserSpec(
        "raj@example.com", "Raj Patel",
        last_sign_in_days_ago=200,
        note="Azure-only, inactive long-term, surfaces ORPHANED-IDENTITY",
    ),
]


GOOGLE_USERS = [
    GoogleUserSpec(
        "alice@example.com", "Alice Example",
        note="active, links AWS + GitHub + Google",
    ),
    GoogleUserSpec(
        "bob@example.com", "Bob Example", suspended=True,
        note="SUSPENDED, surfaces OFFBOARDED-OWNER on bob's AWS key",
    ),
    GoogleUserSpec(
        "carol@example.com", "Carol Example", archived=True,
        note="ARCHIVED, surfaces OFFBOARDED-OWNER on carol's AWS key",
    ),
    GoogleUserSpec(
        "dave@example.com", "Dave Example",
        is_admin=True, is_enforced_in_2sv=False,
        last_login_days_ago=120,
        note="ADMIN WITHOUT 2FA + inactive, fires both ADMIN-WITHOUT-MFA and INACTIVE-ADMIN",
    ),
    GoogleUserSpec(
        "eve@example.com", "Eve Example",
        note="active, links AWS + Google",
    ),
    GoogleUserSpec(
        "nina@example.com", "Nina Newcomer",
        note="active, Google only, surfaces ORPHANED-IDENTITY",
    ),
]


# ---------- seeders ----------


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


def seed_aws(iam) -> None:
    policy_arns = {
        name: iam.create_policy(
            PolicyName=name, PolicyDocument=json.dumps(doc)
        )["Policy"]["Arn"]
        for name, doc in _DEMO_POLICY_DOCS.items()
    }

    for u in AWS_USERS:
        with freeze_time(DEMO_NOW - timedelta(days=u.created_days_ago)):
            iam.create_user(
                UserName=u.name,
                Tags=[{"Key": "email", "Value": u.email}],
            )
            iam.create_access_key(UserName=u.name)
            for policy_name in u.policies:
                iam.attach_user_policy(
                    UserName=u.name, PolicyArn=policy_arns[policy_name]
                )
        if u.key_last_used_days_ago is not None:
            _backdate_key_last_used(
                MOTO_ACCOUNT_ID, u.name, u.key_last_used_days_ago
            )
    for role in AWS_ROLES:
        with freeze_time(DEMO_NOW - timedelta(days=role.created_days_ago)):
            iam.create_role(
                RoleName=role.name,
                AssumeRolePolicyDocument=role.trust_policy,
            )
            for policy_name in role.policies:
                iam.attach_role_policy(
                    RoleName=role.name, PolicyArn=policy_arns[policy_name]
                )


def _gh_user_json(spec: GHMemberSpec) -> dict:
    return {
        "login": spec.login,
        "id": abs(hash(spec.login)) % 100000,
        "type": "User",
        "email": spec.email,
        "name": spec.name,
        "html_url": f"https://github.com/{spec.login}",
    }


def _google_user_json(spec: GoogleUserSpec, idx: int) -> dict:
    return {
        "id": f"100000000000000000{idx:03d}",
        "primaryEmail": spec.primary_email,
        "name": {"fullName": spec.full_name},
        "suspended": spec.suspended,
        "archived": spec.archived,
        "isAdmin": spec.is_admin,
        "isEnforcedIn2Sv": spec.is_enforced_in_2sv,
        "isEnrolledIn2Sv": spec.is_enforced_in_2sv,
        "lastLoginTime": _iso(DEMO_NOW - timedelta(days=spec.last_login_days_ago)),
        "creationTime": _iso(DEMO_NOW - timedelta(days=400)),
        "suspensionReason": "ADMIN" if spec.suspended else None,
    }


def seed_google_routes(router) -> None:
    """Register respx routes that serve the synthetic Workspace customer."""
    users_json = [_google_user_json(u, i) for i, u in enumerate(GOOGLE_USERS)]
    router.route(
        method="GET",
        host="admin.googleapis.com",
        path="/admin/directory/v1/users",
    ).mock(return_value=httpx.Response(200, json={"users": users_json}))


def _azure_user_json(spec: AzureUserSpec, idx: int) -> dict:
    sign_in = None
    if spec.last_sign_in_days_ago is not None:
        sign_in = {
            "lastSignInDateTime": _iso(
                DEMO_NOW - timedelta(days=spec.last_sign_in_days_ago)
            )
        }
    return {
        "id": f"00000000-0000-4000-8000-{idx:012d}",
        "displayName": spec.display_name,
        "userPrincipalName": spec.upn,
        "mail": spec.upn,
        "accountEnabled": spec.enabled,
        "createdDateTime": _iso(DEMO_NOW - timedelta(days=400)),
        "signInActivity": sign_in,
    }


def seed_azure_routes(router) -> None:
    users_json = [_azure_user_json(u, i) for i, u in enumerate(AZURE_USERS)]
    router.route(
        method="GET", host="graph.microsoft.com", path="/v1.0/users"
    ).mock(return_value=httpx.Response(200, json={"value": users_json}))


def _gl_member_json(spec: GLMemberSpec, idx: int) -> dict:
    return {
        "id": 10000 + idx,
        "username": spec.username,
        "name": spec.name,
        "email": spec.email,
        "state": spec.state,
        "access_level": 30,
        "expires_at": None,
        "web_url": f"https://gitlab.com/{spec.username}",
    }


def _gl_deploy_keys_json() -> list[dict]:
    return [
        {
            "id": k["id"],
            "title": k["title"],
            "created_at": _iso(DEMO_NOW - timedelta(days=k["created_days_ago"])),
            "last_used_at": _iso(
                DEMO_NOW - timedelta(days=k["last_used_days_ago"])
            ),
            "can_push": k["can_push"],
        }
        for k in GL_DEPLOY_KEYS_RAW
    ]


def seed_gitlab_routes(router) -> None:
    members = [_gl_member_json(m, i) for i, m in enumerate(GL_MEMBERS)]
    router.route(
        method="GET",
        host="gitlab.com",
        path=f"/api/v4/groups/{GL_GROUP}/members/all",
    ).mock(return_value=httpx.Response(200, json=members))
    router.route(
        method="GET",
        host="gitlab.com",
        path=f"/api/v4/groups/{GL_GROUP}/projects",
    ).mock(return_value=httpx.Response(200, json=GL_PROJECTS))
    for project in GL_PROJECTS:
        router.route(
            method="GET",
            host="gitlab.com",
            path=f"/api/v4/projects/{project['id']}/deploy_keys",
        ).mock(return_value=httpx.Response(200, json=_gl_deploy_keys_json()))


def seed_github_routes(router) -> None:
    """Register respx routes that serve the synthetic GitHub org.

    Routes are added to `router` (the context-manager mock instance) rather
    than the global respx singleton, because `respx.mock(...)` with args
    returns a fresh router.
    """
    router.route(
        method="GET", host="api.github.com", path=f"/orgs/{GH_ORG}/members"
    ).mock(
        return_value=httpx.Response(
            200, json=[_gh_user_json(m) for m in GH_MEMBERS]
        )
    )
    router.route(
        method="GET",
        host="api.github.com",
        path=f"/orgs/{GH_ORG}/outside_collaborators",
    ).mock(
        return_value=httpx.Response(
            200, json=[_gh_user_json(m) for m in GH_OUTSIDE]
        )
    )
    router.route(
        method="GET", host="api.github.com", path=f"/orgs/{GH_ORG}/installations"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "total_count": len(GH_INSTALLATIONS),
                "installations": GH_INSTALLATIONS,
            },
        )
    )
    router.route(
        method="GET", host="api.github.com", path=f"/orgs/{GH_ORG}/repos"
    ).mock(return_value=httpx.Response(200, json=GH_REPOS))
    for repo in GH_REPOS:
        router.route(
            method="GET",
            host="api.github.com",
            path=f"/repos/{repo['full_name']}/keys",
        ).mock(
            return_value=httpx.Response(
                200, json=GH_DEPLOY_KEYS.get(repo["full_name"], [])
            )
        )


# ---------- rendering ----------


def _render_header() -> None:
    body = (
        "An end-to-end run against in-memory AWS (moto), GitHub (respx),\n"
        "and Google Workspace (respx). Plants AWS IAM resources, a small\n"
        "GitHub org, and a Workspace customer with two deprovisioned users,\n"
        "then runs every collector, the rules engine, and the identity graph."
    )
    console.print(Panel.fit(body, title="Afterlife: Synthetic Demo", border_style="cyan"))
    console.print()


def _render_aws_seed() -> None:
    console.print("[bold][1/5][/bold] Seeding AWS environment...")
    for u in AWS_USERS:
        pols = (
            f" [{'red' if 'AdministratorAccess' in u.policies else 'yellow' if any('FullAccess' in p for p in u.policies) else 'cyan'}]"
            f"[{', '.join(u.policies) if u.policies else '-'}]"
            f"[/]"
        )
        console.print(f"  [dim]●[/dim]  {u.name:<8}{pols} [dim]({u.note})[/dim]")
    for role in AWS_ROLES:
        pols = f" [dim][{', '.join(role.policies) if role.policies else '-'}][/dim]"
        console.print(f"  [dim]●[/dim]  role:{role.name}{pols} [dim]({role.note})[/dim]")
    console.print()


def _render_github_seed() -> None:
    console.print("[bold][2/5][/bold] Seeding GitHub organization...")
    for m in GH_MEMBERS:
        console.print(f"  [dim]●[/dim]  member  {m.login:<16} [dim]({m.note})[/dim]")
    for m in GH_OUTSIDE:
        console.print(
            f"  [dim]●[/dim]  outside {m.login:<16} [dim]({m.note})[/dim]"
        )
    console.print(f"  [dim]●[/dim]  installation: dependabot")
    console.print(
        f"  [dim]●[/dim]  repo {GH_ORG}/main-app [dim](2 deploy keys: ci-deploy fresh, "
        "legacy-deploy stale)[/dim]"
    )
    console.print(f"  [dim]●[/dim]  repo {GH_ORG}/infra [dim](no deploy keys)[/dim]")
    console.print()


def _render_azure_seed() -> None:
    console.print("[bold][3a/5][/bold] Seeding Entra ID tenant...")
    for u in AZURE_USERS:
        status = "[dim]act  [/dim]" if u.enabled else "[red]DISA[/red]"
        console.print(
            f"  [dim]●[/dim]  {status} {u.upn:<22} [dim]({u.note})[/dim]"
        )
    console.print()


def _render_gitlab_seed() -> None:
    console.print("[bold][3b/5][/bold] Seeding GitLab group...")
    for m in GL_MEMBERS:
        console.print(
            f"  [dim]●[/dim]  member  {m.username:<10} [dim]({m.note})[/dim]"
        )
    for p in GL_PROJECTS:
        console.print(
            f"  [dim]●[/dim]  project {p['path_with_namespace']} [dim](1 deploy key)[/dim]"
        )
    console.print()


def _render_google_seed() -> None:
    console.print("[bold][3/5][/bold] Seeding Google Workspace customer...")
    for u in GOOGLE_USERS:
        if u.suspended:
            status = "[red]SUSP[/red]"
        elif u.archived:
            status = "[red]ARCH[/red]"
        elif u.is_admin and not u.is_enforced_in_2sv:
            status = "[red]ADMIN[/red]"
        elif u.is_admin:
            status = "[yellow]admin[/yellow]"
        else:
            status = "[dim]act  [/dim]"
        console.print(
            f"  [dim]●[/dim]  {status} {u.primary_email:<22} [dim]({u.note})[/dim]"
        )
    console.print()


def _render_findings(findings) -> None:
    suppressed = [f for f in findings if f.suppressed]
    findings = [f for f in findings if not f.suppressed]
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f.severity.value] += 1

    table = Table(show_header=True, header_style="bold", border_style="dim")
    table.add_column("Rule")
    table.add_column("Severity")
    table.add_column("Blast")
    table.add_column("Target")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    blast_styles = {"broad": "bold red", "moderate": "yellow", "limited": "cyan"}
    for f in sorted(
        findings,
        key=lambda x: (
            severity_order[x.severity.value],
            -(x.blast_radius.score if x.blast_radius else 0.0),
            x.rule_id,
        ),
    ):
        sev = f.severity.value
        target = (
            f.evidence.get("credential_id")
            or f.evidence.get("admin_id")
            or f.evidence.get("idp_id")
            or f.evidence.get("aws_identity")
            or f.evidence.get("github_login")
            or f.evidence.get("owner_email")
            or "?"
        )
        if isinstance(target, str) and target.startswith("arn:aws:iam::"):
            target = target.split(":", 5)[-1]
        if isinstance(target, str) and target.startswith("deploy_key:"):
            target = target.split(":", 1)[1]
        extra = ""
        if f.rule_id == "UNUSED-CREDENTIAL":
            extra = f" (unused since {(f.evidence.get('last_used_at') or '?')[:10]})"
        elif f.rule_id in {"NEVER-USED", "UNROTATED-KEY"}:
            extra = f" (created {(f.evidence.get('created_at') or '?')[:10]})"

        blast_cell = "-"
        if f.blast_radius:
            label = f.blast_radius.label
            style = blast_styles.get(label, "white")
            blast_cell = f"[{style}]{label} ({f.blast_radius.score:.2f})[/{style}]"

        table.add_row(
            f.rule_id,
            f"[{SEVERITY_STYLE[sev]}]{sev}[/{SEVERITY_STYLE[sev]}]",
            blast_cell,
            f"{target}[dim]{extra}[/dim]",
        )
    console.print(table)
    console.print()
    console.print(
        f"[bold]{len(findings)} active findings[/bold]"
        f"{f' ([dim]{len(suppressed)} suppressed by allowlist[/dim])' if suppressed else ''}"
    )
    for sev in ("critical", "high", "medium", "low"):
        style = SEVERITY_STYLE[sev]
        console.print(f"  [{style}]{by_sev[sev]:>2}[/{style}] {sev}")

    offboarded = [f for f in findings if f.rule_id == "OFFBOARDED-OWNER"]
    if offboarded:
        console.print()
        console.print(
            "[bold red]OFFBOARDED-OWNER fired:[/bold red] "
            "credentials whose owners are deprovisioned in Google Workspace "
            "but still active in AWS. The Uber 2022 pattern."
        )
        for f in offboarded:
            console.print(
                f"  → {f.evidence['credential_id']} owned by "
                f"[bold]{f.evidence['owner_email']}[/bold] "
                f"({f.evidence['deprovisioned_in']}: "
                f"[red]{f.evidence['deprovisioned_status']}[/red])"
            )


def _render_identities(graph: IdentityGraph) -> None:
    persons = list(graph.persons())
    cross = [p for p in persons if p.is_cross_source]
    persons.sort(
        key=lambda p: (not p.is_cross_source, p.canonical_email or "zzz")
    )

    console.print(
        f"[bold]{len(persons)} persons[/bold] across "
        f"[bold]{len({s for p in persons for s in p.sources})}[/bold] sources "
        f"([green]{len(cross)} cross-source[/green])"
    )
    console.print()
    for person in persons:
        if person.canonical_email:
            label = f"[bold]{person.canonical_email}[/bold]"
            if person.is_cross_source:
                label += " [green](cross-source)[/green]"
            console.print(label)
            for i in person.identities:
                console.print(
                    f"  [cyan]{i.source:<7}[/cyan] {i.source_id}"
                )
        else:
            i = person.identities[0]
            console.print(
                f"[bold]{i.name or i.source_id}[/bold] "
                f"[dim]({i.source}, no email, unlinkable)[/dim]"
            )
    console.print()


# ---------- main ----------


def main() -> None:
    _render_header()

    db_path = Path(".afterlife-demo.db").resolve()
    if db_path.exists():
        db_path.unlink()

    with freeze_time(DEMO_NOW), mock_aws(), respx.mock(
        assert_all_called=False
    ) as gh_mock:
        iam = boto3.client(
            "iam",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        seed_aws(iam)
        seed_github_routes(gh_mock)
        seed_google_routes(gh_mock)
        seed_azure_routes(gh_mock)
        seed_gitlab_routes(gh_mock)
        _render_aws_seed()
        _render_github_seed()
        _render_google_seed()
        _render_azure_seed()
        _render_gitlab_seed()

        db.init_db(db_path)
        session = boto3.Session(
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )

        console.print("[bold][4/5][/bold] [dim]$[/dim] afterlife scan aws")
        with record_run(db_path, "aws") as run:
            n_aws = AWSCollector(
                db_path=db_path, profile="default", region="us-east-1", session=session
            ).run()
            run["records_collected"] = n_aws
        console.print(f"  [green]OK[/green] collected {n_aws} AWS records")
        console.print("       [dim]$[/dim] afterlife scan github")
        with record_run(db_path, "github") as run:
            n_gh = GitHubCollector(
                token="demo-token", org=GH_ORG, db_path=db_path
            ).run()
            run["records_collected"] = n_gh
        console.print(f"  [green]OK[/green] collected {n_gh} GitHub records")
        console.print("       [dim]$[/dim] afterlife scan idp --provider google")
        with record_run(db_path, "google") as run:
            n_idp = GoogleWorkspaceCollector(
                db_path=db_path, access_token="demo-token"
            ).run()
            run["records_collected"] = n_idp
        console.print(f"  [green]OK[/green] collected {n_idp} Google Workspace records")
        console.print("       [dim]$[/dim] afterlife scan idp --provider azure")
        with record_run(db_path, "azure") as run:
            n_azure = AzureEntraIDCollector(
                db_path=db_path, access_token="demo-token"
            ).run()
            run["records_collected"] = n_azure
        console.print(f"  [green]OK[/green] collected {n_azure} Entra ID records")
        console.print("       [dim]$[/dim] afterlife scan gitlab")
        with record_run(db_path, "gitlab") as run:
            n_gl = GitLabCollector(
                db_path=db_path, token="demo-token", group=GL_GROUP
            ).run()
            run["records_collected"] = n_gl
        console.print(f"  [green]OK[/green] collected {n_gl} GitLab records")
        console.print()

        console.print(
            "[bold][5/5][/bold] [dim]$[/dim] afterlife analyze --allowlist demo/allowlist.yaml"
        )
        allowlist_path = Path(__file__).parent / "allowlist.yaml"
        findings = run_all(db_path, allowlist_path=allowlist_path)
        console.print()
        _render_findings(findings)

    console.print()
    console.print("[bold]       [dim]$[/dim] afterlife identities[/bold]")
    console.print()
    _render_identities(IdentityGraph.from_db(db_path))

    report_path = Path(".afterlife-demo-report.html").resolve()
    report_path.write_text(write_html_report(db_path))
    console.print(
        f"[bold green]HTML report[/bold green] written to "
        f"[bold]{report_path.name}[/bold] ([dim]open in a browser[/dim])"
    )
    console.print()
    console.print(
        f"[dim]DB left at {db_path}. Try `afterlife identities --db-path "
        f"{db_path}` or `afterlife report --format html --db-path {db_path} -o report.html`.[/dim]"
    )


if __name__ == "__main__":
    main()
