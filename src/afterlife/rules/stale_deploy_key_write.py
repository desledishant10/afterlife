"""STALE-DEPLOY-KEY-WRITE: a write-capable deploy key hasn't been used in N days.

A focused superset of UNUSED-CREDENTIAL for the specific case where the
stale credential can push code to a repository. Write-enabled deploy keys
that nobody is using are the cleanest path for an attacker who has stolen
a CI image or developer laptop: nobody is watching, but the key is still
capable of poisoning the codebase.
"""

from datetime import datetime, timedelta, timezone

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule

DEPLOY_KEY_TYPES = frozenset({"github_deploy_key", "gitlab_deploy_key"})
WRITE_SCOPES = frozenset({"write", "push"})


@rule(
    id="STALE-DEPLOY-KEY-WRITE",
    title="Write-capable deploy key has not been used recently",
    description=(
        "A deploy key with push or write access has not been used in N days "
        "(default 90). Write-capable deploy keys that nobody touches are the "
        "cleanest supply-chain attack surface: still active, still trusted, "
        "but nobody is watching."
    ),
    severity=Severity.HIGH,
)
def stale_deploy_key_write(conn, config, graph) -> list[Finding]:
    cutoff = datetime.now(timezone.utc) - timedelta(
        days=config.unused_days_threshold
    )
    placeholders = ",".join("?" * len(DEPLOY_KEY_TYPES))
    rows = conn.execute(
        f"""
        SELECT source, credential_id, credential_type, scopes,
               last_used_at, created_at, metadata
        FROM credentials
        WHERE is_active = 1
          AND credential_type IN ({placeholders})
          AND last_used_at IS NOT NULL
          AND last_used_at < ?
        """,
        (*DEPLOY_KEY_TYPES, cutoff.isoformat()),
    ).fetchall()

    import json

    findings: list[Finding] = []
    for r in rows:
        scopes = json.loads(r["scopes"]) if r["scopes"] else []
        if not any(s in WRITE_SCOPES for s in scopes):
            continue
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
        last_used = r["last_used_at"] or ""
        findings.append(
            Finding(
                rule_id="STALE-DEPLOY-KEY-WRITE",
                severity=Severity.HIGH,
                title=(
                    f"write-capable deploy key {r['credential_id']} unused "
                    f"since {last_used[:10]}"
                ),
                description=(
                    f"Deploy key {r['credential_id']} on {r['source']} can "
                    f"push to {meta.get('repo') or meta.get('project') or 'a repository'} "
                    f"and has not been used since {last_used}. Beyond the "
                    f"{config.unused_days_threshold}-day staleness window."
                ),
                evidence={
                    "credential_id": r["credential_id"],
                    "credential_type": r["credential_type"],
                    "credential_source": r["source"],
                    "scopes": scopes,
                    "last_used_at": r["last_used_at"],
                    "created_at": r["created_at"],
                    "repo_or_project": meta.get("repo") or meta.get("project"),
                    "key_title": meta.get("title"),
                    "threshold_days": config.unused_days_threshold,
                },
                suggested_remediation=(
                    "Remove the deploy key. If CI still needs it, rotate to a "
                    "fresh key with a documented owner and tighter scope. If "
                    "push access is no longer needed, replace with a "
                    "read-only key."
                ),
            )
        )
    return findings
