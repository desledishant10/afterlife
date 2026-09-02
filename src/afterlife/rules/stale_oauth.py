"""STALE-OAUTH: a write-scoped third-party OAuth grant hasn't been used in N days.

Third-party OAuth grants accumulate and are almost never revoked. The Zapier,
analytics, or MailChimp integration someone authorized two years ago for a
one-off task is still authorized to read or modify data, and nobody is
monitoring it for compromise. This rule surfaces active OAuth grants that
carry a write-tier scope and have not been used within `oauth_stale_days`
(default 90).

Input: credentials of type `oauth_grant`, owned by the user who granted the
app, with `scopes` set to the granted OAuth scopes and `last_used_at` set to
the app's last API call. Populating `last_used_at` needs a source that reports
OAuth usage (a provider's audit/activity log); grants ingested without a usage
timestamp are still inventoried and still caught by OFFBOARDED-OWNER when their
owner leaves, but do not trigger this staleness rule.
"""

import json
from datetime import UTC, datetime, timedelta

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule

OAUTH_GRANT_TYPES = frozenset({"oauth_grant"})

# OAuth scopes that grant no material access. Everything else is treated as
# write/modify-capable unless it is explicitly read-only, which is the
# security-cautious default for opaque third-party scope strings.
_IDENTITY_SCOPES = frozenset({
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
})


def is_write_scope(scope: str) -> bool:
    s = scope.strip().lower()
    if not s or s in _IDENTITY_SCOPES:
        return False
    return not ("readonly" in s or "read_only" in s or s.endswith(".read"))


@rule(
    id="STALE-OAUTH",
    title="Write-scoped OAuth grant has not been used recently",
    description=(
        "An active third-party OAuth grant with a write-tier scope has not "
        "been used in N days (default 90). Long-forgotten integrations keep "
        "the access they were given and are rarely monitored, making them a "
        "quiet path to data exfiltration or modification."
    ),
    severity=Severity.HIGH,
)
def stale_oauth(conn, config, graph) -> list[Finding]:
    cutoff = datetime.now(UTC) - timedelta(days=config.oauth_stale_days)
    placeholders = ",".join("?" * len(OAUTH_GRANT_TYPES))
    rows = conn.execute(
        f"""
        SELECT source, credential_id, credential_type, owner_source, owner_id,
               scopes, last_used_at, created_at, metadata
        FROM credentials
        WHERE is_active = 1
          AND credential_type IN ({placeholders})
          AND last_used_at IS NOT NULL
          AND last_used_at < ?
        """,
        (*OAUTH_GRANT_TYPES, cutoff.isoformat()),
    ).fetchall()

    findings: list[Finding] = []
    for r in rows:
        scopes = json.loads(r["scopes"]) if r["scopes"] else []
        write_scopes = [s for s in scopes if is_write_scope(s)]
        if not write_scopes:
            continue
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
        app = meta.get("app") or meta.get("display_text") or r["credential_id"]
        last_used = r["last_used_at"] or ""
        findings.append(
            Finding(
                rule_id="STALE-OAUTH",
                severity=Severity.HIGH,
                title=(
                    f"OAuth app '{app}' unused since {last_used[:10]} "
                    f"but retains write access"
                ),
                description=(
                    f"The third-party app '{app}' on {r['source']} holds a "
                    f"write-tier OAuth grant and has not been used since "
                    f"{last_used}, past the {config.oauth_stale_days}-day "
                    f"window. It can still read or modify data unwatched."
                ),
                identity_source=r["owner_source"],
                identity_id=r["owner_id"],
                evidence={
                    "credential_id": r["credential_id"],
                    "credential_type": r["credential_type"],
                    "credential_source": r["source"],
                    "app": app,
                    "client_id": meta.get("client_id"),
                    "scopes": scopes,
                    "write_scopes": write_scopes,
                    "last_used_at": r["last_used_at"],
                    "owner": r["owner_id"],
                    "threshold_days": config.oauth_stale_days,
                },
                suggested_remediation=(
                    "Revoke the OAuth grant if the app is no longer needed. If "
                    "it is still required, confirm the owner, reduce its scopes "
                    "to the minimum, and document why it exists."
                ),
            )
        )
    return findings
