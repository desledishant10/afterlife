"""ORPHANED-GITHUB: a GitHub token outlives its owner's org membership.

GitHub does not automatically invalidate a member's personal access tokens
when they are removed from an organization. The token keeps working against
any repository the ex-member can still reach, including org repos they later
regain access to as an outside collaborator. This rule fires on active
`github_pat` credentials whose owning login is no longer anyone the org knows
about (neither a current member nor an outside collaborator).

Input: `github_pat` credentials (owner = the login), ingested by the GitHub
collector from the Enterprise SAML SSO credential-authorizations endpoint.
Deploy keys are deliberately out of scope here; they are covered by
UNUSED-CREDENTIAL and STALE-DEPLOY-KEY-WRITE.
"""

import json

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule


@rule(
    id="ORPHANED-GITHUB",
    title="GitHub token owned by someone no longer in the org",
    description=(
        "An active GitHub personal access token is owned by a login that is no "
        "longer a member or outside collaborator of the organization. GitHub "
        "does not revoke tokens on removal, so it can still reach repositories "
        "the former user retains access to."
    ),
    severity=Severity.HIGH,
)
def orphaned_github(conn, config, graph) -> list[Finding]:
    known_logins = {
        row["source_id"]
        for row in conn.execute(
            "SELECT source_id FROM identities WHERE source = 'github'"
        )
    }
    rows = conn.execute(
        """
        SELECT source, credential_id, credential_type, owner_source, owner_id,
               scopes, last_used_at, created_at, metadata
        FROM credentials
        WHERE is_active = 1 AND credential_type = 'github_pat'
        """
    ).fetchall()

    findings: list[Finding] = []
    for r in rows:
        login = r["owner_id"]
        if not login or login in known_logins:
            continue
        scopes = json.loads(r["scopes"]) if r["scopes"] else []
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
        last8 = meta.get("token_last_eight")
        findings.append(
            Finding(
                rule_id="ORPHANED-GITHUB",
                severity=Severity.HIGH,
                title=(
                    f"GitHub token for '{login}' outlives their org membership"
                ),
                description=(
                    f"An active personal access token owned by GitHub user "
                    f"'{login}'"
                    f"{f' (…{last8})' if last8 else ''} is still authorized for "
                    f"the org, but '{login}' is no longer a member or outside "
                    f"collaborator. The token can still reach repositories the "
                    f"user retains access to."
                ),
                identity_source="github",
                identity_id=login,
                evidence={
                    "credential_id": r["credential_id"],
                    "credential_type": r["credential_type"],
                    "credential_source": r["source"],
                    "owner_login": login,
                    "scopes": scopes,
                    "last_used_at": r["last_used_at"],
                    "token_last_eight": last8,
                    "authorized_at": meta.get("authorized_at"),
                },
                suggested_remediation=(
                    "Revoke the token in the org's SAML SSO credential "
                    "authorizations (Settings -> Authentication security), and "
                    "confirm the user's org membership was fully removed."
                ),
            )
        )
    return findings
