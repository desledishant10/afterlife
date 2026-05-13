from datetime import datetime, timedelta, timezone

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule


@rule(
    id="UNUSED-CREDENTIAL",
    title="Credential not used within the staleness window",
    description=(
        "Credential is active but hasn't been used in N days (default 90). "
        "May indicate forgotten automation, a decommissioned service, or pre-staged "
        "attacker access waiting to be used."
    ),
    severity=Severity.HIGH,
)
def unused_credential(conn, config, graph) -> list[Finding]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.unused_days_threshold)
    rows = conn.execute(
        """
        SELECT source, credential_id, credential_type, owner_source, owner_id,
               last_used_at, scopes, created_at
        FROM credentials
        WHERE is_active = 1
          AND last_used_at IS NOT NULL
          AND last_used_at < ?
        """,
        (cutoff.isoformat(),),
    ).fetchall()

    findings: list[Finding] = []
    for r in rows:
        last_used_display = (r["last_used_at"] or "")[:10]
        findings.append(
            Finding(
                rule_id="UNUSED-CREDENTIAL",
                severity=Severity.HIGH,
                title=f"{r['credential_type']} unused since {last_used_display}",
                description=(
                    f"Credential {r['credential_id']} on {r['source']} has not been used "
                    f"since {r['last_used_at']}, beyond the {config.unused_days_threshold}-day "
                    "staleness threshold."
                ),
                identity_source=r["owner_source"],
                identity_id=r["owner_id"],
                evidence={
                    "credential_id": r["credential_id"],
                    "credential_type": r["credential_type"],
                    "last_used_at": r["last_used_at"],
                    "created_at": r["created_at"],
                    "threshold_days": config.unused_days_threshold,
                },
                suggested_remediation=(
                    f"Confirm the owner still needs {r['credential_id']}; otherwise revoke. "
                    "If it powers a service, document the service and rotate to a "
                    "short-lived credential."
                ),
            )
        )
    return findings
