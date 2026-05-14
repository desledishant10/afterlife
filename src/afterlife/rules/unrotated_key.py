from datetime import datetime, timedelta, timezone

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule


ROTATABLE_TYPES = ("aws_access_key", "gcp_service_account_key")


@rule(
    id="UNROTATED-KEY",
    title="Long-lived static cloud credential has not been rotated",
    description=(
        "An active static cloud credential (AWS access key, GCP service "
        "account key) was created more than N days ago (default 180) and has "
        "not been rotated. Long-lived static credentials are high-value "
        "targets: their value persists indefinitely and compromise is often "
        "only caught by usage anomalies, not key age."
    ),
    severity=Severity.MEDIUM,
)
def unrotated_key(conn, config, graph) -> list[Finding]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.unrotated_key_days)
    placeholders = ",".join("?" * len(ROTATABLE_TYPES))
    rows = conn.execute(
        f"""
        SELECT source, credential_id, credential_type, owner_source, owner_id,
               created_at, last_used_at
        FROM credentials
        WHERE is_active = 1
          AND credential_type IN ({placeholders})
          AND created_at IS NOT NULL
          AND created_at < ?
        """,
        (*ROTATABLE_TYPES, cutoff.isoformat()),
    ).fetchall()

    findings: list[Finding] = []
    for r in rows:
        created_display = (r["created_at"] or "")[:10]
        findings.append(
            Finding(
                rule_id="UNROTATED-KEY",
                severity=Severity.MEDIUM,
                title=(
                    f"AWS access key {r['credential_id']} unrotated since {created_display}"
                ),
                description=(
                    f"Access key {r['credential_id']} on {r['source']} was created on "
                    f"{r['created_at']} and has not been rotated in over "
                    f"{config.unrotated_key_days} days. AWS Well-Architected guidance "
                    "is to rotate access keys at least every 90 days for human users."
                ),
                identity_source=r["owner_source"],
                identity_id=r["owner_id"],
                evidence={
                    "credential_id": r["credential_id"],
                    "created_at": r["created_at"],
                    "last_used_at": r["last_used_at"],
                    "rotation_threshold_days": config.unrotated_key_days,
                },
                suggested_remediation=(
                    "Rotate the access key: create a new one, update consumers, verify "
                    "they pick up the new key, then delete the old one. Long-term, "
                    "migrate this workload to short-lived credentials via IAM Roles "
                    "Anywhere, OIDC federation, or instance/task roles."
                ),
            )
        )
    return findings
