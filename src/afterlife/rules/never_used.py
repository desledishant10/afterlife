from datetime import datetime, timedelta, timezone

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule

# Credential types whose source system does not expose a usable last-used
# signal. Without a usage signal we cannot distinguish "never used" from
# "actively used but unobservable", so we skip them.
TYPES_WITHOUT_USAGE_SIGNAL = ("github_app_installation",)


@rule(
    id="NEVER-USED",
    title="Active credential has never been used",
    description=(
        "Credential was created more than N days ago (default 30) and has no recorded "
        "last-used timestamp. Frequently the result of 'just in case' provisioning that "
        "was never picked up. Among the easiest wins in any access audit."
    ),
    severity=Severity.MEDIUM,
)
def never_used(conn, config, graph) -> list[Finding]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.never_used_grace_days)
    placeholders = ",".join("?" * len(TYPES_WITHOUT_USAGE_SIGNAL))
    rows = conn.execute(
        f"""
        SELECT source, credential_id, credential_type, owner_source, owner_id,
               created_at
        FROM credentials
        WHERE is_active = 1
          AND last_used_at IS NULL
          AND created_at IS NOT NULL
          AND created_at < ?
          AND credential_type NOT IN ({placeholders})
        """,
        (cutoff.isoformat(), *TYPES_WITHOUT_USAGE_SIGNAL),
    ).fetchall()

    findings: list[Finding] = []
    for r in rows:
        created_display = (r["created_at"] or "")[:10]
        findings.append(
            Finding(
                rule_id="NEVER-USED",
                severity=Severity.MEDIUM,
                title=(
                    f"{r['credential_type']} created {created_display} has never been used"
                ),
                description=(
                    f"Credential {r['credential_id']} on {r['source']} was created on "
                    f"{r['created_at']} and has no recorded usage. Past the "
                    f"{config.never_used_grace_days}-day grace period, an unused "
                    "credential is most likely abandoned."
                ),
                identity_source=r["owner_source"],
                identity_id=r["owner_id"],
                evidence={
                    "credential_id": r["credential_id"],
                    "credential_type": r["credential_type"],
                    "created_at": r["created_at"],
                    "grace_period_days": config.never_used_grace_days,
                },
                suggested_remediation=(
                    f"Confirm whether {r['credential_id']} was created for a use case "
                    "that ever materialized. If not, revoke. If it is a break-glass "
                    "credential intentionally dormant, tag it explicitly so future "
                    "scans can skip it."
                ),
            )
        )
    return findings
