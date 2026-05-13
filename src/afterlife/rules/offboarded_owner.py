from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule

DEPROVISIONED_STATUSES = ("suspended", "deleted", "deprovisioned", "inactive", "archived")


@rule(
    id="OFFBOARDED-OWNER",
    title="Active credential belongs to a deprovisioned identity",
    description=(
        "A credential is still active but its owner has been suspended, archived, or deleted in "
        "the IdP. This is the Uber 2022 pattern — offboarding completed in HR but credentials "
        "survived in downstream systems."
    ),
    severity=Severity.CRITICAL,
)
def offboarded_owner(conn, config) -> list[Finding]:
    placeholders = ",".join("?" * len(DEPROVISIONED_STATUSES))
    rows = conn.execute(
        f"""
        SELECT
            c.source        AS cred_source,
            c.credential_id AS credential_id,
            c.credential_type,
            c.last_used_at,
            c.scopes,
            i.source        AS id_source,
            i.source_id     AS id_id,
            i.email,
            i.status        AS owner_status
        FROM credentials c
        JOIN identities i
          ON c.owner_source = i.source AND c.owner_id = i.source_id
        WHERE c.is_active = 1
          AND LOWER(i.status) IN ({placeholders})
        """,
        DEPROVISIONED_STATUSES,
    ).fetchall()

    findings: list[Finding] = []
    for r in rows:
        owner_label = r["email"] or r["id_id"]
        findings.append(
            Finding(
                rule_id="OFFBOARDED-OWNER",
                severity=Severity.CRITICAL,
                title=(
                    f"{r['credential_type']} active for offboarded identity {owner_label}"
                ),
                description=(
                    f"Credential {r['credential_id']} on {r['cred_source']} is still active, "
                    f"but its owner ({owner_label}) has status '{r['owner_status']}' in "
                    f"{r['id_source']}."
                ),
                identity_source=r["id_source"],
                identity_id=r["id_id"],
                evidence={
                    "credential_source": r["cred_source"],
                    "credential_id": r["credential_id"],
                    "credential_type": r["credential_type"],
                    "last_used_at": r["last_used_at"],
                    "owner_status": r["owner_status"],
                    "owner_email": r["email"],
                },
                suggested_remediation=(
                    f"Revoke credential {r['credential_id']} on {r['cred_source']}. "
                    "Verify no automation depends on it before deletion; if it does, "
                    "rotate the ownership to a service account."
                ),
            )
        )
    return findings
