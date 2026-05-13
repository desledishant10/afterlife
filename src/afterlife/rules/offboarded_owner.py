from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule

DEPROVISIONED_STATUSES = frozenset(
    {"suspended", "deleted", "deprovisioned", "inactive", "archived"}
)


@rule(
    id="OFFBOARDED-OWNER",
    title="Active credential belongs to a deprovisioned identity",
    description=(
        "A credential is still active but its owner, or any identity linked "
        "to its owner via the cross-source graph, has been suspended, archived, "
        "or deleted. This is the Uber 2022 pattern: offboarding completed in HR "
        "but credentials survived in downstream systems."
    ),
    severity=Severity.CRITICAL,
)
def offboarded_owner(conn, config, graph) -> list[Finding]:
    rows = conn.execute(
        """
        SELECT source, credential_id, credential_type, owner_source, owner_id,
               last_used_at
        FROM credentials
        WHERE is_active = 1
          AND owner_source IS NOT NULL
          AND owner_id IS NOT NULL
        """
    ).fetchall()

    findings: list[Finding] = []
    for r in rows:
        person = graph.person_for(r["owner_source"], r["owner_id"])
        if person is None:
            continue
        deprovisioned = [
            i for i in person.identities
            if (i.status or "").lower() in DEPROVISIONED_STATUSES
        ]
        if not deprovisioned:
            continue

        deprov = deprovisioned[0]
        owner_label = person.canonical_email or deprov.source_id

        findings.append(
            Finding(
                rule_id="OFFBOARDED-OWNER",
                severity=Severity.CRITICAL,
                title=(
                    f"{r['credential_type']} active for offboarded identity {owner_label}"
                ),
                description=(
                    f"Credential {r['credential_id']} on {r['source']} is still active. "
                    f"Its owner is linked across {len(person.identities)} system(s); "
                    f"in {deprov.source} the identity has status '{deprov.status}'."
                ),
                identity_source=deprov.source,
                identity_id=deprov.source_id,
                evidence={
                    "credential_source": r["source"],
                    "credential_id": r["credential_id"],
                    "credential_type": r["credential_type"],
                    "last_used_at": r["last_used_at"],
                    "owner_email": person.canonical_email,
                    "deprovisioned_in": deprov.source,
                    "deprovisioned_status": deprov.status,
                    "linked_identities": [
                        {
                            "source": i.source,
                            "source_id": i.source_id,
                            "status": i.status,
                        }
                        for i in person.identities
                    ],
                },
                suggested_remediation=(
                    f"Revoke credential {r['credential_id']} on {r['source']}. "
                    "Verify no automation depends on it before deletion; if it does, "
                    "rotate ownership to a service account."
                ),
            )
        )
    return findings
