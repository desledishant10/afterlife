"""ADMIN-CONCENTRATION: one person holds admin-tier access in multiple systems.

If the same human is admin in Google Workspace *and* owns an AWS access key
with `AdministratorAccess`, compromising that one human gives an attacker
control of both the directory and the cloud account. Concentration of
admin authority across systems is the failure mode behind several public
breaches (the Reddit-2023 employee-phishing -> source-code-pull story is
one variant).

What counts as admin:
  - IdP identity with `is_admin: True` in its metadata (Google's flag today).
  - AWS credential owned by this person with an attached policy whose name
    contains `AdministratorAccess` or a `*:*` action.

We require the admin signal to span >= 2 distinct source systems.
"""

from __future__ import annotations

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule

AWS_ADMIN_POLICY_FRAGMENTS = ("administratoraccess", "*:*")


@rule(
    id="ADMIN-CONCENTRATION",
    title="One person holds admin-tier access in 2+ systems",
    description=(
        "A single identity-graph person has admin-equivalent access in two or "
        "more source systems (IdP admin flag, AWS AdministratorAccess, etc.). "
        "Compromising one human grants an attacker authority across both. "
        "Split admin responsibilities so no single account opens the whole "
        "kingdom."
    ),
    severity=Severity.CRITICAL,
)
def admin_concentration(conn, config, graph) -> list[Finding]:
    findings: list[Finding] = []
    for person in graph.persons():
        admin_in: set[str] = set()
        details: list[dict] = []

        for ident in person.identities:
            if (ident.metadata or {}).get("is_admin"):
                admin_in.add(ident.source)
                details.append(
                    {
                        "source": ident.source,
                        "source_id": ident.source_id,
                        "kind": "idp_admin_flag",
                    }
                )

        aws_admin_credentials: list[str] = []
        for cred in graph.credentials_for_person(person):
            if cred.source != "aws":
                continue
            scope_text = " ".join(cred.scopes or []).lower()
            if any(f in scope_text for f in AWS_ADMIN_POLICY_FRAGMENTS):
                aws_admin_credentials.append(cred.credential_id)
        if aws_admin_credentials:
            admin_in.add("aws")
            details.append(
                {
                    "source": "aws",
                    "kind": "admin_policy_attached",
                    "credentials": aws_admin_credentials,
                }
            )

        if len(admin_in) < 2:
            continue

        primary = (
            person.identity_in("google")
            or person.identity_in("okta")
            or person.identity_in("azure")
            or person.identities[0]
        )
        label = person.canonical_email or primary.source_id
        sources_str = " + ".join(sorted(admin_in))
        findings.append(
            Finding(
                rule_id="ADMIN-CONCENTRATION",
                severity=Severity.CRITICAL,
                title=(
                    f"{label} is admin across {len(admin_in)} systems: "
                    f"{sources_str}"
                ),
                description=(
                    f"{label} holds admin-equivalent access in {sources_str}. "
                    "Compromising one account would grant an attacker that "
                    "level of access in every linked system."
                ),
                identity_source=primary.source,
                identity_id=primary.source_id,
                evidence={
                    "owner_email": person.canonical_email,
                    "admin_sources": sorted(admin_in),
                    "details": details,
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
                    "Reduce admin scope: keep admin privileges in the one "
                    "system this person needs day-to-day, downgrade the rest. "
                    "If the cross-system admin role is genuinely needed, "
                    "enforce 2-step verification everywhere and consider a "
                    "dedicated admin-only account separate from the daily "
                    "identity."
                ),
            )
        )
    return findings
