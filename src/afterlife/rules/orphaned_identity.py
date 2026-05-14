from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule

IDP_SOURCES = frozenset({"okta", "google"})
DOWNSTREAM_SOURCES = frozenset({"aws", "github"})


@rule(
    id="ORPHANED-IDENTITY",
    title="Active IdP identity has no downstream system access",
    description=(
        "An identity in the IdP (Okta or Google Workspace) is active but does "
        "not appear in any downstream system (AWS, GitHub). Either the user "
        "does not need downstream access (legitimate), or downstream "
        "provisioning never completed (a gap to close). Low-severity hygiene "
        "signal, but useful for audits."
    ),
    severity=Severity.LOW,
)
def orphaned_identity(conn, config, graph) -> list[Finding]:
    findings: list[Finding] = []
    for person in graph.persons():
        sources = person.sources
        if not (sources & IDP_SOURCES):
            continue
        if sources & DOWNSTREAM_SOURCES:
            continue
        active = [
            i for i in person.identities
            if (i.status or "").lower() == "active"
        ]
        if not active:
            # Already deprovisioned; OFFBOARDED-OWNER would cover any credentials.
            continue
        primary = active[0]
        label = person.canonical_email or primary.source_id
        findings.append(
            Finding(
                rule_id="ORPHANED-IDENTITY",
                severity=Severity.LOW,
                title=(
                    f"{primary.source} identity {label} has no downstream access"
                ),
                description=(
                    f"Identity {primary.source_id} is active in {primary.source} "
                    "but does not appear in any AWS or GitHub source. Either the "
                    "user does not need downstream access, or provisioning has "
                    "not completed."
                ),
                identity_source=primary.source,
                identity_id=primary.source_id,
                evidence={
                    "idp_source": primary.source,
                    "idp_id": primary.source_id,
                    "owner_email": person.canonical_email,
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
                    "Confirm whether this user needs AWS or GitHub access. If "
                    "not, no action required. If yes, complete provisioning."
                ),
            )
        )
    return findings
