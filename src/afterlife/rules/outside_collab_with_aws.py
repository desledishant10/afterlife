from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule


@rule(
    id="OUTSIDE-COLLAB-WITH-AWS",
    title="GitHub outside collaborator linked to AWS access",
    description=(
        "A user marked as 'outside collaborator' on GitHub (not a full org "
        "member) is linked via email to an AWS IAM user. External "
        "contractors and vendors should generally not hold long-lived cloud "
        "credentials; if they need access, it should be time-boxed via "
        "Identity Center / Roles Anywhere."
    ),
    severity=Severity.HIGH,
)
def outside_collab_with_aws(conn, config, graph) -> list[Finding]:
    findings: list[Finding] = []
    for person in graph.persons():
        github = person.identity_in("github")
        aws = person.identity_in("aws")
        if not github or not aws:
            continue
        if not (github.metadata or {}).get("is_outside_collaborator"):
            continue

        aws_credentials = [
            c for c in graph.credentials_for_person(person)
            if c.source == "aws" and c.is_active
        ]

        if aws_credentials:
            for cred in aws_credentials:
                findings.append(
                    Finding(
                        rule_id="OUTSIDE-COLLAB-WITH-AWS",
                        severity=Severity.HIGH,
                        title=(
                            f"GitHub outside collaborator {github.source_id} "
                            f"owns AWS credential {cred.credential_id}"
                        ),
                        description=(
                            f"User {github.source_id} is an outside collaborator on "
                            f"GitHub (not a full org member) yet owns an active "
                            f"{cred.credential_type} on AWS. External users should "
                            "not hold long-lived static credentials."
                        ),
                        identity_source="github",
                        identity_id=github.source_id,
                        evidence={
                            "github_login": github.source_id,
                            "owner_email": person.canonical_email,
                            "credential_id": cred.credential_id,
                            "credential_type": cred.credential_type,
                            "credential_source": cred.source,
                            "is_outside_collaborator": True,
                        },
                        suggested_remediation=(
                            f"Revoke {cred.credential_id} or migrate this access "
                            "to a time-boxed pattern (IAM Identity Center with "
                            "short sessions, IAM Roles Anywhere for CI). External "
                            "users should not hold long-lived static credentials."
                        ),
                    )
                )
        else:
            findings.append(
                Finding(
                    rule_id="OUTSIDE-COLLAB-WITH-AWS",
                    severity=Severity.HIGH,
                    title=(
                        f"GitHub outside collaborator {github.source_id} "
                        f"matches AWS identity {aws.source_id}"
                    ),
                    description=(
                        f"Outside collaborator {github.source_id} is linked to AWS "
                        f"identity {aws.source_id} by email. No active credentials "
                        "are currently attached, but the link is worth reviewing."
                    ),
                    identity_source="github",
                    identity_id=github.source_id,
                    evidence={
                        "github_login": github.source_id,
                        "owner_email": person.canonical_email,
                        "aws_identity": aws.source_id,
                        "is_outside_collaborator": True,
                    },
                    suggested_remediation=(
                        "Confirm whether this AWS access is intentional. If not, "
                        "remove the IAM user."
                    ),
                )
            )
    return findings
