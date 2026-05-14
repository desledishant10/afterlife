from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule


@rule(
    id="ADMIN-WITHOUT-MFA",
    title="IdP admin without 2-step verification enforced",
    description=(
        "An IdP identity flagged as admin does not have 2-step verification "
        "enforced. Admin account compromise via password reuse or phishing is "
        "catastrophic since admins can escalate to every downstream system. "
        "Enforced 2FA is the minimum bar."
    ),
    severity=Severity.CRITICAL,
)
def admin_without_mfa(conn, config, graph) -> list[Finding]:
    findings: list[Finding] = []
    seen_keys: set[tuple[str, str]] = set()

    for person in graph.persons():
        for ident in person.identities:
            md = ident.metadata or {}
            if not md.get("is_admin"):
                continue
            if not _missing_mfa(ident, md):
                continue
            key = (ident.source, ident.source_id)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            label = person.canonical_email or ident.source_id
            findings.append(
                Finding(
                    rule_id="ADMIN-WITHOUT-MFA",
                    severity=Severity.CRITICAL,
                    title=(
                        f"{ident.source} admin {label} without 2-step "
                        "verification enforced"
                    ),
                    description=(
                        f"Identity {ident.source_id} is flagged as admin in "
                        f"{ident.source} but does not have 2-step verification "
                        "enforced. A compromised admin account can be used to "
                        "escalate to any downstream system this person is linked to."
                    ),
                    identity_source=ident.source,
                    identity_id=ident.source_id,
                    evidence={
                        "admin_in": ident.source,
                        "admin_id": ident.source_id,
                        "owner_email": person.canonical_email,
                        "is_enforced_in_2sv": md.get("is_enforced_in_2sv"),
                        "is_enrolled_in_2sv": md.get("is_enrolled_in_2sv"),
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
                        "Enforce 2-step verification on this account immediately. "
                        "For Google Workspace: Admin Console → Security → "
                        "2-step verification → set to required. For Okta: "
                        "require an MFA factor at the group or app level."
                    ),
                )
            )
    return findings


def _missing_mfa(ident, metadata: dict) -> bool:
    """Source-specific check for whether 2-step verification is enforced.

    Returns True when we can confirm 2SV is not in effect. Returns False if
    we have positive evidence that it is enforced, or if the source does not
    surface the signal (in which case we don't fire to avoid noise).
    """
    if ident.source == "google":
        enforced = metadata.get("is_enforced_in_2sv")
        if enforced is True:
            return False
        # Anything other than True (False, None) means we can't confirm.
        # We treat None as "missing" only when is_enrolled is also False,
        # which strongly suggests no 2SV at all.
        if enforced is False:
            return True
        enrolled = metadata.get("is_enrolled_in_2sv")
        return enrolled is False
    # Okta signal not yet captured by our collector; future work.
    return False
