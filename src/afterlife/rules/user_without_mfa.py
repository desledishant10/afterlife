"""USER-WITHOUT-MFA: an active non-admin identity has no 2-step verification.

The Snowflake 2024 campaign showed the cost of MFA gaps on ordinary accounts:
attackers replayed stolen passwords against user accounts that had no second
factor and exfiltrated data at scale. Admin gaps are reported separately as
ADMIN-WITHOUT-MFA (Critical); this rule surfaces the broader population of
active non-admin identities we can confirm are not protected by 2-step
verification.

We fire only on positive evidence that 2SV is absent, and only for sources that
report the signal (Google Workspace today). A source that does not surface MFA
state stays quiet rather than producing noise.
"""

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule


@rule(
    id="USER-WITHOUT-MFA",
    title="Active user without 2-step verification",
    description=(
        "An active non-admin IdP identity does not have 2-step verification "
        "enforced. Password-only accounts are the entry point behind "
        "credential-stuffing breaches like Snowflake 2024. Admin gaps are "
        "reported separately as ADMIN-WITHOUT-MFA."
    ),
    severity=Severity.MEDIUM,
)
def user_without_mfa(conn, config, graph) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for person in graph.persons():
        for ident in person.identities:
            md = ident.metadata or {}
            if md.get("is_admin"):
                continue  # admins are covered by ADMIN-WITHOUT-MFA (Critical)
            if (ident.status or "").lower() != "active":
                continue
            if not _confirmed_no_2sv(ident, md):
                continue
            key = (ident.source, ident.source_id)
            if key in seen:
                continue
            seen.add(key)

            label = person.canonical_email or ident.email or ident.source_id
            findings.append(
                Finding(
                    rule_id="USER-WITHOUT-MFA",
                    severity=Severity.MEDIUM,
                    title=(
                        f"{ident.source} user {label} without 2-step verification"
                    ),
                    description=(
                        f"Identity {ident.source_id} in {ident.source} is active "
                        "and not an admin, but has no 2-step verification "
                        "enforced. Password-only access is the entry point for "
                        "credential-stuffing and phishing."
                    ),
                    identity_source=ident.source,
                    identity_id=ident.source_id,
                    evidence={
                        "source": ident.source,
                        "source_id": ident.source_id,
                        "email": person.canonical_email or ident.email,
                        "is_enforced_in_2sv": md.get("is_enforced_in_2sv"),
                        "is_enrolled_in_2sv": md.get("is_enrolled_in_2sv"),
                    },
                    suggested_remediation=(
                        "Enforce 2-step verification for this user. For Google "
                        "Workspace, enforce 2SV at the org-unit or group level so "
                        "existing and new users are covered."
                    ),
                )
            )
    return findings


def _confirmed_no_2sv(ident, md: dict) -> bool:
    """True only when we can positively confirm 2SV is not in effect.

    Mirrors ADMIN-WITHOUT-MFA: return False (stay quiet) whenever the source
    does not surface the signal or we have evidence 2SV is on.
    """
    if ident.source == "google":
        enforced = md.get("is_enforced_in_2sv")
        if enforced is True:
            return False
        if enforced is False:
            return True
        # Enforcement unknown: treat as a gap only if enrollment is also absent.
        return md.get("is_enrolled_in_2sv") is False
    # Okta / Entra factor state not captured by our collectors yet; future work.
    return False
