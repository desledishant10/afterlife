from datetime import datetime, timedelta, timezone

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule


@rule(
    id="INACTIVE-ADMIN",
    title="Admin account has not logged in within the inactivity window",
    description=(
        "An IdP identity flagged as admin has not logged in for more than N "
        "days (default 30). Dormant admin accounts are prime targets for "
        "credential stuffing and phishing; if there is no business reason for "
        "the admin role, it should be downgraded."
    ),
    severity=Severity.HIGH,
)
def inactive_admin(conn, config, graph) -> list[Finding]:
    findings: list[Finding] = []
    cutoff = datetime.now(timezone.utc) - timedelta(
        days=config.inactive_admin_days
    )
    seen: set[tuple[str, str]] = set()

    for person in graph.persons():
        for ident in person.identities:
            md = ident.metadata or {}
            if not md.get("is_admin"):
                continue
            last_login_str = md.get("last_login_time") or md.get("last_login")
            last_login = _parse(last_login_str)
            if last_login is None or last_login >= cutoff:
                continue
            key = (ident.source, ident.source_id)
            if key in seen:
                continue
            seen.add(key)

            label = person.canonical_email or ident.source_id
            days = (datetime.now(timezone.utc) - last_login).days
            findings.append(
                Finding(
                    rule_id="INACTIVE-ADMIN",
                    severity=Severity.HIGH,
                    title=(
                        f"{ident.source} admin {label} has not logged in "
                        f"for {days} days"
                    ),
                    description=(
                        f"Admin identity {ident.source_id} in {ident.source} "
                        f"last logged in on {last_login_str}, {days} days ago. "
                        f"Threshold for this rule is "
                        f"{config.inactive_admin_days} days. Dormant admin "
                        "accounts are high-value targets."
                    ),
                    identity_source=ident.source,
                    identity_id=ident.source_id,
                    evidence={
                        "admin_in": ident.source,
                        "admin_id": ident.source_id,
                        "owner_email": person.canonical_email,
                        "last_login": last_login_str,
                        "days_since_last_login": days,
                        "threshold_days": config.inactive_admin_days,
                    },
                    suggested_remediation=(
                        "Confirm whether this user still needs admin "
                        "privileges. If not, downgrade to a regular user or "
                        "deprovision. If yes, document the business reason "
                        "and enforce 2-step verification."
                    ),
                )
            )
    return findings


def _parse(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
