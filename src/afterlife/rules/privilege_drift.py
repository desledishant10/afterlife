"""PRIVILEGE-DRIFT: an IAM role is granted far more than it uses.

An IAM role's attached policies grant access to a set of AWS services, but the
role actually touches only a fraction of them. The unused-but-granted subset is
ghost access: it does nothing for the workload and everything for an attacker
who compromises the role. This rule surfaces active roles whose granted-service
footprint is much larger than their observed usage.

Input: `aws_iam_role` credentials carrying `metadata.service_access`, a list of
{service, last_authenticated} records from IAM Access Advisor
(GenerateServiceLastAccessedDetails). A service is "used" if it was accessed
within `privilege_drift_days` (default 90); the rule fires when a role has an
observed usage profile (at least one used service) yet at least
`privilege_drift_min_unused` granted services it does not use.
"""

import json
from datetime import UTC, datetime, timedelta

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule

_SAMPLE = 12


def _used_recently(last_authenticated, cutoff: datetime) -> bool:
    if not last_authenticated:
        return False
    try:
        return datetime.fromisoformat(last_authenticated) >= cutoff
    except ValueError:
        return False


@rule(
    id="PRIVILEGE-DRIFT",
    title="IAM role is granted far more access than it uses",
    description=(
        "An active IAM role can reach many AWS services its policies grant but "
        "that it has not used within N days (default 90). The unused-but-granted "
        "services are ghost access: dead weight for the workload, live blast "
        "radius for an attacker who compromises the role."
    ),
    severity=Severity.MEDIUM,
)
def privilege_drift(conn, config, graph) -> list[Finding]:
    cutoff = datetime.now(UTC) - timedelta(days=config.privilege_drift_days)
    rows = conn.execute(
        """
        SELECT credential_id, credential_type, metadata
        FROM credentials
        WHERE is_active = 1 AND credential_type = 'aws_iam_role'
        """
    ).fetchall()

    findings: list[Finding] = []
    for r in rows:
        meta = json.loads(r["metadata"]) if r["metadata"] else {}
        service_access = meta.get("service_access") or []
        if not service_access:
            continue
        used: list[str] = []
        unused: list[str] = []
        for s in service_access:
            if _used_recently(s.get("last_authenticated"), cutoff):
                used.append(s.get("service"))
            else:
                unused.append(s.get("service"))
        # Needs an observed usage profile plus a material unused surplus, so a
        # role that is simply never used (covered elsewhere) does not fire here.
        if len(used) < 1 or len(unused) < config.privilege_drift_min_unused:
            continue
        role_name = meta.get("role_name") or r["credential_id"]
        granted = len(service_access)
        findings.append(
            Finding(
                rule_id="PRIVILEGE-DRIFT",
                severity=Severity.MEDIUM,
                title=(
                    f"IAM role {role_name} uses {len(used)} of {granted} "
                    f"granted services"
                ),
                description=(
                    f"Role {r['credential_id']} is granted access to {granted} "
                    f"AWS services but has used only {len(used)} in the last "
                    f"{config.privilege_drift_days} days. The other "
                    f"{len(unused)} are unused, over-broad permissions."
                ),
                evidence={
                    "credential_id": r["credential_id"],
                    "credential_type": r["credential_type"],
                    "credential_source": "aws",
                    "role_name": role_name,
                    "granted_services": granted,
                    "used_services": len(used),
                    "unused_services": len(unused),
                    "unused_sample": sorted(u for u in unused if u)[:_SAMPLE],
                    "threshold_days": config.privilege_drift_days,
                },
                suggested_remediation=(
                    "Right-size the role's policies to the services it actually "
                    "uses (IAM Access Analyzer can generate a least-privilege "
                    "policy from this access history). Remove or scope down the "
                    "unused grants."
                ),
            )
        )
    return findings
