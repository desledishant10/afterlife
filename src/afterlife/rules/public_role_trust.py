"""PUBLIC-ROLE-TRUST: an IAM role is assumable by any AWS principal.

A trust policy whose Principal is `*` (or `AWS: "*"`, or an ARN with a wildcard
account) lets any AWS account assume the role, and in the anonymous `*` form,
anyone at all. This is strictly worse than the specific external-account trust
that CROSS-ACCOUNT-TRUST reports: there is no named counterparty to vet.

A wildcard is only safe when a Condition meaningfully constrains who may assume
(an org id, a principal ARN/account, a source account, or an ExternalId). This
rule fires only on an unconstrained wildcard, so the common safe pattern
(`Principal: *` gated by `aws:PrincipalOrgID`) stays quiet.
"""

from __future__ import annotations

import json
from typing import Any

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule

# Condition keys that meaningfully restrict WHO may assume the role. A wildcard
# Principal paired with one of these is not actually open to everyone.
_CONSTRAINING_CONDITION_KEYS = {
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalarn",
    "aws:principalaccount",
    "aws:sourceaccount",
    "aws:sourceowner",
    "sts:externalid",
}


@rule(
    id="PUBLIC-ROLE-TRUST",
    title="IAM role assumable by any AWS principal",
    description=(
        "An IAM role's trust policy allows assume-role from a wildcard "
        "principal with no condition restricting who may assume it. Any AWS "
        "account (or, in the anonymous form, anyone) can assume the role, "
        "making it a direct path into the account."
    ),
    severity=Severity.CRITICAL,
)
def public_role_trust(conn, config, graph) -> list[Finding]:
    rows = conn.execute(
        """
        SELECT credential_id, credential_type, metadata
        FROM credentials
        WHERE source = 'aws' AND credential_type = 'aws_iam_role'
        """
    ).fetchall()

    findings: list[Finding] = []
    for row in rows:
        try:
            meta = json.loads(row["metadata"]) if row["metadata"] else {}
        except (TypeError, json.JSONDecodeError):
            continue
        trust_policy = meta.get("assume_role_policy_document")
        if not isinstance(trust_policy, dict):
            continue
        open_statements = _open_wildcard_statements(trust_policy)
        if not open_statements:
            continue

        role_name = meta.get("role_name") or row["credential_id"]
        findings.append(
            Finding(
                rule_id="PUBLIC-ROLE-TRUST",
                severity=Severity.CRITICAL,
                title=f"IAM role {role_name} is assumable by any AWS principal",
                description=(
                    f"Role {row['credential_id']} has a trust policy that "
                    "allows assume-role from a wildcard principal with no "
                    "condition restricting who may assume it. Any AWS account "
                    "can assume this role and inherit its permissions."
                ),
                evidence={
                    "credential_id": row["credential_id"],
                    "credential_type": row["credential_type"],
                    "role_name": role_name,
                    "own_account_id": meta.get("account_id"),
                    "open_statements": open_statements,
                },
                suggested_remediation=(
                    "Replace the wildcard Principal with your own account id or "
                    "specific principal ARNs. If cross-account access is truly "
                    "required, name the accounts and add a Condition "
                    "(aws:PrincipalOrgID or sts:ExternalId) so the role is not "
                    "assumable by the entire world."
                ),
            )
        )
    return findings


def _open_wildcard_statements(trust_policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = trust_policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    out: list[dict[str, Any]] = []
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        if not any(
            isinstance(a, str) and a.lower().startswith("sts:assume")
            for a in actions
        ):
            continue
        if not _principal_is_wildcard(stmt.get("Principal")):
            continue
        if _has_constraining_condition(stmt):
            continue
        out.append({"principal": stmt.get("Principal"), "actions": actions})
    return out


def _principal_is_wildcard(principal: Any) -> bool:
    # Anonymous form: Principal: "*"
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        values = [aws] if isinstance(aws, str) else (aws or [])
        return any(isinstance(v, str) and _arn_is_wildcard(v) for v in values)
    return False


def _arn_is_wildcard(value: str) -> bool:
    if value == "*":
        return True
    # An ARN whose account field contains a wildcard, e.g. arn:aws:iam::*:root
    if value.startswith("arn:"):
        parts = value.split(":")
        return len(parts) >= 5 and "*" in parts[4]
    return False


def _has_constraining_condition(stmt: dict[str, Any]) -> bool:
    condition = stmt.get("Condition")
    if not isinstance(condition, dict):
        return False
    for comparison in condition.values():
        if not isinstance(comparison, dict):
            continue
        for key in comparison:
            if isinstance(key, str) and key.lower() in _CONSTRAINING_CONDITION_KEYS:
                return True
    return False
