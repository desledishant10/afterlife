"""CROSS-ACCOUNT-TRUST: an IAM role trusts an external AWS account.

External-account trust is the precondition for the Capital One 2019 pattern:
a third-party WAF role was assumable from a foreign account, and that path
was used to reach S3 data. Trust policies that grant `sts:AssumeRole` to a
principal in a different AWS account warrant scrutiny even when intentional.

This rule is conservative: AWS service principals (ec2.amazonaws.com,
lambda.amazonaws.com, etc.), federated identities, and same-account
principals do not fire it. Only `Principal.AWS` ARNs with an account ID
different from the role's own account ID count.
"""

from __future__ import annotations

import json
from typing import Any

from afterlife.models import Finding, Severity
from afterlife.rules.registry import rule


@rule(
    id="CROSS-ACCOUNT-TRUST",
    title="IAM role trusts an external AWS account",
    description=(
        "An IAM role's trust policy allows assume-role from an AWS principal "
        "in a different account. Cross-account trust is the precondition for "
        "the Capital One 2019 breach pattern and is worth reviewing even when "
        "intentional."
    ),
    severity=Severity.CRITICAL,
)
def cross_account_trust(conn, config, graph) -> list[Finding]:
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
        own_account = meta.get("account_id")
        external = _find_external_principals(trust_policy, own_account)
        if not external:
            continue

        role_name = meta.get("role_name") or row["credential_id"]
        external_accounts = sorted({e["account_id"] for e in external})
        findings.append(
            Finding(
                rule_id="CROSS-ACCOUNT-TRUST",
                severity=Severity.CRITICAL,
                title=(
                    f"IAM role {role_name} trusts external account(s): "
                    f"{', '.join(external_accounts)}"
                ),
                description=(
                    f"Role {row['credential_id']} has a trust policy that "
                    f"allows assume-role from {len(external)} external "
                    "principal(s). External-account trust is high-risk: it "
                    "is the precondition for the Capital One 2019 pattern."
                ),
                evidence={
                    "credential_id": row["credential_id"],
                    "credential_type": row["credential_type"],
                    "role_name": role_name,
                    "own_account_id": own_account,
                    "external_principals": external,
                },
                suggested_remediation=(
                    "Confirm the cross-account trust is intentional. If so, "
                    "scope the role's permissions to the minimum needed and "
                    "require ExternalId in the trust policy condition. If "
                    "not, restrict Principal to your own account."
                ),
            )
        )
    return findings


def _find_external_principals(
    trust_policy: dict[str, Any], own_account: str | None
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    statements = trust_policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
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
        principal = stmt.get("Principal")
        if not isinstance(principal, dict):
            continue
        aws_principal = principal.get("AWS")
        if aws_principal is None:
            continue
        if isinstance(aws_principal, str):
            aws_principal = [aws_principal]
        for arn in aws_principal:
            if not isinstance(arn, str):
                continue
            account = _account_from_principal(arn)
            if account and account != own_account:
                out.append({"arn": arn, "account_id": account})
    return out


def _account_from_principal(value: str) -> str | None:
    """Extract account id from a Principal.AWS value.

    Accepts:
      - 12-digit account number directly: "999999999999"
      - ARNs: "arn:aws:iam::999999999999:root", "...:user/foo", etc.
    """
    if value.isdigit() and len(value) == 12:
        return value
    if not value.startswith("arn:"):
        return None
    parts = value.split(":")
    if len(parts) < 5:
        return None
    candidate = parts[4]
    return candidate if candidate.isdigit() else None
