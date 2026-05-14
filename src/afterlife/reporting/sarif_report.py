"""SARIF v2.1.0 output for CI integration.

SARIF (Static Analysis Results Interchange Format) is the format that GitHub
Code Scanning, Azure DevOps, GitLab, and most security pipelines speak. Each
Afterlife finding maps to one SARIF `result`; each detection rule maps to one
`reportingDescriptor` in the tool driver.

Findings are not file-based, so we emit `logicalLocations` with the credential
identifier rather than `physicalLocation` (path/line). Code Scanning still
ingests these and lists them as alerts; they just won't deep-link to a file.

Severity is mapped to SARIF's `level` field:
  critical, high -> error
  medium         -> warning
  low            -> note
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from afterlife import __version__, db
from afterlife.rules.registry import all_rules

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def write_sarif_report(db_path: Path) -> str:
    findings = _load_findings(db_path)
    rules = all_rules()

    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Afterlife",
                        "version": __version__,
                        "informationUri": "https://github.com/anthropics/afterlife",
                        "rules": [_rule_descriptor(r) for r in rules],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        ),
                    }
                ],
                "results": [_result(f) for f in findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _rule_descriptor(rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.id.replace("-", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "defaultConfiguration": {
            "level": SEVERITY_TO_LEVEL.get(rule.default_severity.value, "warning")
        },
        "properties": {
            "tags": ["security", "iam", "ghost-access"],
            "severity": rule.default_severity.value,
        },
    }


def _result(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence") or {}
    credential_id = evidence.get("credential_id") or finding.get("identity_id") or "?"
    return {
        "ruleId": finding["rule_id"],
        "level": SEVERITY_TO_LEVEL.get(finding["severity"], "warning"),
        "message": {"text": finding["description"]},
        "locations": [
            {
                "logicalLocations": [
                    {"name": str(credential_id), "kind": "resource"}
                ]
            }
        ],
        "properties": {
            "title": finding["title"],
            "severity": finding["severity"],
            "evidence": evidence,
            "suggested_remediation": finding.get("suggested_remediation"),
            "identity_source": finding.get("identity_source"),
            "identity_id": finding.get("identity_id"),
            "detected_at": finding.get("detected_at"),
        },
    }


def _load_findings(db_path: Path) -> list[dict[str, Any]]:
    with db.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT rule_id, severity, title, description,
                   identity_source, identity_id, evidence,
                   suggested_remediation, detected_at
            FROM findings
            """
        ).fetchall()
    findings: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        if d.get("evidence"):
            d["evidence"] = json.loads(d["evidence"])
        findings.append(d)
    return findings
