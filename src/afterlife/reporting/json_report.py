import json
from pathlib import Path

from afterlife import db


def write_json_report(db_path: Path) -> str:
    with db.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT rule_id, severity, title, description,
                   identity_source, identity_id, evidence,
                   suggested_remediation, detected_at
            FROM findings
            ORDER BY
              CASE severity
                WHEN 'critical' THEN 0
                WHEN 'high'     THEN 1
                WHEN 'medium'   THEN 2
                WHEN 'low'      THEN 3
              END,
              detected_at DESC
            """
        ).fetchall()

    findings = []
    for r in rows:
        d = dict(r)
        if d.get("evidence"):
            d["evidence"] = json.loads(d["evidence"])
        findings.append(d)
    return json.dumps({"count": len(findings), "findings": findings}, indent=2)
