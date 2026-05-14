import json

from afterlife import db
from afterlife.models import Finding, Severity
from afterlife.reporting.sarif_report import write_sarif_report


def _seed_findings(db_path, findings):
    with db.connect(db_path) as conn:
        for f in findings:
            db.insert_finding(conn, f)


def _parse(db_path):
    return json.loads(write_sarif_report(db_path))


def test_empty_db_produces_valid_sarif(fresh_db):
    sarif = _parse(fresh_db)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Afterlife"
    assert run["results"] == []


def test_tool_driver_advertises_all_rules(fresh_db):
    sarif = _parse(fresh_db)
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids >= {
        "OFFBOARDED-OWNER", "UNUSED-CREDENTIAL", "NEVER-USED", "UNROTATED-KEY"
    }


def test_severity_maps_to_sarif_level(fresh_db):
    _seed_findings(
        fresh_db,
        [
            Finding(
                rule_id="A", severity=Severity.CRITICAL, title="c", description="d"
            ),
            Finding(rule_id="B", severity=Severity.HIGH, title="h", description="d"),
            Finding(rule_id="C", severity=Severity.MEDIUM, title="m", description="d"),
            Finding(rule_id="D", severity=Severity.LOW, title="l", description="d"),
        ],
    )
    sarif = _parse(fresh_db)
    results = sarif["runs"][0]["results"]
    levels_by_rule = {r["ruleId"]: r["level"] for r in results}
    assert levels_by_rule == {"A": "error", "B": "error", "C": "warning", "D": "note"}


def test_finding_evidence_preserved_in_properties(fresh_db):
    _seed_findings(
        fresh_db,
        [
            Finding(
                rule_id="OFFBOARDED-OWNER",
                severity=Severity.CRITICAL,
                title="Bob's key still active",
                description="bob is suspended in google",
                evidence={
                    "credential_id": "AKIA-BOB",
                    "owner_email": "bob@example.com",
                    "deprovisioned_in": "google",
                },
                suggested_remediation="Revoke AKIA-BOB.",
                identity_source="google",
                identity_id="00uBOB",
            )
        ],
    )
    sarif = _parse(fresh_db)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "OFFBOARDED-OWNER"
    assert result["level"] == "error"
    assert result["message"]["text"] == "bob is suspended in google"
    location = result["locations"][0]["logicalLocations"][0]
    assert location["name"] == "AKIA-BOB"
    assert location["kind"] == "resource"
    props = result["properties"]
    assert props["evidence"]["owner_email"] == "bob@example.com"
    assert props["suggested_remediation"] == "Revoke AKIA-BOB."
    assert props["identity_source"] == "google"
    assert props["identity_id"] == "00uBOB"


def test_logical_location_falls_back_to_identity_id(fresh_db):
    _seed_findings(
        fresh_db,
        [
            Finding(
                rule_id="X",
                severity=Severity.MEDIUM,
                title="t",
                description="d",
                evidence={},
                identity_id="some-identity",
            )
        ],
    )
    sarif = _parse(fresh_db)
    location = sarif["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
    assert location["name"] == "some-identity"


def test_invocation_timestamp_present(fresh_db):
    sarif = _parse(fresh_db)
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    # Format check: ISO 8601 with trailing Z
    assert invocation["endTimeUtc"].endswith("Z")
    assert "T" in invocation["endTimeUtc"]


def test_sarif_is_valid_json(fresh_db):
    """The output must parse as JSON (regression guard)."""
    text = write_sarif_report(fresh_db)
    parsed = json.loads(text)
    assert isinstance(parsed, dict)
