from fastapi.testclient import TestClient

from afterlife import db
from afterlife.models import BlastRadius, Finding, Identity, Severity
from afterlife.web import create_app


def _client(db_path):
    return TestClient(create_app(db_path))


def _seed(db_path, *, identities=(), findings=()):
    with db.connect(db_path) as conn:
        for i in identities:
            db.upsert_identity(conn, i)
        for f in findings:
            db.insert_finding(conn, f)


def test_overview_renders_with_empty_db(fresh_db):
    client = _client(fresh_db)
    r = client.get("/")
    assert r.status_code == 200
    assert "Overview" in r.text
    assert "No findings yet" in r.text


def test_overview_shows_severity_counts(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="A", severity=Severity.CRITICAL, title="c1", description=""
            ),
            Finding(rule_id="A", severity=Severity.CRITICAL, title="c2", description=""),
            Finding(rule_id="B", severity=Severity.HIGH, title="h1", description=""),
        ],
    )

    r = _client(fresh_db).get("/")
    assert r.status_code == 200
    # Two criticals, one high. The metric blocks render the count
    # immediately next to the label span.
    assert 'class="count">2</span>\n      <span class="label">Critical' in r.text
    assert 'class="count">1</span>\n      <span class="label">High' in r.text


def test_findings_page_lists_all_findings(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="UNUSED-CREDENTIAL",
                severity=Severity.HIGH,
                title="Stale key",
                description="key idle",
                evidence={"credential_id": "AKIA-1"},
            ),
            Finding(
                rule_id="NEVER-USED",
                severity=Severity.MEDIUM,
                title="Never used",
                description="never used",
                evidence={"credential_id": "AKIA-2"},
            ),
        ],
    )

    r = _client(fresh_db).get("/findings")
    assert r.status_code == 200
    assert "Stale key" in r.text
    assert "Never used" in r.text
    assert "UNUSED-CREDENTIAL" in r.text


def test_findings_severity_filter(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="A",
                severity=Severity.CRITICAL,
                title="critical-finding-title",
                description="",
            ),
            Finding(
                rule_id="B",
                severity=Severity.HIGH,
                title="high-finding-title",
                description="",
            ),
        ],
    )

    r = _client(fresh_db).get("/findings?severity=high")
    assert "high-finding-title" in r.text
    assert "critical-finding-title" not in r.text


def test_findings_rule_filter(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(rule_id="X", severity=Severity.LOW, title="x-finding", description=""),
            Finding(rule_id="Y", severity=Severity.LOW, title="y-finding", description=""),
        ],
    )

    r = _client(fresh_db).get("/findings?rule=X")
    assert "x-finding" in r.text
    assert "y-finding" not in r.text


def test_findings_blast_filter(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="A",
                severity=Severity.MEDIUM,
                title="broad-finding",
                description="",
                blast_radius=BlastRadius(score=0.85, factors=["wide"]),
            ),
            Finding(
                rule_id="B",
                severity=Severity.MEDIUM,
                title="limited-finding",
                description="",
                blast_radius=BlastRadius(score=0.20, factors=["small"]),
            ),
        ],
    )

    r = _client(fresh_db).get("/findings?blast=broad")
    assert "broad-finding" in r.text
    assert "limited-finding" not in r.text


def test_identities_page_renders_persons(fresh_db):
    _seed(
        fresh_db,
        identities=[
            Identity(
                source="aws",
                source_id="arn:1",
                email="alice@example.com",
                name="Alice",
                status="active",
            ),
            Identity(
                source="google",
                source_id="g1",
                email="alice@example.com",
                name="Alice",
                status="suspended",
            ),
        ],
    )

    r = _client(fresh_db).get("/identities")
    assert r.status_code == 200
    assert "alice@example.com" in r.text
    assert "cross-source" in r.text
    assert "status-suspended" in r.text


def test_identities_cross_source_only_filter(fresh_db):
    _seed(
        fresh_db,
        identities=[
            Identity(
                source="aws",
                source_id="arn:1",
                email="alice@example.com",
                name="Alice",
                status="active",
            ),
            Identity(
                source="google",
                source_id="g1",
                email="alice@example.com",
                name="Alice",
                status="suspended",
            ),
            Identity(
                source="github",
                source_id="solo",
                email=None,
                name="solo",
                status="active",
            ),
        ],
    )

    r = _client(fresh_db).get("/identities?cross_source_only=true")
    assert r.status_code == 200
    assert "alice@example.com" in r.text
    assert "solo" not in r.text


def test_html_escapes_user_supplied_strings(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="X",
                severity=Severity.LOW,
                title="<script>alert(1)</script>",
                description="<b>bold</b>",
                evidence={"credential_id": "<img>"},
            )
        ],
    )

    r = _client(fresh_db).get("/findings")
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


def test_nav_marks_active_tab(fresh_db):
    client = _client(fresh_db)
    r = client.get("/findings")
    # Active class marks the current tab in the nav
    assert 'class="tab active" href="/findings"' in r.text
