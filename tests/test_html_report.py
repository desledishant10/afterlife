from afterlife import db
from afterlife.models import Finding, Identity, Severity
from afterlife.reporting.html_report import write_html_report


def _seed(db_path, *, identities=(), findings=()):
    with db.connect(db_path) as conn:
        for i in identities:
            db.upsert_identity(conn, i)
        for f in findings:
            db.insert_finding(conn, f)


def test_empty_db_renders_with_placeholders(fresh_db):
    html = write_html_report(fresh_db)
    assert "Afterlife report" in html
    assert "No findings recorded." in html
    assert "No identities collected yet." in html


def test_finding_appears_with_severity_badge(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="UNUSED-CREDENTIAL",
                severity=Severity.HIGH,
                title="Old key not used in 120 days",
                description="An access key has been idle.",
                evidence={"credential_id": "AKIA-FAKE", "days": 120},
                suggested_remediation="Revoke it.",
            )
        ],
    )

    html = write_html_report(fresh_db)
    assert 'class="badge high"' in html
    assert "UNUSED-CREDENTIAL" in html
    assert "Old key not used in 120 days" in html
    assert "AKIA-FAKE" in html
    assert "Revoke it." in html


def test_severity_counts_match(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(rule_id="A", severity=Severity.CRITICAL, title="c1", description=""),
            Finding(rule_id="A", severity=Severity.CRITICAL, title="c2", description=""),
            Finding(rule_id="B", severity=Severity.HIGH, title="h1", description=""),
            Finding(rule_id="C", severity=Severity.MEDIUM, title="m1", description=""),
        ],
    )

    html = write_html_report(fresh_db)
    # Severity tiles render the count followed by the label in the next span.
    assert 'class="count">2</span><span class="label">Critical' in html
    assert 'class="count">1</span><span class="label">High' in html
    assert 'class="count">1</span><span class="label">Medium' in html
    assert 'class="count">0</span><span class="label">Low' in html


def test_cross_source_person_flagged(fresh_db):
    _seed(
        fresh_db,
        identities=[
            Identity(
                source="aws",
                source_id="arn:1",
                email="alice@example.com",
                name="alice",
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

    html = write_html_report(fresh_db)
    assert "alice@example.com" in html
    assert "cross-source" in html
    assert "status-suspended" in html


def test_html_escapes_user_supplied_strings(fresh_db):
    """Identity source_ids and finding titles must be HTML-escaped to prevent XSS."""
    _seed(
        fresh_db,
        identities=[
            Identity(
                source="aws",
                source_id="<script>alert(1)</script>",
                email="evil@example.com",
                name="evil",
                status="active",
            )
        ],
        findings=[
            Finding(
                rule_id="X",
                severity=Severity.LOW,
                title="<img src=x onerror=alert(1)>",
                description="<b>bold</b>",
            )
        ],
    )

    html = write_html_report(fresh_db)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_findings_sorted_by_severity(fresh_db):
    """Criticals should appear before highs, etc."""
    _seed(
        fresh_db,
        findings=[
            Finding(rule_id="LOW", severity=Severity.LOW, title="low-finding", description=""),
            Finding(
                rule_id="CRIT", severity=Severity.CRITICAL, title="crit-finding", description=""
            ),
            Finding(rule_id="MED", severity=Severity.MEDIUM, title="med-finding", description=""),
        ],
    )

    html = write_html_report(fresh_db)
    crit_pos = html.find("crit-finding")
    med_pos = html.find("med-finding")
    low_pos = html.find("low-finding")
    assert crit_pos < med_pos < low_pos


def test_self_contained_no_external_resources(fresh_db):
    """The report must not pull in external CSS, JS, fonts, or images."""
    html = write_html_report(fresh_db)
    assert 'src="http' not in html
    assert 'href="http' not in html
    assert "<script " not in html  # accidentally including a script tag
