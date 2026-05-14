from fastapi.testclient import TestClient

from afterlife import db
from afterlife.models import BlastRadius, Credential, Finding, Identity, Severity
from afterlife.web import create_app


def _client(db_path):
    return TestClient(create_app(db_path))


def _seed(db_path, *, identities=(), credentials=(), findings=()):
    with db.connect(db_path) as conn:
        for i in identities:
            db.upsert_identity(conn, i)
        for c in credentials:
            db.upsert_credential(conn, c)
        for f in findings:
            db.insert_finding(conn, f)


def _last_finding_id(db_path):
    with db.connect(db_path) as conn:
        return conn.execute("SELECT MAX(id) AS id FROM findings").fetchone()["id"]


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
    # Two criticals, one high. Counts render in <span class="count"> immediately
    # followed (whitespace-separated) by a label span.
    import re
    crit_match = re.search(
        r'class="count">2</span>\s*<span class="label">Critical', r.text
    )
    high_match = re.search(
        r'class="count">1</span>\s*<span class="label">High', r.text
    )
    assert crit_match is not None
    assert high_match is not None


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


def test_security_headers_set_on_every_response(fresh_db):
    client = _client(fresh_db)
    for path in ["/", "/findings", "/identities", "/static/style.css"]:
        r = client.get(path)
        assert r.headers["X-Frame-Options"] == "DENY"
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["Referrer-Policy"] == "no-referrer"
        assert "Content-Security-Policy" in r.headers
        csp = r.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp


def test_openapi_and_docs_endpoints_disabled(fresh_db):
    """The dashboard should not expose introspection surface."""
    client = _client(fresh_db)
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_static_assets_served(fresh_db):
    client = _client(fresh_db)
    css = client.get("/static/style.css")
    assert css.status_code == 200
    assert "metric" in css.text  # one of our class names
    htmx = client.get("/static/htmx.min.js")
    assert htmx.status_code == 200
    assert "htmx" in htmx.text.lower()


def test_static_path_traversal_blocked(fresh_db):
    """StaticFiles must reject path traversal attempts."""
    client = _client(fresh_db)
    # Anything that escapes /static should 404, not return system files.
    r = client.get("/static/../app.py")
    assert r.status_code in (404, 400)


def test_finding_detail_renders(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="OFFBOARDED-OWNER",
                severity=Severity.CRITICAL,
                title="bob aws key still active",
                description="bob is suspended in google",
                evidence={"credential_id": "AKIA-BOB", "owner_email": "bob@example.com"},
                suggested_remediation="Revoke AKIA-BOB.",
                blast_radius=BlastRadius(score=0.85, factors=["admin"]),
            )
        ],
    )
    fid = _last_finding_id(fresh_db)
    r = _client(fresh_db).get(f"/findings/{fid}")
    assert r.status_code == 200
    assert "bob aws key still active" in r.text
    assert "AKIA-BOB" in r.text
    assert "Revoke AKIA-BOB" in r.text
    assert "broad" in r.text  # blast label


def test_finding_detail_404_for_missing(fresh_db):
    r = _client(fresh_db).get("/findings/999")
    assert r.status_code == 404


def test_credentials_list_shows_credentials(fresh_db):
    _seed(
        fresh_db,
        credentials=[
            Credential(
                source="aws",
                credential_id="AKIA-1",
                credential_type="aws_access_key",
                owner_source="aws",
                owner_id="arn:1",
                scopes=["AdministratorAccess"],
            ),
            Credential(
                source="github",
                credential_id="deploy_key:test/repo:1",
                credential_type="github_deploy_key",
                scopes=["read", "write"],
            ),
        ],
    )
    r = _client(fresh_db).get("/credentials")
    assert r.status_code == 200
    assert "AKIA-1" in r.text
    assert "deploy_key:test/repo:1" in r.text
    assert "AdministratorAccess" in r.text


def test_credentials_source_filter(fresh_db):
    _seed(
        fresh_db,
        credentials=[
            Credential(
                source="aws", credential_id="AKIA-1", credential_type="aws_access_key"
            ),
            Credential(
                source="github",
                credential_id="deploy_key:r:1",
                credential_type="github_deploy_key",
            ),
        ],
    )
    r = _client(fresh_db).get("/credentials?source=github")
    assert "deploy_key:r:1" in r.text
    assert "AKIA-1" not in r.text


def test_credentials_search_matches_scope(fresh_db):
    _seed(
        fresh_db,
        credentials=[
            Credential(
                source="aws",
                credential_id="AKIA-ADMIN",
                credential_type="aws_access_key",
                scopes=["AdministratorAccess"],
            ),
            Credential(
                source="aws",
                credential_id="AKIA-RO",
                credential_type="aws_access_key",
                scopes=["ReadOnlyAccess"],
            ),
        ],
    )
    r = _client(fresh_db).get("/credentials?q=administrator")
    assert "AKIA-ADMIN" in r.text
    assert "AKIA-RO" not in r.text


def test_credential_detail_renders(fresh_db):
    _seed(
        fresh_db,
        credentials=[
            Credential(
                source="aws",
                credential_id="AKIA-BOB",
                credential_type="aws_access_key",
                owner_source="aws",
                owner_id="arn:aws:iam::123:user/bob",
                scopes=["AdministratorAccess"],
            )
        ],
    )
    r = _client(fresh_db).get("/credentials/aws/AKIA-BOB")
    assert r.status_code == 200
    assert "AKIA-BOB" in r.text
    assert "AdministratorAccess" in r.text


def test_credential_detail_with_path_in_id(fresh_db):
    """Deploy key IDs contain slashes; the :path converter must accept them."""
    _seed(
        fresh_db,
        credentials=[
            Credential(
                source="github",
                credential_id="deploy_key:test-org/main-app:902",
                credential_type="github_deploy_key",
                scopes=["read"],
            )
        ],
    )
    r = _client(fresh_db).get(
        "/credentials/github/deploy_key:test-org/main-app:902"
    )
    assert r.status_code == 200
    assert "deploy_key:test-org/main-app:902" in r.text


def test_credential_detail_404_for_missing(fresh_db):
    r = _client(fresh_db).get("/credentials/aws/nonexistent")
    assert r.status_code == 404


def test_credential_detail_shows_findings(fresh_db):
    _seed(
        fresh_db,
        credentials=[
            Credential(
                source="aws",
                credential_id="AKIA-X",
                credential_type="aws_access_key",
            )
        ],
        findings=[
            Finding(
                rule_id="UNUSED-CREDENTIAL",
                severity=Severity.HIGH,
                title="stale key here",
                description="...",
                evidence={"credential_id": "AKIA-X"},
            )
        ],
    )
    r = _client(fresh_db).get("/credentials/aws/AKIA-X")
    assert "stale key here" in r.text


def test_person_detail_renders(fresh_db):
    _seed(
        fresh_db,
        identities=[
            Identity(
                source="aws",
                source_id="arn:aws:iam::123:user/alice",
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
    r = _client(fresh_db).get("/persons/google/g1")
    assert r.status_code == 200
    assert "alice@example.com" in r.text
    assert "status-suspended" in r.text
    assert "Owned credentials" in r.text


def test_person_detail_404_for_missing(fresh_db):
    r = _client(fresh_db).get("/persons/google/missing")
    assert r.status_code == 404


def test_person_detail_with_slashed_source_id(fresh_db):
    """AWS ARNs contain slashes."""
    _seed(
        fresh_db,
        identities=[
            Identity(
                source="aws",
                source_id="arn:aws:iam::123456789012:user/alice",
                email="alice@example.com",
                name="alice",
                status="active",
            )
        ],
    )
    r = _client(fresh_db).get(
        "/persons/aws/arn:aws:iam::123456789012:user/alice"
    )
    assert r.status_code == 200
    assert "alice@example.com" in r.text


def test_person_detail_lists_owned_credentials_and_findings(fresh_db):
    aws_arn = "arn:aws:iam::123:user/bob"
    _seed(
        fresh_db,
        identities=[
            Identity(
                source="aws",
                source_id=aws_arn,
                email="bob@example.com",
                name="bob",
                status="active",
            ),
            Identity(
                source="google",
                source_id="g-bob",
                email="bob@example.com",
                name="Bob",
                status="suspended",
            ),
        ],
        credentials=[
            Credential(
                source="aws",
                credential_id="AKIA-BOB",
                credential_type="aws_access_key",
                owner_source="aws",
                owner_id=aws_arn,
                scopes=["AdministratorAccess"],
            )
        ],
        findings=[
            Finding(
                rule_id="OFFBOARDED-OWNER",
                severity=Severity.CRITICAL,
                title="offboarded bob fires here",
                description="...",
                evidence={"credential_id": "AKIA-BOB"},
                identity_source="google",
                identity_id="g-bob",
            )
        ],
    )
    r = _client(fresh_db).get("/persons/google/g-bob")
    assert r.status_code == 200
    assert "AKIA-BOB" in r.text
    assert "offboarded bob fires here" in r.text


def test_findings_search_filter(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="A",
                severity=Severity.HIGH,
                title="findme-specifically",
                description="x",
            ),
            Finding(
                rule_id="B",
                severity=Severity.HIGH,
                title="another result",
                description="x",
            ),
        ],
    )
    r = _client(fresh_db).get("/findings?q=findme")
    assert "findme-specifically" in r.text
    assert "another result" not in r.text


def test_hx_request_returns_partial_only(fresh_db):
    """HTMX requests for findings should return just the list partial."""
    _seed(
        fresh_db,
        findings=[
            Finding(rule_id="A", severity=Severity.HIGH, title="hello", description="")
        ],
    )
    r = _client(fresh_db).get(
        "/findings", headers={"HX-Request": "true"}
    )
    assert r.status_code == 200
    # The partial does not include the nav or <html>
    assert "<nav>" not in r.text
    assert "<!doctype html>" not in r.text
    assert "hello" in r.text


def test_identities_hx_partial_only(fresh_db):
    _seed(
        fresh_db,
        identities=[
            Identity(
                source="aws", source_id="arn:1", email="a@example.com",
                name="a", status="active",
            )
        ],
    )
    r = _client(fresh_db).get(
        "/identities", headers={"HX-Request": "true"}
    )
    assert r.status_code == 200
    assert "<nav>" not in r.text
    assert "a@example.com" in r.text


def test_credentials_hx_partial_only(fresh_db):
    _seed(
        fresh_db,
        credentials=[
            Credential(
                source="aws", credential_id="AKIA-1", credential_type="aws_access_key"
            )
        ],
    )
    r = _client(fresh_db).get(
        "/credentials", headers={"HX-Request": "true"}
    )
    assert r.status_code == 200
    assert "<nav>" not in r.text
    assert "AKIA-1" in r.text


def test_nav_includes_credentials_tab(fresh_db):
    r = _client(fresh_db).get("/")
    assert 'href="/credentials"' in r.text


def test_scan_history_page_renders(fresh_db):
    from afterlife.scan_runs import record_run

    with record_run(fresh_db, "aws") as run:
        run["records_collected"] = 7

    r = _client(fresh_db).get("/scan-history")
    assert r.status_code == 200
    assert "Scan history" in r.text
    assert "aws" in r.text
    import re
    assert re.search(r"<td>\s*7\s*</td>", r.text) is not None


def test_overview_shows_last_run_per_source(fresh_db):
    from afterlife.scan_runs import record_run

    with record_run(fresh_db, "aws") as run:
        run["records_collected"] = 12

    r = _client(fresh_db).get("/")
    assert "Last scan per source" in r.text
    assert "aws" in r.text


def test_scan_history_empty_state(fresh_db):
    r = _client(fresh_db).get("/scan-history")
    assert r.status_code == 200
    assert "No scan runs recorded" in r.text


def test_suppressed_findings_hidden_by_default(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="A",
                severity=Severity.HIGH,
                title="visible-finding",
                description="",
            ),
            Finding(
                rule_id="B",
                severity=Severity.HIGH,
                title="hidden-suppressed-finding",
                description="",
                suppressed=True,
                suppression_reason="break-glass",
            ),
        ],
    )
    r = _client(fresh_db).get("/findings")
    assert "visible-finding" in r.text
    assert "hidden-suppressed-finding" not in r.text


def test_show_suppressed_query_param_unhides(fresh_db):
    _seed(
        fresh_db,
        findings=[
            Finding(
                rule_id="B",
                severity=Severity.HIGH,
                title="hidden-suppressed-finding",
                description="",
                suppressed=True,
                suppression_reason="break-glass",
            ),
        ],
    )
    r = _client(fresh_db).get("/findings?show_suppressed=true")
    assert "hidden-suppressed-finding" in r.text
    assert "break-glass" in r.text


def test_app_js_served(fresh_db):
    client = _client(fresh_db)
    r = client.get("/static/app.js")
    assert r.status_code == 200
    assert "navigator.clipboard" in r.text
    assert "keydown" in r.text


def test_keyboard_help_dialog_present(fresh_db):
    r = _client(fresh_db).get("/")
    assert '<dialog id="kbd-help"' in r.text
    assert "Keyboard shortcuts" in r.text
    assert "<kbd>/</kbd>" in r.text


def test_footer_present(fresh_db):
    r = _client(fresh_db).get("/")
    assert '<footer class="site"' in r.text
    assert "No data leaves this machine" in r.text


def test_csp_allows_self_script_and_inline_style(fresh_db):
    """app.js must be loadable under the configured CSP."""
    r = _client(fresh_db).get("/")
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    # We bundle JS at /static/app.js and HTMX at /static/htmx.min.js;
    # both are same-origin so script-src 'self' is sufficient.
    assert 'src="/static/app.js"' in r.text
    assert 'src="/static/htmx.min.js"' in r.text
