"""Finding lifecycle: fingerprinting and cross-run reconciliation.

These test db.reconcile_findings directly (isolated from rule semantics) plus
one integration path through run_analysis, and confirm resolved findings are
kept in history but excluded from the current-findings reports.
"""

from datetime import UTC, datetime, timedelta

from afterlife import db
from afterlife.models import Finding, Severity, finding_fingerprint
from afterlife.rules.registry import run_analysis
from tests.conftest import make_credential, make_identity

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = T0 + timedelta(days=1)
T2 = T0 + timedelta(days=2)


def _f(credential_id, *, rule="OFFBOARDED-OWNER", title="t"):
    return Finding(
        rule_id=rule,
        severity=Severity.CRITICAL,
        title=title,
        description="d",
        evidence={"credential_id": credential_id},
    )


def _reconcile(fresh_db, findings, when):
    with db.connect(fresh_db) as conn:
        return db.reconcile_findings(conn, findings, when)


def _row(fresh_db, needle):
    with db.connect(fresh_db) as conn:
        return conn.execute(
            "SELECT status, first_seen, last_seen, resolved_at "
            "FROM findings WHERE evidence LIKE ?",
            (f"%{needle}%",),
        ).fetchone()


# ---------- fingerprint ----------


def test_fingerprint_stable_despite_mutable_fields():
    a = _f("AKIA-1", title="one")
    b = Finding(
        rule_id="OFFBOARDED-OWNER",
        severity=Severity.HIGH,  # severity changed
        title="a totally different title",
        description="d2",
        evidence={"credential_id": "AKIA-1", "extra": "noise"},
    )
    assert finding_fingerprint(a) == finding_fingerprint(b)


def test_fingerprint_differs_by_rule_and_subject():
    a = _f("C1", rule="R1")
    b = _f("C1", rule="R2")
    c = _f("C2", rule="R1")
    assert len({finding_fingerprint(a), finding_fingerprint(b), finding_fingerprint(c)}) == 3


def test_fingerprint_uses_identity_when_no_credential():
    f = Finding(
        rule_id="ADMIN-WITHOUT-MFA",
        severity=Severity.CRITICAL,
        title="t",
        description="d",
        identity_source="google",
        identity_id="g-1",
    )
    # Deterministic and non-empty.
    assert finding_fingerprint(f) == finding_fingerprint(f)
    assert len(finding_fingerprint(f)) == 16


# ---------- reconcile lifecycle ----------


def test_new_findings_recorded_as_open(fresh_db):
    s = _reconcile(fresh_db, [_f("C1"), _f("C2")], T0)
    assert (s.new, s.ongoing, s.reopened, s.resolved, s.open_total) == (2, 0, 0, 0, 2)
    row = _row(fresh_db, "C1")
    assert row["status"] == "open"
    assert row["first_seen"] == row["last_seen"] == T0.isoformat()
    assert row["resolved_at"] is None


def test_rerun_is_ongoing_and_bumps_last_seen(fresh_db):
    _reconcile(fresh_db, [_f("C1")], T0)
    s = _reconcile(fresh_db, [_f("C1")], T1)
    assert (s.new, s.ongoing, s.resolved, s.open_total) == (0, 1, 0, 1)
    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
    assert n == 1  # not duplicated
    row = _row(fresh_db, "C1")
    assert row["first_seen"] == T0.isoformat()
    assert row["last_seen"] == T1.isoformat()


def test_absent_finding_is_resolved_not_deleted(fresh_db):
    _reconcile(fresh_db, [_f("C1"), _f("C2")], T0)
    s = _reconcile(fresh_db, [_f("C1")], T1)  # C2 disappeared
    assert (s.ongoing, s.resolved, s.open_total) == (1, 1, 1)
    row = _row(fresh_db, "C2")
    assert row["status"] == "resolved"
    assert row["resolved_at"] == T1.isoformat()
    with db.connect(fresh_db) as conn:
        total = conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
    assert total == 2  # C2 kept in history


def test_resolve_all_when_nothing_fires(fresh_db):
    _reconcile(fresh_db, [_f("C1"), _f("C2")], T0)
    s = _reconcile(fresh_db, [], T1)
    assert (s.new, s.ongoing, s.resolved, s.open_total) == (0, 0, 2, 0)


def test_finding_reopens_after_resolution(fresh_db):
    _reconcile(fresh_db, [_f("C1")], T0)
    _reconcile(fresh_db, [], T1)  # resolved
    s = _reconcile(fresh_db, [_f("C1")], T2)  # reappears
    assert (s.new, s.reopened, s.resolved, s.open_total) == (0, 1, 0, 1)
    row = _row(fresh_db, "C1")
    assert row["status"] == "open"
    assert row["resolved_at"] is None
    assert row["first_seen"] == T0.isoformat()  # original first-seen preserved
    assert row["last_seen"] == T2.isoformat()


# ---------- integration + report filtering ----------


def test_run_analysis_reports_new_finding(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity(status="suspended"))
        db.upsert_credential(conn, make_credential())
    findings, delta = run_analysis(fresh_db)
    assert delta.new >= 1
    assert any(f.rule_id == "OFFBOARDED-OWNER" for f in findings)
    with db.connect(fresh_db) as conn:
        n_open = conn.execute(
            "SELECT COUNT(*) AS n FROM findings "
            "WHERE rule_id='OFFBOARDED-OWNER' AND status='open'"
        ).fetchone()["n"]
    assert n_open == 1


def test_resolved_findings_excluded_from_json_report(fresh_db):
    import json

    from afterlife.reporting.json_report import write_json_report

    _reconcile(fresh_db, [_f("C1")], T0)
    _reconcile(fresh_db, [], T1)  # C1 resolved
    report = json.loads(write_json_report(fresh_db))
    assert report["count"] == 0
