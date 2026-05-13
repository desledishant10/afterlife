from datetime import timedelta

from afterlife import db
from afterlife.config import Config
from afterlife.rules.offboarded_owner import offboarded_owner
from afterlife.rules.unused_credential import unused_credential
from tests.conftest import make_credential, make_identity


def test_offboarded_owner_fires_for_deprovisioned_user(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity(status="suspended"))
        db.upsert_credential(conn, make_credential())

    with db.connect(fresh_db) as conn:
        findings = offboarded_owner(conn, Config())

    assert len(findings) == 1
    assert findings[0].rule_id == "OFFBOARDED-OWNER"
    assert "suspended" in findings[0].description.lower()


def test_offboarded_owner_quiet_for_active_user(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity(status="active"))
        db.upsert_credential(conn, make_credential())

    with db.connect(fresh_db) as conn:
        findings = offboarded_owner(conn, Config())

    assert findings == []


def test_offboarded_owner_handles_case_insensitive_status(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity(status="DEPROVISIONED"))
        db.upsert_credential(conn, make_credential())

    with db.connect(fresh_db) as conn:
        findings = offboarded_owner(conn, Config())

    assert len(findings) == 1


def test_unused_credential_fires_past_threshold(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity())
        db.upsert_credential(
            conn,
            make_credential(last_used_at=now - timedelta(days=120)),
        )

    with db.connect(fresh_db) as conn:
        findings = unused_credential(conn, Config(unused_days_threshold=90))

    assert len(findings) == 1
    assert findings[0].rule_id == "UNUSED-CREDENTIAL"


def test_unused_credential_quiet_within_threshold(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity())
        db.upsert_credential(
            conn,
            make_credential(last_used_at=now - timedelta(days=30)),
        )

    with db.connect(fresh_db) as conn:
        findings = unused_credential(conn, Config(unused_days_threshold=90))

    assert findings == []


def test_unused_credential_quiet_when_never_used(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity())
        db.upsert_credential(conn, make_credential(last_used_at=None))

    with db.connect(fresh_db) as conn:
        findings = unused_credential(conn, Config())

    assert findings == []


def test_rule_registry_discovers_both_rules():
    from afterlife.rules.registry import all_rules

    ids = {r.id for r in all_rules()}
    assert "OFFBOARDED-OWNER" in ids
    assert "UNUSED-CREDENTIAL" in ids
