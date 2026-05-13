from datetime import timedelta

from afterlife import db
from afterlife.config import Config
from afterlife.graph.identity_graph import IdentityGraph
from afterlife.models import Identity
from afterlife.rules.never_used import never_used
from afterlife.rules.offboarded_owner import offboarded_owner
from afterlife.rules.unrotated_key import unrotated_key
from afterlife.rules.unused_credential import unused_credential
from tests.conftest import make_credential, make_identity


def _graph(conn):
    return IdentityGraph.from_conn(conn)


def test_offboarded_owner_fires_for_deprovisioned_user(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity(status="suspended"))
        db.upsert_credential(conn, make_credential())

    with db.connect(fresh_db) as conn:
        findings = offboarded_owner(conn, Config(), _graph(conn))

    assert len(findings) == 1
    assert findings[0].rule_id == "OFFBOARDED-OWNER"
    assert "suspended" in findings[0].description.lower()


def test_offboarded_owner_quiet_for_active_user(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity(status="active"))
        db.upsert_credential(conn, make_credential())

    with db.connect(fresh_db) as conn:
        findings = offboarded_owner(conn, Config(), _graph(conn))

    assert findings == []


def test_offboarded_owner_handles_case_insensitive_status(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity(status="DEPROVISIONED"))
        db.upsert_credential(conn, make_credential())

    with db.connect(fresh_db) as conn:
        findings = offboarded_owner(conn, Config(), _graph(conn))

    assert len(findings) == 1


def test_offboarded_owner_fires_across_email_link(fresh_db):
    """AWS-owned credential + Okta identity sharing email + Okta status=suspended.

    The graph links the AWS identity to the Okta identity by email; the rule
    walks that link to find the deprovisioned status.
    """
    aws_arn = "arn:aws:iam::123:user/alice"
    with db.connect(fresh_db) as conn:
        # AWS identity (the credential's direct owner) is "active" — by itself
        # the rule wouldn't fire.
        db.upsert_identity(
            conn,
            Identity(
                source="aws",
                source_id=aws_arn,
                email="alice@example.com",
                name="alice",
                status="active",
            ),
        )
        # Okta identity, same email, suspended.
        db.upsert_identity(
            conn,
            Identity(
                source="okta",
                source_id="00uABC",
                email="alice@example.com",
                name="alice",
                status="suspended",
            ),
        )
        db.upsert_credential(
            conn,
            make_credential(
                source="aws",
                credential_id="AKIA-ALICE",
                owner_source="aws",
                owner_id=aws_arn,
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = offboarded_owner(conn, Config(), _graph(conn))

    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["deprovisioned_in"] == "okta"
    assert f.evidence["deprovisioned_status"] == "suspended"
    assert f.evidence["owner_email"] == "alice@example.com"
    linked = {(i["source"], i["status"]) for i in f.evidence["linked_identities"]}
    assert linked == {("aws", "active"), ("okta", "suspended")}


def test_offboarded_owner_quiet_when_no_link_to_deprovisioned(fresh_db):
    """AWS-owned credential, AWS identity active, an unrelated Okta user suspended.

    No email link, so the graph treats them as separate persons — no finding.
    """
    aws_arn = "arn:aws:iam::123:user/alice"
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="aws",
                source_id=aws_arn,
                email="alice@example.com",
                name="alice",
                status="active",
            ),
        )
        db.upsert_identity(
            conn,
            Identity(
                source="okta",
                source_id="00uXYZ",
                email="bob@example.com",
                name="bob",
                status="suspended",
            ),
        )
        db.upsert_credential(
            conn,
            make_credential(
                source="aws",
                credential_id="AKIA-ALICE",
                owner_source="aws",
                owner_id=aws_arn,
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = offboarded_owner(conn, Config(), _graph(conn))

    assert findings == []


def test_unused_credential_fires_past_threshold(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity())
        db.upsert_credential(
            conn,
            make_credential(last_used_at=now - timedelta(days=120)),
        )

    with db.connect(fresh_db) as conn:
        findings = unused_credential(conn, Config(unused_days_threshold=90), _graph(conn))

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
        findings = unused_credential(conn, Config(unused_days_threshold=90), _graph(conn))

    assert findings == []


def test_unused_credential_quiet_when_never_used(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity())
        db.upsert_credential(conn, make_credential(last_used_at=None))

    with db.connect(fresh_db) as conn:
        findings = unused_credential(conn, Config(), _graph(conn))

    assert findings == []


def test_never_used_fires_past_grace_period(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            make_credential(
                credential_id="never-used-1",
                created_at=now - timedelta(days=60),
                last_used_at=None,
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = never_used(conn, Config(never_used_grace_days=30), _graph(conn))

    assert len(findings) == 1
    assert findings[0].rule_id == "NEVER-USED"


def test_never_used_quiet_within_grace_period(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            make_credential(
                credential_id="fresh-1",
                created_at=now - timedelta(days=10),
                last_used_at=None,
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = never_used(conn, Config(never_used_grace_days=30), _graph(conn))

    assert findings == []


def test_never_used_quiet_when_credential_was_used(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            make_credential(
                credential_id="used-1",
                created_at=now - timedelta(days=60),
                last_used_at=now - timedelta(days=5),
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = never_used(conn, Config(never_used_grace_days=30), _graph(conn))

    assert findings == []


def test_never_used_quiet_when_created_at_missing(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            make_credential(
                credential_id="unknown-age",
                created_at=None,
                last_used_at=None,
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = never_used(conn, Config(), _graph(conn))

    assert findings == []


def test_never_used_skips_types_without_usage_signal(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            make_credential(
                source="github",
                credential_type="github_app_installation",
                credential_id="installation:42",
                owner_source=None,
                owner_id=None,
                created_at=now - timedelta(days=400),
                last_used_at=None,
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = never_used(conn, Config(), _graph(conn))

    assert findings == []


def test_unrotated_key_fires_past_threshold(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            make_credential(
                credential_type="aws_access_key",
                credential_id="AKIA-OLD",
                created_at=now - timedelta(days=200),
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = unrotated_key(conn, Config(unrotated_key_days=180), _graph(conn))

    assert len(findings) == 1
    assert findings[0].rule_id == "UNROTATED-KEY"


def test_unrotated_key_quiet_within_threshold(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            make_credential(
                credential_type="aws_access_key",
                credential_id="AKIA-FRESH",
                created_at=now - timedelta(days=30),
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = unrotated_key(conn, Config(unrotated_key_days=180), _graph(conn))

    assert findings == []


def test_unrotated_key_ignores_non_access_keys(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            make_credential(
                credential_type="aws_iam_role",
                credential_id="arn:aws:iam::123:role/Old",
                owner_source=None,
                owner_id=None,
                created_at=now - timedelta(days=400),
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = unrotated_key(conn, Config(unrotated_key_days=180), _graph(conn))

    assert findings == []


def test_unrotated_key_ignores_inactive_keys(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            make_credential(
                credential_type="aws_access_key",
                credential_id="AKIA-DISABLED",
                created_at=now - timedelta(days=500),
                is_active=False,
            ),
        )

    with db.connect(fresh_db) as conn:
        findings = unrotated_key(conn, Config(unrotated_key_days=180), _graph(conn))

    assert findings == []


def test_rule_registry_discovers_all_rules():
    from afterlife.rules.registry import all_rules

    ids = {r.id for r in all_rules()}
    assert ids >= {"OFFBOARDED-OWNER", "UNUSED-CREDENTIAL", "NEVER-USED", "UNROTATED-KEY"}
