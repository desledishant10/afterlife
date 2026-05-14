from datetime import timedelta

from afterlife import db
from afterlife.config import Config
from afterlife.graph.identity_graph import IdentityGraph
from afterlife.models import Credential, Identity
from afterlife.rules.admin_concentration import admin_concentration
from afterlife.rules.admin_without_mfa import admin_without_mfa
from afterlife.rules.cross_account_trust import cross_account_trust
from afterlife.rules.inactive_admin import inactive_admin
from afterlife.rules.never_used import never_used
from afterlife.rules.offboarded_owner import offboarded_owner
from afterlife.rules.orphaned_identity import orphaned_identity
from afterlife.rules.outside_collab_with_aws import outside_collab_with_aws
from afterlife.rules.stale_deploy_key_write import stale_deploy_key_write
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
        # AWS identity (the credential's direct owner) is "active"; by itself
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

    No email link, so the graph treats them as separate persons; no finding.
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


# ---------- STALE-DEPLOY-KEY-WRITE ----------


def test_stale_deploy_key_write_fires_on_write_capable_stale_github_key(
    fresh_db, now
):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            Credential(
                source="github",
                credential_id="deploy_key:test/app:1",
                credential_type="github_deploy_key",
                scopes=["read", "write"],
                last_used_at=now - timedelta(days=120),
                metadata={"repo": "test/app", "title": "ci-deploy"},
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = stale_deploy_key_write(
            conn, Config(unused_days_threshold=90), _graph(conn)
        )
    assert len(findings) == 1
    assert findings[0].evidence["credential_id"] == "deploy_key:test/app:1"


def test_stale_deploy_key_write_quiet_for_read_only_key(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            Credential(
                source="github",
                credential_id="deploy_key:test/app:2",
                credential_type="github_deploy_key",
                scopes=["read"],
                last_used_at=now - timedelta(days=200),
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = stale_deploy_key_write(conn, Config(), _graph(conn))
    assert findings == []


def test_stale_deploy_key_write_quiet_when_recent(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            Credential(
                source="github",
                credential_id="deploy_key:test/app:3",
                credential_type="github_deploy_key",
                scopes=["read", "write"],
                last_used_at=now - timedelta(days=10),
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = stale_deploy_key_write(
            conn, Config(unused_days_threshold=90), _graph(conn)
        )
    assert findings == []


def test_stale_deploy_key_write_handles_gitlab_push_scope(fresh_db, now):
    """GitLab encodes write access as scope `push` rather than `write`."""
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            Credential(
                source="gitlab",
                credential_id="deploy_key:demo/app:4",
                credential_type="gitlab_deploy_key",
                scopes=["push"],
                last_used_at=now - timedelta(days=150),
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = stale_deploy_key_write(conn, Config(), _graph(conn))
    assert len(findings) == 1


def test_stale_deploy_key_write_quiet_for_non_deploy_credential_types(
    fresh_db, now
):
    """An aws_access_key is handled by UNUSED-CREDENTIAL; not our scope."""
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            Credential(
                source="aws",
                credential_id="AKIA-X",
                credential_type="aws_access_key",
                scopes=["AdministratorAccess"],
                last_used_at=now - timedelta(days=200),
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = stale_deploy_key_write(conn, Config(), _graph(conn))
    assert findings == []


# ---------- ADMIN-CONCENTRATION ----------


def test_admin_concentration_fires_for_idp_admin_with_aws_admin_policy(fresh_db):
    aws_arn = "arn:aws:iam::123:user/dave"
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-dave",
                email="dave@example.com",
                name="Dave",
                status="active",
                metadata={"is_admin": True},
            ),
        )
        db.upsert_identity(
            conn,
            Identity(
                source="aws",
                source_id=aws_arn,
                email="dave@example.com",
                name="Dave",
                status="active",
            ),
        )
        db.upsert_credential(
            conn,
            Credential(
                source="aws",
                credential_id="AKIA-DAVE",
                credential_type="aws_access_key",
                owner_source="aws",
                owner_id=aws_arn,
                scopes=["AdministratorAccess"],
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = admin_concentration(conn, Config(), _graph(conn))
    assert len(findings) == 1
    assert set(findings[0].evidence["admin_sources"]) == {"google", "aws"}


def test_admin_concentration_quiet_for_single_source_admin(fresh_db):
    """Admin only in Google, no AWS admin policies = ADMIN-WITHOUT-MFA's job, not this one."""
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-solo",
                email="solo@example.com",
                name="Solo",
                status="active",
                metadata={"is_admin": True},
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = admin_concentration(conn, Config(), _graph(conn))
    assert findings == []


def test_admin_concentration_quiet_for_readonly_aws_link(fresh_db):
    aws_arn = "arn:aws:iam::123:user/alice"
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-alice",
                email="alice@example.com",
                name="Alice",
                status="active",
                metadata={"is_admin": True},
            ),
        )
        db.upsert_identity(
            conn,
            Identity(
                source="aws",
                source_id=aws_arn,
                email="alice@example.com",
                name="Alice",
                status="active",
            ),
        )
        db.upsert_credential(
            conn,
            Credential(
                source="aws",
                credential_id="AKIA-ALICE",
                credential_type="aws_access_key",
                owner_source="aws",
                owner_id=aws_arn,
                scopes=["ReadOnlyAccess"],
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = admin_concentration(conn, Config(), _graph(conn))
    assert findings == []


def test_admin_concentration_fires_for_two_idp_admins(fresh_db):
    """Same person is admin in both Google and Okta-style IdPs."""
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-1",
                email="x@example.com",
                name="X",
                status="active",
                metadata={"is_admin": True},
            ),
        )
        db.upsert_identity(
            conn,
            Identity(
                source="okta",
                source_id="o-1",
                email="x@example.com",
                name="X",
                status="active",
                metadata={"is_admin": True},
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = admin_concentration(conn, Config(), _graph(conn))
    assert len(findings) == 1
    assert set(findings[0].evidence["admin_sources"]) == {"google", "okta"}


# ---------- CROSS-ACCOUNT-TRUST ----------


def _role_credential(role_name, trust_policy, own_account="123456789012"):
    return Credential(
        source="aws",
        credential_id=f"arn:aws:iam::{own_account}:role/{role_name}",
        credential_type="aws_iam_role",
        owner_source=None,
        owner_id=None,
        metadata={
            "role_name": role_name,
            "account_id": own_account,
            "assume_role_policy_document": trust_policy,
        },
    )


def test_cross_account_trust_fires_for_external_principal(fresh_db):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    with db.connect(fresh_db) as conn:
        db.upsert_credential(conn, _role_credential("ExternalAuditorRole", trust))

    with db.connect(fresh_db) as conn:
        findings = cross_account_trust(conn, Config(), _graph(conn))

    assert len(findings) == 1
    assert "999999999999" in findings[0].title
    assert findings[0].evidence["external_principals"][0]["account_id"] == "999999999999"


def test_cross_account_trust_quiet_for_same_account(fresh_db):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    with db.connect(fresh_db) as conn:
        db.upsert_credential(conn, _role_credential("OwnRole", trust))

    with db.connect(fresh_db) as conn:
        findings = cross_account_trust(conn, Config(), _graph(conn))

    assert findings == []


def test_cross_account_trust_quiet_for_service_principal(fresh_db):
    """ec2.amazonaws.com is a service principal, not a foreign account."""
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    with db.connect(fresh_db) as conn:
        db.upsert_credential(conn, _role_credential("EC2Role", trust))

    with db.connect(fresh_db) as conn:
        findings = cross_account_trust(conn, Config(), _graph(conn))

    assert findings == []


def test_cross_account_trust_handles_principal_list(fresh_db):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": [
                "arn:aws:iam::123456789012:root",
                "arn:aws:iam::888888888888:root",
                "arn:aws:iam::999999999999:root",
            ]},
            "Action": "sts:AssumeRole",
        }],
    }
    with db.connect(fresh_db) as conn:
        db.upsert_credential(conn, _role_credential("MixedRole", trust))

    with db.connect(fresh_db) as conn:
        findings = cross_account_trust(conn, Config(), _graph(conn))

    assert len(findings) == 1
    accts = {e["account_id"] for e in findings[0].evidence["external_principals"]}
    assert accts == {"888888888888", "999999999999"}


def test_cross_account_trust_handles_assume_role_with_web_identity(fresh_db):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
            "Action": "sts:AssumeRoleWithWebIdentity",
        }],
    }
    with db.connect(fresh_db) as conn:
        db.upsert_credential(conn, _role_credential("FederatedRole", trust))

    with db.connect(fresh_db) as conn:
        findings = cross_account_trust(conn, Config(), _graph(conn))

    assert len(findings) == 1


def test_cross_account_trust_quiet_when_no_policy(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            Credential(
                source="aws",
                credential_id="arn:aws:iam::123:role/NoPolicy",
                credential_type="aws_iam_role",
                metadata={"role_name": "NoPolicy", "account_id": "123"},
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = cross_account_trust(conn, Config(), _graph(conn))
    assert findings == []


def test_run_all_replaces_prior_findings(fresh_db):
    """`analyze` is a snapshot, not an append-log: re-running must not
    duplicate findings in the database."""
    from afterlife.rules.registry import run_all

    with db.connect(fresh_db) as conn:
        db.upsert_identity(conn, make_identity(status="suspended"))
        db.upsert_credential(conn, make_credential())

    run_all(fresh_db)
    run_all(fresh_db)
    run_all(fresh_db)

    with db.connect(fresh_db) as conn:
        # The OFFBOARDED-OWNER rule should fire exactly once for the one
        # credential present, regardless of how many times analyze was called.
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM findings WHERE rule_id = 'OFFBOARDED-OWNER'"
        ).fetchone()["n"]
        assert n == 1


def test_rule_registry_discovers_all_rules():
    from afterlife.rules.registry import all_rules

    ids = {r.id for r in all_rules()}
    assert ids >= {
        "OFFBOARDED-OWNER",
        "UNUSED-CREDENTIAL",
        "NEVER-USED",
        "UNROTATED-KEY",
        "ORPHANED-IDENTITY",
        "OUTSIDE-COLLAB-WITH-AWS",
        "ADMIN-WITHOUT-MFA",
        "INACTIVE-ADMIN",
        "CROSS-ACCOUNT-TRUST",
        "ADMIN-CONCENTRATION",
        "STALE-DEPLOY-KEY-WRITE",
    }


# ---------- ORPHANED-IDENTITY ----------


def test_orphaned_identity_fires_for_google_only_user(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g1",
                email="nina@example.com",
                name="Nina",
                status="active",
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = orphaned_identity(conn, Config(), _graph(conn))
    assert len(findings) == 1
    assert findings[0].rule_id == "ORPHANED-IDENTITY"
    assert findings[0].identity_source == "google"


def test_orphaned_identity_quiet_when_downstream_present(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g1",
                email="alice@example.com",
                name="Alice",
                status="active",
            ),
        )
        db.upsert_identity(
            conn,
            Identity(
                source="aws",
                source_id="arn:1",
                email="alice@example.com",
                name="Alice",
                status="active",
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = orphaned_identity(conn, Config(), _graph(conn))
    assert findings == []


def test_orphaned_identity_quiet_when_already_deprovisioned(fresh_db):
    """A suspended IdP user is handled by OFFBOARDED-OWNER (when they have creds);
    ORPHANED-IDENTITY should not pile on with redundant noise."""
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g1",
                email="ex@example.com",
                name="Ex",
                status="suspended",
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = orphaned_identity(conn, Config(), _graph(conn))
    assert findings == []


# ---------- OUTSIDE-COLLAB-WITH-AWS ----------


def test_outside_collab_with_aws_fires_when_outside_member_has_aws_cred(fresh_db):
    aws_arn = "arn:aws:iam::123:user/jane"
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="github",
                source_id="contractor-jane",
                email="jane@vendor.com",
                name="Jane",
                status="active",
                metadata={"is_outside_collaborator": True},
            ),
        )
        db.upsert_identity(
            conn,
            Identity(
                source="aws",
                source_id=aws_arn,
                email="jane@vendor.com",
                name="jane",
                status="active",
            ),
        )
        db.upsert_credential(
            conn,
            Credential(
                source="aws",
                credential_id="AKIA-JANE",
                credential_type="aws_access_key",
                owner_source="aws",
                owner_id=aws_arn,
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = outside_collab_with_aws(conn, Config(), _graph(conn))
    assert len(findings) == 1
    assert findings[0].evidence["credential_id"] == "AKIA-JANE"


def test_outside_collab_quiet_when_user_is_full_member(fresh_db):
    aws_arn = "arn:aws:iam::123:user/alice"
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="github",
                source_id="alice",
                email="alice@example.com",
                name="Alice",
                status="active",
                metadata={"is_outside_collaborator": False},
            ),
        )
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
    with db.connect(fresh_db) as conn:
        findings = outside_collab_with_aws(conn, Config(), _graph(conn))
    assert findings == []


def test_outside_collab_quiet_when_no_aws_link(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="github",
                source_id="contractor-jane",
                email="jane@vendor.com",
                name="Jane",
                status="active",
                metadata={"is_outside_collaborator": True},
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = outside_collab_with_aws(conn, Config(), _graph(conn))
    assert findings == []


# ---------- ADMIN-WITHOUT-MFA ----------


def test_admin_without_mfa_fires_when_admin_2sv_not_enforced(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-admin",
                email="admin@example.com",
                name="Admin",
                status="active",
                metadata={"is_admin": True, "is_enforced_in_2sv": False},
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = admin_without_mfa(conn, Config(), _graph(conn))
    assert len(findings) == 1
    assert findings[0].evidence["admin_id"] == "g-admin"


def test_admin_without_mfa_quiet_when_2sv_enforced(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-safe",
                email="safe@example.com",
                name="Safe",
                status="active",
                metadata={"is_admin": True, "is_enforced_in_2sv": True},
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = admin_without_mfa(conn, Config(), _graph(conn))
    assert findings == []


def test_admin_without_mfa_quiet_for_non_admin(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-norm",
                email="norm@example.com",
                name="Norm",
                status="active",
                metadata={"is_admin": False, "is_enforced_in_2sv": False},
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = admin_without_mfa(conn, Config(), _graph(conn))
    assert findings == []


def test_admin_without_mfa_quiet_when_2sv_signal_unknown_and_enrolled(fresh_db):
    """If enforcement is None but the user IS enrolled, treat as protected
    (avoids noise on Workspaces that haven't enabled enforcement at the org
    level but have voluntary enrollment)."""
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-enrolled",
                email="enrolled@example.com",
                name="Enrolled",
                status="active",
                metadata={
                    "is_admin": True,
                    "is_enforced_in_2sv": None,
                    "is_enrolled_in_2sv": True,
                },
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = admin_without_mfa(conn, Config(), _graph(conn))
    assert findings == []


# ---------- INACTIVE-ADMIN ----------


def test_inactive_admin_fires_for_stale_login(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-old",
                email="old-admin@example.com",
                name="Old Admin",
                status="active",
                metadata={
                    "is_admin": True,
                    "last_login_time": (now - timedelta(days=120)).isoformat(),
                },
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = inactive_admin(conn, Config(inactive_admin_days=30), _graph(conn))
    assert len(findings) == 1
    assert findings[0].rule_id == "INACTIVE-ADMIN"
    assert findings[0].evidence["days_since_last_login"] >= 119


def test_inactive_admin_quiet_when_recent_login(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-active",
                email="active@example.com",
                name="Active",
                status="active",
                metadata={
                    "is_admin": True,
                    "last_login_time": (now - timedelta(days=5)).isoformat(),
                },
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = inactive_admin(conn, Config(inactive_admin_days=30), _graph(conn))
    assert findings == []


def test_inactive_admin_quiet_for_non_admin(fresh_db, now):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-user",
                email="user@example.com",
                name="User",
                status="active",
                metadata={
                    "is_admin": False,
                    "last_login_time": (now - timedelta(days=300)).isoformat(),
                },
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = inactive_admin(conn, Config(inactive_admin_days=30), _graph(conn))
    assert findings == []


def test_inactive_admin_quiet_when_no_login_data(fresh_db):
    """A user who never logged in is handled elsewhere; this rule needs a
    real timestamp to compute a 'days inactive' value."""
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-new",
                email="new@example.com",
                name="New",
                status="active",
                metadata={"is_admin": True, "last_login_time": None},
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = inactive_admin(conn, Config(), _graph(conn))
    assert findings == []


def test_admin_without_mfa_fires_when_both_signals_negative(fresh_db):
    with db.connect(fresh_db) as conn:
        db.upsert_identity(
            conn,
            Identity(
                source="google",
                source_id="g-no2fa",
                email="no2fa@example.com",
                name="No2FA",
                status="active",
                metadata={
                    "is_admin": True,
                    "is_enforced_in_2sv": None,
                    "is_enrolled_in_2sv": False,
                },
            ),
        )
    with db.connect(fresh_db) as conn:
        findings = admin_without_mfa(conn, Config(), _graph(conn))
    assert len(findings) == 1
