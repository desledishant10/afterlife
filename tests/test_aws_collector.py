import json

import boto3
import pytest
from moto import mock_aws

from afterlife import db
from afterlife.collectors.aws import AWSCollector

TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


@pytest.fixture
def aws_env(monkeypatch):
    """Mocked AWS environment via moto with credentials forced into env vars.

    Without the env vars, boto3 walks the credential provider chain and may hit
    the real shared credentials file, which moto cannot intercept.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


def _run_collector(session, fresh_db):
    collector = AWSCollector(
        db_path=fresh_db, profile="default", region="us-east-1", session=session
    )
    return collector.run()


def test_collects_user_with_email_tag(aws_env, fresh_db):
    iam = aws_env.client("iam")
    iam.create_user(
        UserName="alice", Tags=[{"Key": "email", "Value": "alice@example.com"}]
    )
    iam.create_access_key(UserName="alice")

    _run_collector(aws_env, fresh_db)

    with db.connect(fresh_db) as conn:
        identity = conn.execute(
            "SELECT * FROM identities WHERE source = 'aws' AND name = 'alice'"
        ).fetchone()
        assert identity is not None
        assert identity["email"] == "alice@example.com"
        assert identity["status"] == "active"
        assert identity["source_id"].endswith(":user/alice")

        keys = conn.execute(
            "SELECT * FROM credentials WHERE credential_type = 'aws_access_key'"
        ).fetchall()
        assert len(keys) == 1
        assert keys[0]["owner_id"] == identity["source_id"]
        assert keys[0]["is_active"] == 1


def test_collects_user_without_email_tag(aws_env, fresh_db):
    iam = aws_env.client("iam")
    iam.create_user(UserName="bob")
    iam.create_access_key(UserName="bob")

    _run_collector(aws_env, fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT email FROM identities WHERE name = 'bob'"
        ).fetchone()
        assert row["email"] is None


def test_finds_email_in_alternate_tag_keys(aws_env, fresh_db):
    iam = aws_env.client("iam")
    iam.create_user(
        UserName="carol", Tags=[{"Key": "Owner", "Value": "carol@example.com"}]
    )

    _run_collector(aws_env, fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT email FROM identities WHERE name = 'carol'"
        ).fetchone()
        assert row["email"] == "carol@example.com"


def test_ignores_non_email_owner_tag(aws_env, fresh_db):
    iam = aws_env.client("iam")
    iam.create_user(
        UserName="dave", Tags=[{"Key": "Owner", "Value": "platform-team"}]
    )

    _run_collector(aws_env, fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT email FROM identities WHERE name = 'dave'"
        ).fetchone()
        assert row["email"] is None


def test_inactive_key_marked_inactive(aws_env, fresh_db):
    iam = aws_env.client("iam")
    iam.create_user(UserName="eve")
    created = iam.create_access_key(UserName="eve")
    key_id = created["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName="eve", AccessKeyId=key_id, Status="Inactive")

    _run_collector(aws_env, fresh_db)

    with db.connect(fresh_db) as conn:
        cred = conn.execute(
            "SELECT * FROM credentials WHERE credential_id = ?", (key_id,)
        ).fetchone()
        assert cred is not None
        assert cred["is_active"] == 0


def test_collects_roles_as_ownerless_credentials(aws_env, fresh_db):
    iam = aws_env.client("iam")
    iam.create_role(RoleName="DeployRole", AssumeRolePolicyDocument=TRUST_POLICY)

    _run_collector(aws_env, fresh_db)

    with db.connect(fresh_db) as conn:
        roles = conn.execute(
            "SELECT * FROM credentials WHERE credential_type = 'aws_iam_role'"
        ).fetchall()
        assert len(roles) == 1
        assert roles[0]["owner_id"] is None
        assert roles[0]["owner_source"] is None
        assert roles[0]["credential_id"].endswith(":role/DeployRole")


def test_handles_multiple_users_and_keys(aws_env, fresh_db):
    iam = aws_env.client("iam")
    for name in ("alice", "bob", "carol"):
        iam.create_user(UserName=name)
        iam.create_access_key(UserName=name)
        iam.create_access_key(UserName=name)  # 2nd key

    count = _run_collector(aws_env, fresh_db)
    assert count == 3 + 6  # 3 identities + 6 keys

    with db.connect(fresh_db) as conn:
        assert conn.execute(
            "SELECT COUNT(*) AS n FROM identities WHERE source = 'aws'"
        ).fetchone()["n"] == 3
        assert conn.execute(
            "SELECT COUNT(*) AS n FROM credentials WHERE credential_type = 'aws_access_key'"
        ).fetchone()["n"] == 6


def test_rerun_is_idempotent(aws_env, fresh_db):
    iam = aws_env.client("iam")
    iam.create_user(UserName="alice")
    iam.create_access_key(UserName="alice")

    _run_collector(aws_env, fresh_db)
    _run_collector(aws_env, fresh_db)

    with db.connect(fresh_db) as conn:
        assert conn.execute(
            "SELECT COUNT(*) AS n FROM identities"
        ).fetchone()["n"] == 1
        assert conn.execute(
            "SELECT COUNT(*) AS n FROM credentials"
        ).fetchone()["n"] == 1


def test_user_metadata_preserves_tags(aws_env, fresh_db):
    iam = aws_env.client("iam")
    iam.create_user(
        UserName="alice",
        Tags=[
            {"Key": "email", "Value": "alice@example.com"},
            {"Key": "team", "Value": "platform"},
        ],
    )

    _run_collector(aws_env, fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT metadata FROM identities WHERE name = 'alice'"
        ).fetchone()
        meta = json.loads(row["metadata"])
        assert meta["tags"]["team"] == "platform"
        assert meta["tags"]["email"] == "alice@example.com"
