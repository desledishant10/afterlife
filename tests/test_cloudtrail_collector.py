"""CloudTrail usage-enrichment collector (botocore-stubbed, no moto)."""

import json
from datetime import UTC, datetime

import boto3
from botocore.stub import Stubber

from afterlife import db
from afterlife.collectors.cloudtrail import CloudTrailCollector, _aggregate
from afterlife.models import Credential


def _event(*, access_key=None, role_arn=None, source="s3.amazonaws.com", when=None):
    when = when or datetime(2026, 8, 1, tzinfo=UTC)
    identity: dict = {}
    if access_key:
        identity["accessKeyId"] = access_key
    if role_arn:
        identity["sessionContext"] = {"sessionIssuer": {"arn": role_arn}}
    ct = {"eventSource": source, "eventTime": when.isoformat(), "userIdentity": identity}
    return {
        "EventId": "e",
        "EventName": "GetObject",
        "EventTime": when,
        "CloudTrailEvent": json.dumps(ct),
    }


def _client(events):
    client = boto3.client(
        "cloudtrail",
        region_name="us-east-1",
        aws_access_key_id="x",
        aws_secret_access_key="y",
    )
    stub = Stubber(client)
    stub.add_response("lookup_events", {"Events": events})
    stub.activate()
    return client


def _seed_cred(fresh_db, credential_id, ctype, **kw):
    with db.connect(fresh_db) as conn:
        db.upsert_credential(
            conn,
            Credential(source="aws", credential_id=credential_id, credential_type=ctype, **kw),
        )


def _meta(fresh_db, credential_id):
    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT last_used_at, metadata FROM credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone()
    return row["last_used_at"], json.loads(row["metadata"]) if row["metadata"] else {}


# ---------- aggregation (pure) ----------


def test_aggregate_keys_and_services():
    events = [
        _event(access_key="AKIA-1", source="s3.amazonaws.com",
               when=datetime(2026, 8, 1, tzinfo=UTC)),
        _event(access_key="AKIA-1", source="ec2.amazonaws.com",
               when=datetime(2026, 8, 20, tzinfo=UTC)),
        _event(role_arn="arn:aws:iam::123:role/App", source="dynamodb.amazonaws.com"),
    ]
    usage = _aggregate(events)
    assert usage["AKIA-1"]["count"] == 2
    assert set(usage["AKIA-1"]["services"]) == {"s3", "ec2"}
    assert usage["AKIA-1"]["last_activity"] == datetime(2026, 8, 20, tzinfo=UTC)
    assert "dynamodb" in usage["arn:aws:iam::123:role/App"]["services"]


# ---------- enrichment ----------


def test_enriches_access_key_usage(fresh_db):
    _seed_cred(fresh_db, "AKIA-1", "aws_access_key")
    client = _client([
        _event(access_key="AKIA-1", source="s3.amazonaws.com",
               when=datetime(2026, 8, 20, tzinfo=UTC))
    ])
    n = CloudTrailCollector(db_path=fresh_db, client=client).run()
    assert n == 1
    last_used, meta = _meta(fresh_db, "AKIA-1")
    assert last_used.startswith("2026-08-20")
    assert meta["observed_services"][0]["service"] == "s3"
    assert meta["cloudtrail_event_count"] == 1


def test_enriches_role_via_session_issuer(fresh_db):
    arn = "arn:aws:iam::123:role/App"
    _seed_cred(fresh_db, arn, "aws_iam_role")
    client = _client([_event(role_arn=arn, source="dynamodb.amazonaws.com")])
    n = CloudTrailCollector(db_path=fresh_db, client=client).run()
    assert n == 1
    _, meta = _meta(fresh_db, arn)
    assert any(s["service"] == "dynamodb" for s in meta["observed_services"])


def test_unknown_principal_is_skipped(fresh_db):
    client = _client([_event(access_key="AKIA-NOT-COLLECTED")])
    assert CloudTrailCollector(db_path=fresh_db, client=client).run() == 0


def test_last_used_is_never_moved_backwards(fresh_db):
    _seed_cred(
        fresh_db, "AKIA-1", "aws_access_key",
        last_used_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    client = _client([_event(access_key="AKIA-1", when=datetime(2026, 8, 10, tzinfo=UTC))])
    CloudTrailCollector(db_path=fresh_db, client=client).run()
    last_used, _ = _meta(fresh_db, "AKIA-1")
    assert last_used.startswith("2026-08-25")  # kept the newer stored value


def test_empty_event_history(fresh_db):
    _seed_cred(fresh_db, "AKIA-1", "aws_access_key")
    client = _client([])
    assert CloudTrailCollector(db_path=fresh_db, client=client).run() == 0
