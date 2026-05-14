import json

import httpx
import pytest
import respx

from afterlife import db
from afterlife.collectors.gcp_iam import GCPIAMCollector

PROJECT = "demo-project"


def _sa(email, *, disabled=False, display=None, project=PROJECT):
    return {
        "name": f"projects/{project}/serviceAccounts/{email}",
        "projectId": project,
        "uniqueId": str(abs(hash(email))),
        "email": email,
        "displayName": display or email.split("@")[0],
        "disabled": disabled,
    }


def _key(sa_email, key_id, *, valid_after="2024-01-15T09:00:00Z", key_type="USER_MANAGED"):
    return {
        "name": f"projects/{PROJECT}/serviceAccounts/{sa_email}/keys/{key_id}",
        "validAfterTime": valid_after,
        "validBeforeTime": "2099-01-01T00:00:00Z",
        "keyAlgorithm": "KEY_ALG_RSA_2048",
        "keyType": key_type,
        "keyOrigin": "GOOGLE_PROVIDED",
    }


def _sa_route():
    return respx.route(
        method="GET",
        host="iam.googleapis.com",
        path=f"/v1/projects/{PROJECT}/serviceAccounts",
    )


def _keys_route(sa_email):
    return respx.route(
        method="GET",
        host="iam.googleapis.com",
        path=f"/v1/projects/{PROJECT}/serviceAccounts/{sa_email}/keys",
    )


def _run(fresh_db):
    return GCPIAMCollector(
        db_path=fresh_db, project=PROJECT, access_token="fake-token"
    ).run()


@respx.mock
def test_collects_active_service_account(fresh_db):
    sa = _sa("ci-deploy@demo-project.iam.gserviceaccount.com")
    _sa_route().mock(return_value=httpx.Response(200, json={"accounts": [sa]}))
    _keys_route(sa["email"]).mock(return_value=httpx.Response(200, json={"keys": []}))

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT * FROM identities WHERE source = 'gcp'"
        ).fetchone()
        assert row is not None
        assert row["status"] == "active"
        assert row["email"] == sa["email"]
        assert row["source_id"] == sa["email"]


@respx.mock
def test_disabled_service_account_maps_to_suspended(fresh_db):
    sa = _sa("disabled@demo-project.iam.gserviceaccount.com", disabled=True)
    _sa_route().mock(return_value=httpx.Response(200, json={"accounts": [sa]}))
    _keys_route(sa["email"]).mock(return_value=httpx.Response(200, json={"keys": []}))
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        assert conn.execute(
            "SELECT status FROM identities"
        ).fetchone()["status"] == "suspended"


@respx.mock
def test_collects_service_account_keys(fresh_db):
    sa = _sa("ci@demo-project.iam.gserviceaccount.com")
    _sa_route().mock(return_value=httpx.Response(200, json={"accounts": [sa]}))
    _keys_route(sa["email"]).mock(
        return_value=httpx.Response(
            200,
            json={
                "keys": [
                    _key(sa["email"], "key-old", valid_after="2024-01-15T09:00:00Z"),
                    _key(sa["email"], "key-new", valid_after="2026-05-01T09:00:00Z"),
                ]
            },
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT * FROM credentials WHERE credential_type = 'gcp_service_account_key' ORDER BY credential_id"
        ).fetchall()
        assert len(rows) == 2
        assert all(r["owner_source"] == "gcp" and r["owner_id"] == sa["email"] for r in rows)
        cred_ids = {r["credential_id"] for r in rows}
        assert f"sa_key:{sa['email']}:key-old" in cred_ids


@respx.mock
def test_paginates_via_next_page_token(fresh_db):
    sa1 = _sa("a@demo-project.iam.gserviceaccount.com")
    sa2 = _sa("b@demo-project.iam.gserviceaccount.com")
    route = _sa_route()
    route.side_effect = [
        httpx.Response(
            200,
            json={"accounts": [sa1], "nextPageToken": "abc"},
        ),
        httpx.Response(200, json={"accounts": [sa2]}),
    ]
    _keys_route(sa1["email"]).mock(return_value=httpx.Response(200, json={"keys": []}))
    _keys_route(sa2["email"]).mock(return_value=httpx.Response(200, json={"keys": []}))

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 2


@respx.mock
def test_keys_403_is_non_fatal(fresh_db):
    """Some SAs (system ones) deny key listing even to legit collectors."""
    sa = _sa("locked@demo-project.iam.gserviceaccount.com")
    _sa_route().mock(return_value=httpx.Response(200, json={"accounts": [sa]}))
    _keys_route(sa["email"]).mock(
        return_value=httpx.Response(403, json={"error": {"message": "Forbidden"}})
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        # SA identity still recorded; just no keys.
        assert conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"] == 1
        assert conn.execute(
            "SELECT COUNT(*) AS n FROM credentials"
        ).fetchone()["n"] == 0


@respx.mock
def test_rerun_is_idempotent(fresh_db):
    sa = _sa("ci@demo-project.iam.gserviceaccount.com")
    _sa_route().mock(return_value=httpx.Response(200, json={"accounts": [sa]}))
    _keys_route(sa["email"]).mock(
        return_value=httpx.Response(
            200, json={"keys": [_key(sa["email"], "k1")]}
        )
    )

    _run(fresh_db)
    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM credentials").fetchone()["n"] == 1


@respx.mock
def test_unauthorized_raises(fresh_db):
    _sa_route().mock(
        return_value=httpx.Response(
            401, json={"error": {"message": "Request had invalid authentication"}}
        )
    )
    with pytest.raises(httpx.HTTPStatusError):
        _run(fresh_db)


@respx.mock
def test_full_jwt_flow_exchanges_at_oauth_endpoint(fresh_db, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    sa_file = tmp_path / "sa.json"
    sa_file.write_text(
        json.dumps(
            {
                "client_email": "sa@project.iam.gserviceaccount.com",
                "private_key": pem,
            }
        )
    )

    respx.route(
        method="POST", host="oauth2.googleapis.com", path="/token"
    ).mock(return_value=httpx.Response(200, json={"access_token": "iam-token"}))
    _sa_route().mock(return_value=httpx.Response(200, json={"accounts": []}))

    GCPIAMCollector(
        db_path=fresh_db,
        project=PROJECT,
        service_account_file=sa_file,
    ).run()

    last = respx.calls[-1].request
    assert last.url.path == f"/v1/projects/{PROJECT}/serviceAccounts"
    assert last.headers["authorization"] == "Bearer iam-token"


def test_constructor_requires_project(fresh_db):
    with pytest.raises(ValueError, match="project"):
        GCPIAMCollector(db_path=fresh_db, project="")
