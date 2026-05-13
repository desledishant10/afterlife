import json

import httpx
import pytest
import respx

from afterlife import db
from afterlife.collectors.google_workspace import GoogleWorkspaceCollector


def _user(uid: str, email: str, *, suspended: bool = False, archived: bool = False,
          name: str | None = None,
          last_login: str = "2026-05-01T10:00:00.000Z") -> dict:
    return {
        "id": uid,
        "primaryEmail": email,
        "name": {"fullName": name or email.split("@")[0]},
        "suspended": suspended,
        "archived": archived,
        "lastLoginTime": last_login,
        "creationTime": "2024-01-15T09:00:00.000Z",
    }


def _users_route():
    return respx.route(
        method="GET",
        host="admin.googleapis.com",
        path="/admin/directory/v1/users",
    )


def _run(fresh_db):
    return GoogleWorkspaceCollector(
        db_path=fresh_db, access_token="fake-token"
    ).run()


@respx.mock
def test_collects_active_user(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200, json={"users": [_user("1", "alice@example.com")]}
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT * FROM identities WHERE source = 'google'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["email"] == "alice@example.com"
        assert rows[0]["status"] == "active"
        assert rows[0]["source_id"] == "1"


@respx.mock
def test_suspended_user_maps_to_suspended_status(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200,
            json={"users": [_user("2", "bob@example.com", suspended=True)]},
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT status FROM identities").fetchone()
        assert row["status"] == "suspended"


@respx.mock
def test_archived_user_maps_to_archived_status(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200,
            json={"users": [_user("3", "carol@example.com", archived=True)]},
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT status FROM identities").fetchone()
        assert row["status"] == "archived"


@respx.mock
def test_paginates_via_next_page_token(fresh_db):
    route = _users_route()
    route.side_effect = [
        httpx.Response(
            200,
            json={
                "users": [_user("1", "alice@example.com")],
                "nextPageToken": "page2",
            },
        ),
        httpx.Response(200, json={"users": [_user("2", "bob@example.com")]}),
    ]

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT source_id FROM identities ORDER BY source_id"
        ).fetchall()
        assert [r["source_id"] for r in rows] == ["1", "2"]


@respx.mock
def test_idempotent_rerun(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200, json={"users": [_user("1", "alice@example.com")]}
        )
    )

    _run(fresh_db)
    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 1


@respx.mock
def test_empty_domain(fresh_db):
    _users_route().mock(return_value=httpx.Response(200, json={"users": []}))

    count = _run(fresh_db)
    assert count == 0


@respx.mock
def test_unauthorized_raises(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(401, json={"error": {"message": "Unauthorized"}})
    )

    with pytest.raises(httpx.HTTPStatusError):
        _run(fresh_db)


@respx.mock
def test_never_logged_in_sentinel_normalized_to_none(fresh_db):
    _users_route().mock(
        return_value=httpx.Response(
            200,
            json={
                "users": [
                    _user(
                        "1",
                        "newbie@example.com",
                        last_login="1970-01-01T00:00:00.000Z",
                    )
                ]
            },
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT metadata FROM identities").fetchone()
        meta = json.loads(row["metadata"])
        assert meta["last_login_time"] is None


@respx.mock
def test_jwt_auth_flow_signs_and_exchanges(fresh_db, tmp_path):
    """Full auth path: sign a JWT, exchange at token endpoint, then use access token."""
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
    ).mock(return_value=httpx.Response(200, json={"access_token": "issued-token"}))
    _users_route().mock(return_value=httpx.Response(200, json={"users": []}))

    GoogleWorkspaceCollector(
        db_path=fresh_db,
        service_account_file=sa_file,
        admin_email="admin@example.com",
    ).run()

    # Verify the Directory API was called with the issued token.
    last = respx.calls[-1].request
    assert last.url.path == "/admin/directory/v1/users"
    assert last.headers["authorization"] == "Bearer issued-token"
