import json

import httpx
import pytest
import respx

from afterlife import db
from afterlife.collectors.github import GH_API, GitHubCollector


def _user(login: str, **kw) -> dict:
    base = {
        "login": login,
        "id": abs(hash(login)) % 100000,
        "type": "User",
        "html_url": f"https://github.com/{login}",
    }
    base.update(kw)
    return base


def _repo(name: str, **kw) -> dict:
    base = {
        "id": abs(hash(name)) % 100000,
        "name": name,
        "full_name": f"test-org/{name}",
    }
    base.update(kw)
    return base


def _route(path: str):
    """Register a respx route matching `path` for any query string."""
    return respx.route(method="GET", host="api.github.com", path=path)


def _default_routes(
    *,
    members: list[dict] | None = None,
    outside: list[dict] | None = None,
    installations: list[dict] | None = None,
    repos: list[dict] | None = None,
    cred_auths: list[dict] | None = None,
):
    _route("/orgs/test-org/members").mock(
        return_value=httpx.Response(200, json=members or [])
    )
    _route("/orgs/test-org/outside_collaborators").mock(
        return_value=httpx.Response(200, json=outside or [])
    )
    _route("/orgs/test-org/installations").mock(
        return_value=httpx.Response(
            200,
            json={
                "total_count": len(installations or []),
                "installations": installations or [],
            },
        )
    )
    _route("/orgs/test-org/repos").mock(
        return_value=httpx.Response(200, json=repos or [])
    )
    _route("/orgs/test-org/credential-authorizations").mock(
        return_value=httpx.Response(200, json=cred_auths or [])
    )


def _run(fresh_db) -> int:
    return GitHubCollector(token="test-token", org="test-org", db_path=fresh_db).run()


@respx.mock
def test_collects_org_members(fresh_db):
    _default_routes(members=[_user("alice"), _user("bob")])

    count = _run(fresh_db)

    assert count == 2
    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT * FROM identities WHERE source = 'github' ORDER BY source_id"
        ).fetchall()
        assert [r["source_id"] for r in rows] == ["alice", "bob"]
        assert all(r["status"] == "active" for r in rows)


@respx.mock
def test_outside_collaborator_flagged_in_metadata(fresh_db):
    _default_routes(outside=[_user("contractor")])

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT metadata FROM identities WHERE source_id = 'contractor'"
        ).fetchone()
        meta = json.loads(row["metadata"])
        assert meta["is_outside_collaborator"] is True


@respx.mock
def test_org_members_not_flagged_as_outside(fresh_db):
    _default_routes(members=[_user("alice")])

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT metadata FROM identities WHERE source_id = 'alice'"
        ).fetchone()
        meta = json.loads(row["metadata"])
        assert meta["is_outside_collaborator"] is False


@respx.mock
def test_collects_app_installations_with_scopes(fresh_db):
    install = {
        "id": 12345,
        "app_slug": "dependabot",
        "created_at": "2023-01-15T10:00:00Z",
        "permissions": {"contents": "read", "metadata": "read", "pull_requests": "write"},
        "events": ["push", "pull_request"],
    }
    _default_routes(installations=[install])

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        cred = conn.execute(
            "SELECT * FROM credentials WHERE credential_type = 'github_app_installation'"
        ).fetchone()
        assert cred is not None
        assert cred["credential_id"] == "installation:12345"
        scopes = json.loads(cred["scopes"])
        assert set(scopes) == {"contents", "metadata", "pull_requests"}
        assert cred["created_at"] == "2023-01-15T10:00:00+00:00"


@respx.mock
def test_collects_deploy_keys_with_last_used(fresh_db):
    _default_routes(repos=[_repo("app")])
    deploy_key = {
        "id": 999,
        "title": "ci-deploy",
        "created_at": "2024-06-01T12:00:00Z",
        "last_used": "2024-12-01T08:00:00Z",
        "read_only": False,
        "verified": True,
    }
    _route("/repos/test-org/app/keys").mock(
        return_value=httpx.Response(200, json=[deploy_key])
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        cred = conn.execute(
            "SELECT * FROM credentials WHERE credential_type = 'github_deploy_key'"
        ).fetchone()
        assert cred is not None
        assert cred["credential_id"] == "deploy_key:test-org/app:999"
        assert cred["last_used_at"] == "2024-12-01T08:00:00+00:00"
        assert json.loads(cred["scopes"]) == ["read", "write"]


@respx.mock
def test_read_only_deploy_key_marks_scopes_as_read(fresh_db):
    _default_routes(repos=[_repo("app")])
    _route("/repos/test-org/app/keys").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "title": "readonly",
                    "created_at": "2024-01-01T00:00:00Z",
                    "read_only": True,
                }
            ],
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        cred = conn.execute(
            "SELECT scopes FROM credentials WHERE credential_type = 'github_deploy_key'"
        ).fetchone()
        assert json.loads(cred["scopes"]) == ["read"]


@respx.mock
def test_paginates_via_link_header(fresh_db):
    next_url = f"{GH_API}/orgs/test-org/members?page=2"
    route = _route("/orgs/test-org/members")
    route.side_effect = [
        httpx.Response(
            200,
            json=[_user("alice")],
            headers={"Link": f'<{next_url}>; rel="next"'},
        ),
        httpx.Response(200, json=[_user("bob")]),
    ]
    _route("/orgs/test-org/outside_collaborators").mock(
        return_value=httpx.Response(200, json=[])
    )
    _route("/orgs/test-org/installations").mock(
        return_value=httpx.Response(200, json={"installations": []})
    )
    _route("/orgs/test-org/repos").mock(
        return_value=httpx.Response(200, json=[])
    )
    _route("/orgs/test-org/credential-authorizations").mock(
        return_value=httpx.Response(200, json=[])
    )

    count = _run(fresh_db)

    assert count == 2
    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT source_id FROM identities ORDER BY source_id"
        ).fetchall()
        assert [r["source_id"] for r in rows] == ["alice", "bob"]


@respx.mock
def test_installations_403_is_non_fatal(fresh_db):
    _route("/orgs/test-org/members").mock(return_value=httpx.Response(200, json=[]))
    _route("/orgs/test-org/outside_collaborators").mock(
        return_value=httpx.Response(200, json=[])
    )
    _route("/orgs/test-org/installations").mock(
        return_value=httpx.Response(403, json={"message": "Forbidden"})
    )
    _route("/orgs/test-org/repos").mock(return_value=httpx.Response(200, json=[]))
    _route("/orgs/test-org/credential-authorizations").mock(
        return_value=httpx.Response(200, json=[])
    )

    count = _run(fresh_db)
    assert count == 0


@respx.mock
def test_deploy_keys_404_skips_one_repo_not_all(fresh_db):
    _default_routes(repos=[_repo("app"), _repo("infra")])
    _route("/repos/test-org/app/keys").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )
    _route("/repos/test-org/infra/keys").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "title": "deploy",
                    "created_at": "2024-01-01T00:00:00Z",
                    "read_only": False,
                }
            ],
        )
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        keys = conn.execute(
            "SELECT credential_id FROM credentials WHERE credential_type = 'github_deploy_key'"
        ).fetchall()
        assert len(keys) == 1
        assert keys[0]["credential_id"].startswith("deploy_key:test-org/infra:")


@respx.mock
def test_rerun_is_idempotent(fresh_db):
    _default_routes(members=[_user("alice")])

    _run(fresh_db)
    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 1


@respx.mock
def test_unauthorized_raises(fresh_db):
    _route("/orgs/test-org/members").mock(
        return_value=httpx.Response(401, json={"message": "Bad credentials"})
    )

    with pytest.raises(httpx.HTTPStatusError):
        _run(fresh_db)


@respx.mock
def test_collects_personal_access_tokens(fresh_db):
    _default_routes(
        members=[_user("alice")],
        cred_auths=[
            {
                "login": "alice",
                "credential_id": 111,
                "credential_type": "personal access token",
                "credential_authorized_at": "2024-01-02T10:00:00Z",
                "credential_accessed_at": "2026-05-01T10:00:00Z",
                "scopes": ["repo", "read:org"],
                "token_last_eight": "abcd1234",
            },
            {  # an SSH key authorization is not a PAT and must be skipped
                "login": "alice",
                "credential_id": 222,
                "credential_type": "SSH key",
            },
        ],
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT credential_id, owner_source, owner_id, scopes, metadata "
            "FROM credentials WHERE credential_type = 'github_pat'"
        ).fetchall()
    assert len(rows) == 1  # the SSH key was skipped
    assert rows[0]["credential_id"] == "pat:alice:111"
    assert rows[0]["owner_source"] == "github"
    assert rows[0]["owner_id"] == "alice"
    assert json.loads(rows[0]["metadata"])["token_last_eight"] == "abcd1234"


@respx.mock
def test_credential_authorizations_absent_is_tolerated(fresh_db):
    # Non-Enterprise orgs 404 this endpoint; the scan must still succeed.
    _route("/orgs/test-org/members").mock(
        return_value=httpx.Response(200, json=[_user("alice")])
    )
    _route("/orgs/test-org/outside_collaborators").mock(
        return_value=httpx.Response(200, json=[])
    )
    _route("/orgs/test-org/installations").mock(
        return_value=httpx.Response(200, json={"total_count": 0, "installations": []})
    )
    _route("/orgs/test-org/repos").mock(return_value=httpx.Response(200, json=[]))
    _route("/orgs/test-org/credential-authorizations").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )

    _run(fresh_db)

    with db.connect(fresh_db) as conn:
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM credentials WHERE credential_type='github_pat'"
        ).fetchone()["n"]
    assert n == 0
