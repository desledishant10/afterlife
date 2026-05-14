import json

import httpx
import pytest
import respx

from afterlife import db
from afterlife.collectors.gitlab import GitLabCollector

GROUP = "demo-group"


def _user(uid, username, *, state="active", email=None, name=None,
          access_level=30):
    return {
        "id": uid,
        "username": username,
        "name": name or username,
        "state": state,
        "email": email,
        "access_level": access_level,
        "expires_at": None,
        "web_url": f"https://gitlab.com/{username}",
    }


def _project(pid, name):
    return {
        "id": pid,
        "name": name,
        "path_with_namespace": f"{GROUP}/{name}",
    }


def _route(path):
    return respx.route(method="GET", host="gitlab.com", path=path)


def _run(fresh_db):
    return GitLabCollector(
        db_path=fresh_db, token="fake-token", group=GROUP
    ).run()


def _default_routes(members=None, projects=None):
    _route(f"/api/v4/groups/{GROUP}/members/all").mock(
        return_value=httpx.Response(200, json=members or [])
    )
    _route(f"/api/v4/groups/{GROUP}/projects").mock(
        return_value=httpx.Response(200, json=projects or [])
    )


@respx.mock
def test_collects_active_member(fresh_db):
    _default_routes(members=[_user(1, "alice", email="alice@example.com")])
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT * FROM identities WHERE source = 'gitlab'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["email"] == "alice@example.com"
        assert rows[0]["status"] == "active"


@respx.mock
def test_blocked_state_maps_to_suspended(fresh_db):
    _default_routes(members=[_user(2, "bob", state="blocked")])
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        assert conn.execute("SELECT status FROM identities").fetchone()["status"] == "suspended"


@respx.mock
def test_deactivated_state_maps_to_deprovisioned(fresh_db):
    _default_routes(members=[_user(3, "carol", state="deactivated")])
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute("SELECT status FROM identities").fetchone()
        assert row["status"] == "deprovisioned"


@respx.mock
def test_paginates_via_link_header(fresh_db):
    next_url = f"https://gitlab.com/api/v4/groups/{GROUP}/members/all?page=2"
    members_route = _route(f"/api/v4/groups/{GROUP}/members/all")
    members_route.side_effect = [
        httpx.Response(
            200, json=[_user(1, "alice")],
            headers={"Link": f'<{next_url}>; rel="next"'},
        ),
        httpx.Response(200, json=[_user(2, "bob")]),
    ]
    _route(f"/api/v4/groups/{GROUP}/projects").mock(
        return_value=httpx.Response(200, json=[])
    )

    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 2


@respx.mock
def test_collects_deploy_keys(fresh_db):
    _default_routes(projects=[_project(42, "main-app")])
    deploy_key = {
        "id": 7,
        "title": "ci-deploy",
        "created_at": "2024-06-01T12:00:00Z",
        "last_used_at": "2024-12-01T08:00:00Z",
        "can_push": True,
    }
    _route(f"/api/v4/projects/42/deploy_keys").mock(
        return_value=httpx.Response(200, json=[deploy_key])
    )

    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        cred = conn.execute(
            "SELECT * FROM credentials WHERE credential_type = 'gitlab_deploy_key'"
        ).fetchone()
        assert cred is not None
        assert cred["credential_id"] == f"deploy_key:{GROUP}/main-app:7"
        assert cred["last_used_at"] == "2024-12-01T08:00:00+00:00"
        assert json.loads(cred["scopes"]) == ["push"]


@respx.mock
def test_read_only_deploy_key_scope(fresh_db):
    _default_routes(projects=[_project(50, "infra")])
    _route(f"/api/v4/projects/50/deploy_keys").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "title": "readonly",
                    "created_at": "2024-01-01T00:00:00Z",
                    "can_push": False,
                }
            ],
        )
    )
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        row = conn.execute(
            "SELECT scopes FROM credentials WHERE credential_type = 'gitlab_deploy_key'"
        ).fetchone()
        assert json.loads(row["scopes"]) == ["read"]


@respx.mock
def test_deploy_keys_403_does_not_block_other_projects(fresh_db):
    _default_routes(
        projects=[_project(1, "private"), _project(2, "public")]
    )
    _route(f"/api/v4/projects/1/deploy_keys").mock(
        return_value=httpx.Response(403, json={"message": "Forbidden"})
    )
    _route(f"/api/v4/projects/2/deploy_keys").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": 9,
                    "title": "ok",
                    "created_at": "2024-01-01T00:00:00Z",
                    "can_push": False,
                }
            ],
        )
    )

    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        rows = conn.execute(
            "SELECT credential_id FROM credentials"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["credential_id"].endswith(":9")


@respx.mock
def test_rerun_is_idempotent(fresh_db):
    _default_routes(members=[_user(1, "alice")])
    _run(fresh_db)
    _run(fresh_db)
    with db.connect(fresh_db) as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM identities").fetchone()["n"]
        assert n == 1


@respx.mock
def test_unauthorized_raises(fresh_db):
    _route(f"/api/v4/groups/{GROUP}/members/all").mock(
        return_value=httpx.Response(401, json={"message": "401 Unauthorized"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        _run(fresh_db)


def test_constructor_requires_token(fresh_db):
    with pytest.raises(ValueError, match="token"):
        GitLabCollector(db_path=fresh_db, token="", group="g")


def test_constructor_requires_group(fresh_db):
    with pytest.raises(ValueError, match="group"):
        GitLabCollector(db_path=fresh_db, token="x", group="")
