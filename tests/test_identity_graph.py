from afterlife import db
from afterlife.graph.identity_graph import IdentityGraph
from afterlife.models import Credential, Identity


def _seed(db_path, identities, credentials=None):
    with db.connect(db_path) as conn:
        for i in identities:
            db.upsert_identity(conn, i)
        for c in credentials or []:
            db.upsert_credential(conn, c)


def _id(source, source_id, email=None, name=None, status="active"):
    return Identity(
        source=source,
        source_id=source_id,
        email=email,
        name=name or source_id,
        status=status,
    )


def test_single_source_identity_is_one_unlinked_person(fresh_db):
    _seed(fresh_db, [_id("aws", "arn:1", email="alice@example.com")])

    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())

    assert len(persons) == 1
    assert not persons[0].is_cross_source
    assert persons[0].canonical_email == "alice@example.com"


def test_identities_sharing_email_become_one_person(fresh_db):
    _seed(
        fresh_db,
        [
            _id("aws", "arn:1", email="alice@example.com"),
            _id("github", "alice", email="alice@example.com"),
        ],
    )

    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())

    assert len(persons) == 1
    assert persons[0].is_cross_source
    assert persons[0].sources == {"aws", "github"}
    assert persons[0].canonical_email == "alice@example.com"


def test_email_match_is_case_insensitive(fresh_db):
    _seed(
        fresh_db,
        [
            _id("aws", "arn:1", email="Alice@Example.COM"),
            _id("github", "alice", email="alice@example.com"),
        ],
    )

    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())

    assert len(persons) == 1
    assert persons[0].is_cross_source


def test_three_way_email_link_collapses_to_one_person(fresh_db):
    _seed(
        fresh_db,
        [
            _id("aws", "arn:1", email="alice@example.com"),
            _id("github", "alice", email="alice@example.com"),
            _id("okta", "00uABC", email="alice@example.com"),
        ],
    )

    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())

    assert len(persons) == 1
    assert {i.source for i in persons[0].identities} == {"aws", "github", "okta"}


def test_no_email_means_no_link(fresh_db):
    """Two identities with no email stay separate, even if logins happen to match."""
    _seed(
        fresh_db,
        [
            _id("aws", "alice", email=None),
            _id("github", "alice", email=None),
        ],
    )

    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())

    assert len(persons) == 2


def test_distinct_emails_stay_separate(fresh_db):
    _seed(
        fresh_db,
        [
            _id("aws", "arn:1", email="alice@example.com"),
            _id("github", "bob", email="bob@example.com"),
        ],
    )

    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())

    assert len(persons) == 2


def test_person_for_returns_full_component(fresh_db):
    _seed(
        fresh_db,
        [
            _id("aws", "arn:1", email="alice@example.com"),
            _id("github", "alice", email="alice@example.com"),
        ],
    )

    graph = IdentityGraph.from_db(fresh_db)
    person = graph.person_for("aws", "arn:1")

    assert person is not None
    assert person.is_cross_source
    assert person.identity_in("github") is not None
    assert person.identity_in("github").source_id == "alice"


def test_person_for_unknown_returns_none(fresh_db):
    graph = IdentityGraph.from_db(fresh_db)
    assert graph.person_for("aws", "does-not-exist") is None


def test_vault_alias_links_to_matching_aws_identity(fresh_db):
    """A Vault entity whose alias names an AWS ARN should be linked to that
    AWS identity, even if their emails don't match."""
    _seed(
        fresh_db,
        [
            Identity(
                source="aws",
                source_id="arn:aws:iam::123:user/alice",
                email=None,
                name="alice",
                status="active",
            ),
            Identity(
                source="vault",
                source_id="ent-1",
                email=None,
                name="alice",
                status="active",
                metadata={
                    "aliases": [
                        {
                            "mount_type": "aws",
                            "name": "arn:aws:iam::123:user/alice",
                        }
                    ]
                },
            ),
        ],
    )
    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())
    assert len(persons) == 1
    assert persons[0].is_cross_source
    assert {i.source for i in persons[0].identities} == {"aws", "vault"}


def test_vault_alias_links_to_matching_github_login(fresh_db):
    _seed(
        fresh_db,
        [
            Identity(
                source="github",
                source_id="alice",
                email=None,
                name="alice",
                status="active",
            ),
            Identity(
                source="vault",
                source_id="ent-1",
                email=None,
                name="alice",
                status="active",
                metadata={
                    "aliases": [
                        {"mount_type": "github", "name": "alice"}
                    ]
                },
            ),
        ],
    )
    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())
    assert len(persons) == 1
    assert persons[0].is_cross_source


def test_vault_alias_with_no_matching_identity_stays_unlinked(fresh_db):
    """Alias points at a principal we don't have a record of -> no edge added.
    The Vault entity is still its own person."""
    _seed(
        fresh_db,
        [
            Identity(
                source="vault",
                source_id="ent-1",
                email=None,
                name="alice",
                status="active",
                metadata={
                    "aliases": [
                        {
                            "mount_type": "aws",
                            "name": "arn:aws:iam::999:user/ghost",
                        }
                    ]
                },
            ),
        ],
    )
    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())
    assert len(persons) == 1
    assert not persons[0].is_cross_source


def test_vault_alias_chain_links_aws_and_github_via_one_entity(fresh_db):
    """One Vault entity bridges AWS + GitHub even without shared email."""
    _seed(
        fresh_db,
        [
            Identity(
                source="aws",
                source_id="arn:aws:iam::123:user/alice",
                email=None, name="alice", status="active",
            ),
            Identity(
                source="github",
                source_id="alice",
                email=None, name="alice", status="active",
            ),
            Identity(
                source="vault",
                source_id="ent-1",
                email=None, name="alice", status="active",
                metadata={
                    "aliases": [
                        {"mount_type": "aws", "name": "arn:aws:iam::123:user/alice"},
                        {"mount_type": "github", "name": "alice"},
                    ]
                },
            ),
        ],
    )
    graph = IdentityGraph.from_db(fresh_db)
    persons = list(graph.persons())
    assert len(persons) == 1
    assert {i.source for i in persons[0].identities} == {"aws", "github", "vault"}


def test_credentials_for_person_aggregates_across_sources(fresh_db):
    _seed(
        fresh_db,
        [
            _id("aws", "arn:1", email="alice@example.com"),
            _id("github", "alice", email="alice@example.com"),
        ],
        [
            Credential(
                source="aws",
                credential_id="AKIA-1",
                credential_type="aws_access_key",
                owner_source="aws",
                owner_id="arn:1",
            ),
            # GitHub deploy keys are ownerless in our model; this credential
            # is owned by the github identity directly (an unusual case used
            # only to verify aggregation).
            Credential(
                source="github",
                credential_id="pat:abc",
                credential_type="github_pat",
                owner_source="github",
                owner_id="alice",
            ),
        ],
    )

    graph = IdentityGraph.from_db(fresh_db)
    alice = graph.person_for("aws", "arn:1")
    creds = graph.credentials_for_person(alice)

    assert len(creds) == 2
    assert {c.credential_id for c in creds} == {"AKIA-1", "pat:abc"}
