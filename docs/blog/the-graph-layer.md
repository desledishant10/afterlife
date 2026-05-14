# Why a graph is the right shape for "ghost access"

When I started building [Afterlife](https://github.com/desledishant10/afterlife),
a ghost-access auditor that catches credentials outliving their owners, I
spent the first week not building any of that. I built collectors. Eight of
them eventually: AWS IAM, GCP IAM, GitHub, GitLab, Google Workspace,
Microsoft Entra, Okta, Slack, HashiCorp Vault. Each one a thin wrapper that
pulls users / service-accounts / credentials and writes them to SQLite.

That part is boring. The interesting part is what to do when you have
them all in one table, because the moment you do, you notice the thing
nobody talks about: **the same human is not the same identity twice**.

## The problem this is solving

The Uber 2022 breach is the canonical example. An attacker phished an
employee's MFA, hopped to internal systems, found credentials in scripts,
escalated. In every public post-mortem of an "ex-employee credentials
still active" breach, the same shape appears:

```
employee.idp.status        = suspended  (or deleted, archived, ...)
employee.aws_user.status   = active     (because nobody automated the link)
employee.aws_access_key    = still valid
```

The cloud system doesn't know about the IdP. The IdP doesn't know about
the cloud. The only thing that ties them together is one shared field,
usually email, and there's no canonical home for "person."

If you treat each system as a separate inventory ("show me all AWS users",
"show me all Google users"), you can't see the gap. You need to put
"this email is one human" in the schema. That's the identity graph.

## What it looks like in the schema

Three tables: `identities`, `credentials`, `findings`. The interesting one
is `identities`:

```sql
CREATE TABLE identities (
    source        TEXT NOT NULL,   -- "aws", "google", "github", ...
    source_id     TEXT NOT NULL,   -- ARN, Workspace UUID, GitHub login
    email         TEXT,            -- nullable; some sources don't expose it
    name          TEXT,
    status        TEXT NOT NULL,   -- normalized: active/suspended/archived/...
    metadata      TEXT,            -- per-source JSON blob
    PRIMARY KEY (source, source_id)
);
```

Each row is "one source-system view of a person." A single human winds up
with up to 9 rows in this table (AWS + GitHub + GitLab + Google + Azure
+ Okta + Slack + GCP + Vault, in our most generous case).

The graph is what you get when you read those rows and start linking them.

## The first linker: email

The simplest possible link is "same lowercased email." If `alice@example.com`
appears in `aws`, `github`, and `google`, that's one person.

```python
def _link_by_email(self):
    by_email: dict[str, list[tuple[str, str]]] = {}
    for key, identity in self._identities.items():
        if identity.email:
            by_email.setdefault(identity.email.lower(), []).append(key)
    for email, keys in by_email.items():
        if len(keys) < 2:
            continue
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                self.g.add_edge(a, b, kind="email", email=email)
```

Then `nx.connected_components(g)` gives you the persons:

```python
def persons(self) -> Iterator[Person]:
    for component in nx.connected_components(self.g):
        identities = sorted(
            (self._identities[k] for k in component),
            key=lambda i: i.source,
        )
        ...
        yield Person(identities=identities, canonical_email=...)
```

So far this is straightforward graph theory. The interesting part is
what it lets you write next.

## The marquee detection rule

Before the graph, OFFBOARDED-OWNER looked like this:

```sql
SELECT c.*
FROM credentials c
JOIN identities i
  ON c.owner_source = i.source AND c.owner_id = i.source_id
WHERE c.is_active = 1
  AND i.status IN ('suspended', 'deleted', 'deprovisioned', ...);
```

This catches one case: a credential whose direct owner is deprovisioned
**in the same system**. Useful for catching disabled IAM users who still
have access keys. Useless for the Uber pattern, where the credential is
on AWS and the deprovisioned record is on Google.

With the graph, the rule changes:

```python
def offboarded_owner(conn, config, graph):
    rows = conn.execute("""
        SELECT source, credential_id, credential_type, owner_source, owner_id,
               last_used_at
        FROM credentials
        WHERE is_active = 1
          AND owner_source IS NOT NULL
          AND owner_id IS NOT NULL
    """).fetchall()

    for r in rows:
        person = graph.person_for(r["owner_source"], r["owner_id"])
        deprovisioned = [
            i for i in person.identities
            if (i.status or "").lower() in DEPROVISIONED_STATUSES
        ]
        if deprovisioned:
            yield Finding(
                rule_id="OFFBOARDED-OWNER",
                severity=Severity.CRITICAL,
                evidence={
                    "credential_id": r["credential_id"],
                    "deprovisioned_in": deprovisioned[0].source,
                    "deprovisioned_status": deprovisioned[0].status,
                    "linked_identities": [...],
                },
                ...,
            )
```

The change is `graph.person_for(...)` followed by iterating
`person.identities`. The graph walk gets you from "credential's direct
owner" to "every identity that is the same person." If **any** of them is
deprovisioned in any source system, the rule fires.

That's the Uber pattern: bob's AWS access key has `owner_source="aws"`
and the AWS identity row says `status="active"`. The Google identity
row, linked by email, says `status="suspended"`. The graph walk surfaces
the link; the rule fires critical.

## Where it actually got interesting: Vault

Email matching covers ~70% of cases in practice. The rest of the iceberg
is people whose email isn't surfaced (GitHub members default to private
email), people whose SCIM provisioning uses different identifiers across
systems, and service accounts that have no email at all.

HashiCorp Vault solves a chunk of this for free. Vault's identity store
already represents the concept I'd been re-building:

```json
{
  "id": "ent-alice",
  "name": "alice",
  "aliases": [
    {"mount_type": "aws",    "name": "arn:aws:iam::123:user/alice"},
    {"mount_type": "github", "name": "alice"}
  ]
}
```

Each entity has zero or more aliases, and **each alias names a principal
in another system**. That's exactly the cross-source edge I was building
by inferring from emails. With Vault, the edge is explicit. The system
itself is telling me "this Vault entity is also this AWS ARN."

So Afterlife's identity graph has two passes:

```python
@classmethod
def from_db(cls, db_path):
    graph = cls()
    # load identities + credentials from SQLite ...
    graph._link_by_email()
    graph._link_by_vault_alias()
    return graph

def _link_by_vault_alias(self):
    for key, identity in self._identities.items():
        if identity.source != "vault":
            continue
        for alias in (identity.metadata or {}).get("aliases", []):
            target_source = _VAULT_MOUNT_TO_SOURCE.get(
                alias.get("mount_type", "").lower()
            )
            target_name = alias.get("name")
            target_key = (target_source, target_name)
            if target_key in self._identities and target_key != key:
                self.g.add_edge(key, target_key, kind="vault_alias", ...)
```

The mount-type map (`aws -> aws`, `github -> github`, `oidc -> google`,
...) lets a Vault alias whose `mount_type` is `"aws"` match an Identity
row whose `source` is `"aws"`. If they share a name (the ARN, the GitHub
login), the graph adds an edge.

The payoff in the demo is alice. Her email is in Google, AWS tags, and a
few other places, so email-linking already gets her to 5 sources. The
Vault entity for her has an `aws` alias matching her AWS ARN and a
`github` alias matching her GitHub login. Even if the email signal were
missing, those two aliases alone would link aws-alice + github-alice +
vault-alice into one person. With email-linking on top, she ends up as a
single 7-source person.

## What this lets you write next

Once "person" is a first-class thing in the system, every rule that was
"find a credential matching X" can become "find a person where X is
true." A few that fell out for free:

**ADMIN-CONCENTRATION**: same person is admin in 2+ systems. Without the
graph, this is impossible to write. With it:

```python
for person in graph.persons():
    admin_in = {ident.source for ident in person.identities
                if (ident.metadata or {}).get("is_admin")}
    # plus any AWS credentials with AdministratorAccess in scopes
    if len(admin_in) >= 2:
        yield Finding(...)
```

**OUTSIDE-COLLAB-WITH-AWS**: GitHub outside-collaborator linked to active
AWS credentials. The link is the whole rule.

**INACTIVE-ADMIN**: admin with no recent login. Reads `last_login_time`
from any IdP identity in the person, doesn't care which source it came
from.

The pattern: write the rule against the graph, not against any one
system. The graph layer absorbs the heterogeneity.

## The signature change

The one piece of infrastructure that made the graph migration painless
was something I did before the graph existed, almost by accident. The
original rule signature was `(conn, config) -> list[Finding]`. When
the graph layer landed, I changed it to `(conn, config, graph)`.

All four existing rules got a tiny patch: accept the extra arg, ignore
it. The new rule (OFFBOARDED-OWNER refactored) used it.

That's the architectural move worth naming: **add the parameter once,
ignore it everywhere it's not yet needed, then start using it where it
matters**. The alternative is rewriting every rule when the third
collaborator on the registry changes the shape of the world. Don't.

## Why this matters for the actual goal

The goal of this tool is to catch credentials that should have been
revoked but weren't. The IdP usually knows the right answer
(`status: suspended`). The cloud usually still trusts the credential.
The gap between those two facts is where the breaches happen.

Most security tools approach this with workflow integrations: "when an
employee is offboarded in Okta, fire a webhook that disables their
AWS access keys." Those workflows are necessary and they fail in real
deployments all the time. The webhook 500s, the team forgets to add
it for a new IAM user, the Okta event is filtered out by an upstream
rule. **You need a detective control that watches what actually
happened, not what the workflow says should have happened.**

That detective control needs to join across systems. The cleanest data
structure for joining identities that have different IDs in different
systems is a graph. And the cleanest implementation of that graph, for
the data volumes involved (low thousands of identities, hundreds of
credentials), is a NetworkX-in-Python build, rebuilt per analyze run
from the SQLite store.

That's the whole layer. The rest is collectors that fill SQLite, rules
that read SQLite + graph, and reports that read SQLite. Each is
swappable. The graph is the one that does the actual security work.
