# Architecture

## Pipeline

```
collectors/  ─►  SQLite  ─►  identity graph  ─►  rules engine  ─►  findings  ─►  report
   AWS         (afterlife.db)   (NetworkX)        (pluggable)
   GitHub
   Okta / GWS
```

The pipeline runs in five stages, each clean to swap or extend:

### 1. Collectors (`afterlife.collectors`)
One subclass of `Collector` per source system. Each pulls identities and credentials,
normalizes them into `Identity` and `Credential` dataclasses, and writes them to SQLite
via `db.upsert_identity` / `db.upsert_credential`. Collectors are intentionally dumb:
no analysis, no correlation. They are easy to unit-test against mocks (boto3 via `moto`,
GitHub/IdP via `httpx` test transports).

### 2. SQLite store (`afterlife.db`)
A single file `afterlife.db` with three tables: `identities`, `credentials`, `findings`.
Indexed on the join keys rules care about (`(owner_source, owner_id)` and `email`).
Schema is intentionally narrow: JSON blobs absorb source-specific metadata so we don't
hand-roll a schema per source.

### 3. Identity graph (`afterlife.graph.identity_graph`)
A NetworkX multi-graph stitched lazily from the SQLite store. Nodes are identities and
credentials; edges are `owns` (identity → credential) and `same_person_as` (identity →
identity, found by email/name match). Cross-source rules query the graph instead of
joining tables manually.

### 4. Rules engine (`afterlife.rules`)
Decorator-registered detection functions. Each rule receives `(sqlite_conn, config)` and
returns `list[Finding]`. New rules are one file: drop a module under `afterlife/rules/`
with the `@rule(...)` decorator and it's auto-discovered by `registry._discover()`.

### 5. Reporting (`afterlife.reporting`)
JSON for v0.1, HTML in Week 9. Findings are ordered by severity then recency.

## Why these boundaries

- **Collectors do not call rules.** Lets us re-run analysis with new rule logic
  without re-querying upstream APIs (which is slow and rate-limited).
- **Rules do not call collectors.** Lets us swap the SQLite store for Postgres
  later without touching detection logic.
- **Graph is optional.** Simple rules (`UNUSED-CREDENTIAL`) work fine over raw SQL.
  Only cross-source rules need the graph. Avoids forcing all rules through one shape.

## What's outside the system boundary

- Auto-remediation (revoking credentials): explicit non-goal for v0.1. The harm
  of acting incorrectly outweighs the value of acting automatically.
- Real-time detection: Afterlife is a batch scanner.
- SaaS app sprawl (Slack, Notion, Salesforce): out of scope until Phase 2.
- Multi-tenancy: Afterlife is a single-org tool. No auth, no isolation.
