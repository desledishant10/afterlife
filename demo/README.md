# Demo environment

A reproducible, zero-setup playground for Afterlife.

`demo/run.py` plants synthetic IAM resources in an **in-memory** AWS account
(via [`moto`](https://github.com/getmoto/moto), no Docker required), a
synthetic GitHub organization, and a synthetic Google Workspace customer
(both via [`respx`](https://github.com/lundberg/respx) intercepting `httpx`).
It then runs all three collectors, the rules engine, and the identity graph.

## Run it

```bash
make demo
# or, without make:
.venv/bin/python demo/run.py
```

## What it plants

### AWS

| Resource | Age | Last used | Fires |
|----------|-----|-----------|-------|
| user `alice` | 30d | 5d ago | nothing (fresh) |
| user `bob` | 200d | 120d ago | `UNUSED-CREDENTIAL`, `UNROTATED-KEY`, `OFFBOARDED-OWNER` |
| user `carol` | 90d | never | `NEVER-USED`, `OFFBOARDED-OWNER` |
| user `dave` | 250d | 5d ago | `UNROTATED-KEY` |
| user `eve` | 10d | never | nothing (within grace period) |
| role `LegacyDeployRole` | 300d | never | `NEVER-USED` |
| role `ForgottenAuditRole` | 250d | never | `NEVER-USED` |

### GitHub

| Resource | Notes |
|----------|-------|
| member `alice` | email `alice@example.com` — links to AWS + Google alice |
| member `bob123` | private email — won't link (single-source) |
| member `dave-engineer` | email `dave@example.com` — links to AWS + Google dave |
| outside collaborator `contractor-jane` | external vendor, GitHub only |
| installation `dependabot` | App with three permissions |
| `test-org/main-app` deploy key `ci-deploy` | fresh — no findings |
| `test-org/main-app` deploy key `legacy-deploy` | 300d old, last used 120d ago — fires `UNUSED-CREDENTIAL` |

### Google Workspace

| User | Status | Effect |
|------|--------|--------|
| `alice@example.com` | active | links cross-source |
| `bob@example.com` | **suspended** | fires `OFFBOARDED-OWNER` on bob's AWS key |
| `carol@example.com` | **archived** | fires `OFFBOARDED-OWNER` on carol's AWS key |
| `dave@example.com` | active | links cross-source |
| `eve@example.com` | active | links cross-source |
| `nina@example.com` | active | Google-only, no AWS/GitHub presence |

## Expected output

9 findings (2 critical, 2 high, 5 medium), with `OFFBOARDED-OWNER` firing on
both `bob` and `carol`'s AWS keys because the cross-source identity graph
links the AWS identity to a suspended/archived Workspace identity by email.

8 persons in the identity graph — 5 cross-source (alice, bob, carol, dave, eve)
and 3 single-source (jane outside collab, nina Google-only, bob123 with no
email).

## How the backdating works

AWS does not expose APIs to set `CreateDate` or `LastUsedDate` directly, and
GitHub / Google return server-side timestamps. To produce a deterministic
demo:

- **AWS `CreateDate`** is controlled by wrapping `iam.create_user` /
  `iam.create_role` / `iam.create_access_key` in `freezegun.freeze_time(...)`
  — moto reads the (frozen) wall clock when stamping resources.
- **AWS `LastUsedDate`** cannot be set via the API or freezegun, so the demo
  reaches into moto's in-process `iam_backends` and assigns an
  `AccessKeyLastUsed` object directly. Fragile to moto internals; the demo
  script is the only consumer.
- **GitHub and Google timestamps** are set in the mocked JSON responses
  directly — respx serves whatever we return.
- **Google auth** is bypassed in the demo by passing `access_token="demo-token"`
  to the collector, which short-circuits the JWT signing + token exchange.
  The production code path (signed RS256 JWT exchanged at
  `oauth2.googleapis.com/token`) is exercised by a dedicated unit test.
