# Demo environment

A reproducible, zero-setup playground for Afterlife.

`demo/run.py` plants synthetic IAM resources in an **in-memory** AWS account
(via [`moto`](https://github.com/getmoto/moto), no Docker required) and a
synthetic GitHub organization (via [`respx`](https://github.com/lundberg/respx)
intercepting `httpx`), then runs the real AWS and GitHub collectors, the rules
engine, and the identity graph.

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
| user `bob` | 200d | 120d ago | `UNUSED-CREDENTIAL`, `UNROTATED-KEY` |
| user `carol` | 90d | never | `NEVER-USED` |
| user `dave` | 250d | 5d ago | `UNROTATED-KEY` |
| user `eve` | 10d | never | nothing (within grace period) |
| role `LegacyDeployRole` | 300d | never | `NEVER-USED` |
| role `ForgottenAuditRole` | 250d | never | `NEVER-USED` |

### GitHub

| Resource | Notes |
|----------|-------|
| member `alice` | email `alice@example.com` — **links to AWS alice** |
| member `bob123` | private email — won't link (single-source) |
| member `dave-engineer` | email `dave@example.com` — **links to AWS dave** |
| outside collaborator `contractor-jane` | external vendor, GitHub only |
| installation `dependabot` | App with three permissions |
| repo `test-org/main-app` deploy key `ci-deploy` | fresh — no findings |
| repo `test-org/main-app` deploy key `legacy-deploy` | 300d old, last used 120d ago — fires `UNUSED-CREDENTIAL` |
| repo `test-org/infra` | no deploy keys |

Expected output: 7 findings (2 high, 5 medium) and 7 persons in the identity
graph, 2 of which are cross-source (alice and dave appear in both AWS and
GitHub and are linked by email).

## How the backdating works

AWS does not expose APIs to set `CreateDate` or `LastUsedDate` directly, and
GitHub returns its own server-side timestamps. To produce a deterministic
demo:

- **AWS `CreateDate`** is controlled by wrapping `iam.create_user` /
  `iam.create_role` / `iam.create_access_key` in `freezegun.freeze_time(...)`
  — moto reads the (frozen) wall clock when stamping resources.
- **AWS `LastUsedDate`** cannot be set via the API or freezegun, so the demo
  reaches into moto's in-process `iam_backends` and assigns an
  `AccessKeyLastUsed` object directly. Fragile to moto internals; the demo
  script is the only consumer.
- **GitHub timestamps** are set in the mocked JSON responses directly — respx
  serves whatever we return.

## What's *not* in the demo

- `OFFBOARDED-OWNER` does not fire yet: GitHub doesn't have a deprovisioned
  status the way Okta or Google Workspace does, so no linked identity in the
  demo graph has a status other than `active`. Once an IdP collector lands,
  this rule will surface findings for any cross-source person whose IdP
  identity is suspended/deleted.
- Real-world false positives — every planted credential is unambiguous so the
  expected output is fully predictable.
