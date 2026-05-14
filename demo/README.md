# Demo environment

A reproducible, zero-setup playground for Afterlife. `demo/run.py` plants
synthetic data across all 8 source systems, runs the real collectors against
in-process mocks, runs the rules engine + identity graph, and writes both a
terminal-friendly summary and a self-contained HTML report.

## Run it

```bash
make demo
```

(Or `.venv/bin/python demo/run.py`.)

## What gets planted

Eight source systems, in-process via `moto` (AWS), `respx` (every HTTP API),
and `freezegun` (for backdating create timestamps).

### AWS IAM

| Resource | Age | Last used | Policies | Fires |
|---|---|---|---|---|
| `alice` | 30d | 5d ago | `ReadOnlyAccess` | (clean) |
| `bob` | 200d | 120d ago | `AdministratorAccess` | `UNUSED-CREDENTIAL`, `UNROTATED-KEY`, `OFFBOARDED-OWNER` (broad blast) |
| `carol` | 90d | never | `IAMFullAccess`, `AmazonS3FullAccess` | `NEVER-USED`, `OFFBOARDED-OWNER` (broad blast) |
| `dave` | 250d | 5d ago | `AdministratorAccess` | `UNROTATED-KEY` (broad blast); also drives `ADMIN-CONCENTRATION` |
| `eve` | 10d | never | (none) | (clean, inside grace) |
| `contractor-jane` | 60d | 5d ago | `ReadOnlyAccess` | `OUTSIDE-COLLAB-WITH-AWS` (Jane is a GitHub outside collaborator) |
| role `LegacyDeployRole` | 300d | never | `PowerUserAccess` | `NEVER-USED` (broad blast) |
| role `ForgottenAuditRole` | 250d | never | `ReadOnlyAccess` | suppressed via `demo/allowlist.yaml` |
| role `ExternalAuditorRole` | 120d | never | `ReadOnlyAccess` | `CROSS-ACCOUNT-TRUST` (trusted by account `999999999999`) |

### GCP IAM

| Service account | Disabled? | Keys | Fires |
|---|---|---|---|
| `ci-deploy@demo-project...` | no | 1 key, 200d old | `UNROTATED-KEY` |
| `data-pipeline@demo-project...` | no | 1 key, 30d old | (clean) |
| `legacy-bot@demo-project...` | yes | 1 key, 400d old | `OFFBOARDED-OWNER` + `UNROTATED-KEY` |

### GitHub (org `test-org`)

| Resource | Notes |
|---|---|
| member `alice` | links cross-source |
| member `bob123` | private email, won't link |
| member `dave-engineer` | links cross-source |
| outside collaborator `contractor-jane` | drives `OUTSIDE-COLLAB-WITH-AWS` |
| installation `dependabot` | App with three permissions |
| `test-org/main-app` deploy key `ci-deploy` | fresh, clean |
| `test-org/main-app` deploy key `legacy-deploy` | 300d old, last used 120d ago, write-capable | `UNUSED-CREDENTIAL` + `STALE-DEPLOY-KEY-WRITE` |

### GitLab (group `demo-group`)

| Resource | Notes |
|---|---|
| member `alice` | 6+ way cross-source |
| member `priya` | GitLab-only |
| project `demo-group/demo-service` | one fresh deploy key |

### Google Workspace

| User | Status | Effect |
|---|---|---|
| `alice@example.com` | active | cross-source link |
| `bob@example.com` | **suspended** | `OFFBOARDED-OWNER` on bob's AWS key |
| `carol@example.com` | **archived** | `OFFBOARDED-OWNER` on carol's AWS key |
| `dave@example.com` | active, admin, NO 2SV, last login 120d ago | `ADMIN-WITHOUT-MFA` + `INACTIVE-ADMIN` + (combined with AWS admin) `ADMIN-CONCENTRATION` |
| `eve@example.com` | active | cross-source |
| `nina@example.com` | active | Google-only, `ORPHANED-IDENTITY` |

### Microsoft Entra ID

| User | Effect |
|---|---|
| `alice@example.com` | extends alice's cross-source chain |
| `dave@example.com` | extends dave's cross-source chain |
| `raj@example.com` | Azure-only, also fires `ORPHANED-IDENTITY` |

### Slack

| User | Effect |
|---|---|
| `alice` | extends alice's chain to 6 sources |
| `dave` (admin) | adds Slack to dave's `ADMIN-CONCENTRATION` evidence |
| `pixel-bot` | bot, Slack-only |
| `ex-employee` (deleted) | demonstrates deprovisioned status mapping |

### HashiCorp Vault

| Entity | Aliases | Effect |
|---|---|---|
| `alice` | `aws/arn:aws:iam::123456789012:user/alice` + `github/alice` | bridges Vault to AWS + GitHub without needing a shared email — links alice to 7 sources total |
| `deploy-bot` | none | Vault-only service entity |

## Expected output

```
20 active findings (1 suppressed by allowlist)
   3 critical
   3 high
   5 medium
   1 low

16 persons across 8 sources (6 cross-source)
```

The `OFFBOARDED-OWNER fired:` callout explicitly names bob and carol as the
Uber-2022-pattern catches. The identity-graph view shows alice as the most
cross-linked person (7 sources via the Vault alias bridge).

## How the timestamps are controlled

AWS, GitHub, GitLab, Google, and Microsoft Graph all stamp resources with
server-side timestamps. To produce a deterministic demo:

- **AWS `CreateDate`** controlled via `freezegun.freeze_time(...)` around the
  IAM API calls. Moto reads the frozen clock when stamping resources.
- **AWS `LastUsedDate`** has no public API or `freezegun` hook; the demo
  pokes the value directly into moto's `iam_backends` after creation. This
  is intentionally fragile, the demo script is the only consumer.
- **GitHub / GitLab / Google / Azure / Slack / Vault timestamps** are set in
  the mocked JSON responses directly. `respx` serves whatever we return.
- **Cloud / OAuth auth** is bypassed in the demo by passing
  `access_token="demo-token"` / `token="..."` directly. The production code
  paths (JWT signing for Google + GCP, client-credentials grant for Azure,
  PAT auth for GitHub / GitLab / Slack / Vault) are exercised by dedicated
  unit tests.

## What's *not* in the demo

- Anything that requires a CloudTrail / audit-log source (PRIVILEGE-DRIFT,
  ROOT-USAGE, MFA-DOWNGRADE).
- Real-world false positives — every planted credential is unambiguous so
  the expected output is fully reproducible.
- A second AWS account (so CROSS-ACCOUNT-TRUST fires against a hard-coded
  external account number `999999999999`).
