# Afterlife playbook

A task-oriented walkthrough of how to install, configure, run, and read
Afterlife in a real environment. Skim the cheat sheet first; the rest of
the doc is reference material organized by what you're trying to do.

---

## Cheat sheet

```bash
# install
make install                                    # creates .venv/, pulls deps

# initialize
.venv/bin/afterlife init                        # creates afterlife.db

# scan every source you have credentials for (run sequentially or in parallel)
.venv/bin/afterlife scan aws    --profile prod
.venv/bin/afterlife scan gcp    --project corp-prod
.venv/bin/afterlife scan github --org my-org    --token $GITHUB_TOKEN
.venv/bin/afterlife scan gitlab --group my-grp  --token $GITLAB_TOKEN
.venv/bin/afterlife scan idp    --provider google     # / okta / azure
.venv/bin/afterlife scan slack  --token $SLACK_TOKEN
.venv/bin/afterlife scan vault  --api-url https://vault.example.com:8200

# evaluate
.venv/bin/afterlife analyze                                # all rules
.venv/bin/afterlife analyze --allowlist allowlist.yaml     # with suppressions

# read
.venv/bin/afterlife identities                              # CLI: persons grouped
.venv/bin/afterlife list-rules                              # what's loaded
.venv/bin/afterlife report --format html -o report.html     # publish
.venv/bin/afterlife report --format sarif -o report.sarif   # to Code Scanning
.venv/bin/afterlife report --format pdf -o report.pdf       # stakeholder doc
.venv/bin/afterlife serve                                   # dashboard at :8000
```

Re-running `analyze` is idempotent: the findings table is replaced each
run. Re-running `scan` is also idempotent: identities and credentials are
upserted, not appended.

---

## 1. Installation

### Required

- **Python 3.11+**. `make install` creates `.venv/` and installs dependencies.
- A shell with `make` available. On macOS, install via Xcode CLI tools
  (`xcode-select --install`); on Debian/Ubuntu, `sudo apt install make`.

### Optional extras

- **`[pdf]`**: PDF report format. Requires the `weasyprint` Python package
  and a system Pango install.

  ```bash
  pip install -e ".[pdf]"
  # macOS
  brew install pango
  export DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib    # add to ~/.zshrc
  # Debian / Ubuntu
  sudo apt install libpango-1.0-0 libpangoft2-1.0-0
  ```

- **`[dev]`**: test runner + linters. Required only if you want to run
  `pytest` or edit the codebase.

### Verify install

```bash
.venv/bin/afterlife --help            # CLI usage
make demo                             # end-to-end against in-memory mocks
.venv/bin/pytest -q                   # 250+ tests, ~5 seconds
```

`make demo` is the quickest confidence check: it spins up moto-backed AWS,
respx-mocked HTTP for every other collector, runs the rules engine, and
writes `.afterlife-demo-report.html`. If that works, your install is
sound.

---

## 2. First-run setup

```bash
.venv/bin/afterlife init
# OK initialized afterlife.db
```

`afterlife init` creates an empty SQLite database at the configured path
(default `./afterlife.db`). It is safe to re-run; existing tables are
left alone, and any missing columns get added via in-place migration.

The database holds three working tables (`identities`, `credentials`,
`findings`) plus one operational table (`scan_runs`). All four are
keyed for `WHERE`-clause speed at the volumes we expect (low thousands
per source).

---

## 3. Collector setup

Every collector follows the same shape:

1. You give it credentials for the source system.
2. It enumerates identities + credentials there.
3. It upserts them into SQLite.
4. The scan run is recorded in `scan_runs`.

Re-running a scan is safe; identities + credentials are upserted on
their primary key `(source, source_id)` / `(source, credential_id)`.

Below: the auth setup, scopes, and gotchas for each collector.

### 3.1 AWS IAM

```bash
.venv/bin/afterlife scan aws --profile prod
```

**Auth:** boto3's default credential resolver. `--profile` selects a
profile from `~/.aws/credentials` or `~/.aws/config`. For CI, set the
standard AWS env vars (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`) or use OIDC role assumption (see CI section).

**Required IAM permissions:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:ListUsers", "iam:ListUserTags", "iam:ListUserPolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed",
      "iam:ListRoles", "iam:GetRole",
      "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}
```

The `ReadOnlyAccess` AWS-managed policy covers all of these and is the
simplest thing to attach.

**What the collector produces:**

- One Identity row per IAM user (with email pulled from tags `email`,
  `Email`, `owner`, `Owner`, `owner_email`, `OwnerEmail`)
- One Credential row per access key, with `last_used_at` from
  `GetAccessKeyLastUsed`
- One Credential row per IAM role (ownerless), with trust policy stored
  in metadata for CROSS-ACCOUNT-TRUST

**Gotchas:**

- The collector only reads one AWS account per run. For multi-account
  organizations, run the collector once per account (use different
  profiles or `aws-vault` rotation).
- Role last-used dates need a recent `GetRole` call; very old roles
  that have never been used show `last_used_at = None`.

### 3.2 GCP IAM

```bash
.venv/bin/afterlife scan gcp --project corp-prod
```

**Auth:** service-account JSON key file via `GCP_SERVICE_ACCOUNT_JSON`
env var or `--service-account-file` flag.

**Required IAM permissions** on the target project:

- `iam.serviceAccounts.list`
- `iam.serviceAccountKeys.list`

The predefined role `roles/iam.securityReviewer` covers both.

**What the collector produces:**

- One Identity row per service account (`source=gcp`, `source_id=email`)
- One Credential row per user-managed key (system-managed keys are
  excluded, they aren't actionable)

**Gotchas:**

- GCP's IAM API doesn't expose key-last-used data on the standard
  endpoint, so `NEVER-USED` rule explicitly skips
  `gcp_service_account_key` to avoid noise.
- For multi-project orgs, run once per project. (A `--project=...`
  loop is straightforward shell scripting.)

### 3.3 GitHub

```bash
.venv/bin/afterlife scan github --org my-org --token "$GITHUB_TOKEN"
```

**Auth:** Personal Access Token in the `Authorization: Bearer` header.

**Required PAT scopes:**

- Classic PAT: `read:org`, `repo`
- Fine-grained PAT (preferred):
  - Org permissions: Members (read), Administration (read)
  - Repo permissions: Administration (read), Metadata (read)

**What the collector produces:**

- One Identity per org member + one per outside collaborator
  (outside collaborators are flagged in metadata)
- GitHub Apps installed on the org as Credential rows
- Per-repo deploy keys as Credential rows (with `last_used_at` if
  GitHub has recorded usage)

**Gotchas:**

- PATs are not org-listable through the public REST API; only deploy
  keys + App installations + org member tokens via SAML SSO. The
  Enterprise SAML SSO authorization endpoint (which would close this
  gap) is intentionally out of scope for v0.1.
- GitHub rate limit is 5000 req/hour for authenticated PATs; the
  collector well-behaves and uses the standard `Link: next` pagination.

### 3.4 GitLab

```bash
.venv/bin/afterlife scan gitlab --group my-group --token "$GITLAB_TOKEN"
# self-hosted:
.venv/bin/afterlife scan gitlab --group my-group --token "$GITLAB_TOKEN" \
    --api-url https://gitlab.example.com/api/v4
```

**Auth:** Personal Access Token in the `PRIVATE-TOKEN` header.

**Required PAT scopes:** `read_api` (or `api` if your instance still
requires the broader scope).

**What the collector produces:**

- One Identity per group member (including inherited members from
  parent groups)
- Per-project deploy keys as Credential rows, with `last_used_at` and
  push capability surfaced via scopes (`push` vs `read`)

**Gotchas:**

- The collector reads one group at a time. Nested groups are picked up
  via `include_subgroups=true` on the projects endpoint.
- Project-level deploy keys require `Administration: read` access on
  each project; 403 on individual projects is non-fatal (skipped and
  collection continues).

### 3.5 Google Workspace

```bash
.venv/bin/afterlife scan idp --provider google \
    --service-account-file gcp-sa.json \
    --admin-email admin@example.com
```

**Auth:** service account with **domain-wide delegation** authorized to
impersonate a Workspace super-admin.

**Setup steps** (one-time, in the Google Cloud Console + Workspace
Admin):

1. Create a GCP service account.
2. Enable the Admin SDK API in the project.
3. In Workspace Admin → Security → API Controls → Domain-wide
   Delegation, add the service account's client ID with scope
   `https://www.googleapis.com/auth/admin.directory.user.readonly`.
4. Download the service account JSON key.

**What the collector produces:**

- One Identity per Workspace user; `accountEnabled=False` users become
  `status=suspended`, `archived=True` becomes `status=archived`.
- Admin flag (`isAdmin`) and 2-step verification state
  (`isEnforcedIn2Sv`, `isEnrolledIn2Sv`) flow into metadata so
  ADMIN-WITHOUT-MFA and ADMIN-CONCENTRATION can use them.

**Gotchas:**

- Without domain-wide delegation, the service account can authenticate
  but the Directory API call will return 403.
- The collector uses the JWT-bearer OAuth flow (RS256, PyJWT-signed).
  If you get auth errors, double-check the service account email and
  private key in the JSON file.

### 3.6 Microsoft Entra ID (Azure)

```bash
.venv/bin/afterlife scan idp --provider azure \
    --azure-tenant-id "$AZURE_TENANT_ID" \
    --azure-client-id "$AZURE_CLIENT_ID" \
    --azure-client-secret "$AZURE_CLIENT_SECRET"
```

**Auth:** OAuth 2.0 client-credentials grant. App-only (no user
impersonation).

**Setup steps:**

1. Register an application in Entra ID.
2. Grant the `User.Read.All` application permission (admin-consented).
3. Generate a client secret and copy it.

**What the collector produces:**

- One Identity per Entra user; `accountEnabled=false` becomes
  `status=suspended`.
- `signInActivity.lastSignInDateTime` is normalized to
  `metadata.last_login_time` so INACTIVE-ADMIN works uniformly across
  Workspace + Entra.

**Gotchas:**

- `signInActivity` requires a Microsoft Entra ID P1+ license. On a
  Free tier tenant the field is absent and `last_login_time` will be
  `None`.
- The Graph endpoint pagination uses `@odata.nextLink` as an absolute
  URL; the collector follows it transparently.

### 3.7 Okta

```bash
.venv/bin/afterlife scan idp --provider okta \
    --okta-domain mycompany.okta.com \
    --okta-token "$OKTA_API_TOKEN"
```

**Auth:** SSWS API token in the `Authorization: SSWS ...` header.

**Required scopes:** read-only. The default `Read-Only Admin` role
suffices.

**What the collector produces:**

- One Identity per Okta user, with the wide Okta status vocabulary
  mapped to the normalized one: SUSPENDED -> suspended,
  DEPROVISIONED -> deprovisioned, LOCKED_OUT -> active (recoverable),
  STAGED / PROVISIONED -> staged.

**Gotchas:**

- Okta's MFA enforcement signal is at the group/policy level, not on
  the user object. ADMIN-WITHOUT-MFA does not yet fire on Okta admins
  for this reason.

### 3.8 Slack

```bash
.venv/bin/afterlife scan slack --token "$SLACK_BOT_TOKEN"
```

**Auth:** Bearer token. Either a bot token (`xoxb-...`) or user token
(`xoxp-...`) works.

**Required scopes:** `users:read`. If you want email surfacing for
better cross-source linking, also `users:read.email`.

**What the collector produces:**

- One Identity per workspace member. `deleted=true` becomes
  `status=deprovisioned`. Admin / owner / primary-owner flags flow
  into `metadata.is_admin`. Bot, guest, and restricted flags surface in
  metadata for future rules.

**Gotchas:**

- Workspace Owner-tier scopes (`admin.users:read`) are not required;
  basic `users:read` is enough.
- The free tier of Slack Connect limits `users.list` pagination to
  smaller pages; the collector follows `response_metadata.next_cursor`
  regardless.

### 3.9 HashiCorp Vault

```bash
.venv/bin/afterlife scan vault \
    --api-url https://vault.example.com:8200 \
    --token "$VAULT_TOKEN"
# enterprise namespace:
.venv/bin/afterlife scan vault --api-url ... --token ... --namespace team-a/
```

**Auth:** standard `X-Vault-Token` header. Any token whose policy
allows `read` on `identity/entity/id` and `list` on the same path.

**Minimal policy:**

```hcl
path "identity/entity/id" {
  capabilities = ["list"]
}
path "identity/entity/id/*" {
  capabilities = ["read"]
}
```

**What the collector produces:**

- One Identity per entity (`source=vault`).
- Each alias from the entity is stored in metadata, *and the graph
  layer creates cross-source edges from each alias*. A Vault entity
  whose alias is `arn:aws:iam::123:user/alice` links directly to the
  AWS identity with that ARN. This works without a shared email.

**Gotchas:**

- Token enumeration (`/auth/token/accessors`) requires `sudo`-tier
  policy and is intentionally out of scope for v0.1. The collector
  covers what a least-privilege read policy can reach.
- Per-entity 403s are tolerated; the run still completes with the
  entities it can read.

---

## 4. Running `analyze`

```bash
.venv/bin/afterlife analyze
# 9 active findings
#    3 critical
#    3 high
#    5 medium
#    1 low
```

`analyze` is deterministic:

1. Build the identity graph from current SQLite state.
2. For each rule, evaluate against the graph.
3. Score blast radius for each finding.
4. Apply allowlist suppressions.
5. **Replace** the prior findings table (this is a snapshot, not an
   append-log).
6. Print a per-severity summary.

Re-running is safe; the next call's output replaces the previous one.

### Severity tiers

- **Critical**: act now. OFFBOARDED-OWNER, CROSS-ACCOUNT-TRUST,
  ADMIN-CONCENTRATION, ADMIN-WITHOUT-MFA.
- **High**: act this week. UNUSED-CREDENTIAL, STALE-DEPLOY-KEY-WRITE,
  OUTSIDE-COLLAB-WITH-AWS, INACTIVE-ADMIN.
- **Medium**: act this quarter. UNROTATED-KEY, NEVER-USED.
- **Low**: informational / hygiene. ORPHANED-IDENTITY.

### Blast radius

Each finding additionally gets a blast-radius score (0.0-1.0) and a
factor list explaining how the score was derived. Use blast radius to
break ties within a severity tier:

| Tier | Score | What it means |
|------|-------|----------------|
| broad    | >= 0.70 | AdministratorAccess, wildcard scopes, broad write |
| moderate | >= 0.40 | Some write access, multiple scopes |
| limited  | < 0.40  | Read-only or repo-scoped |

A critical+broad finding is always worse than a critical+limited one.
The dashboard sorts by `(severity, -blast_score)` by default; reports
do the same.

---

## 5. Reading the output

### CLI

```bash
.venv/bin/afterlife identities                       # persons grouped
.venv/bin/afterlife identities --cross-source-only   # only cross-system links
.venv/bin/afterlife list-rules                       # what rules are loaded
```

### Reports

```bash
.venv/bin/afterlife report --format html  -o report.html
.venv/bin/afterlife report --format json  -o report.json
.venv/bin/afterlife report --format sarif -o report.sarif
.venv/bin/afterlife report --format pdf   -o report.pdf      # [pdf] extra
```

Without `-o`, JSON/HTML/SARIF print to stdout; PDF requires `-o` since
it is binary. Pick by consumer:

| Format | Best for |
|---|---|
| `json`  | Programmatic consumption, scripting, custom integrations |
| `html`  | Self-contained handout to attach to a PR or email |
| `pdf`   | Publication-ready stakeholder document |
| `sarif` | GitHub Code Scanning, Azure DevOps, GitLab feeds |

### Web dashboard

```bash
.venv/bin/afterlife serve         # localhost:8000
.venv/bin/afterlife serve --host 0.0.0.0 --port 9000    # rarely; see below
```

**Default binding is `127.0.0.1:8000`.** Do not bind to `0.0.0.0` unless
you've put auth in front; the dashboard intentionally has none.

Pages:

- `/`: overview tiles, blast-tier chart, last-scan-per-source, top
  findings.
- `/findings`: filterable / searchable / sortable list. Filter by
  severity, rule, blast tier; sort by severity / blast / newest /
  oldest / rule. Toggle "show suppressed" to surface allowlisted
  findings.
- `/findings/{id}`: finding detail with linked owner person card and
  linked credential card.
- `/credentials`: sortable credential inventory across all sources.
- `/credentials/{source}/{id}`: credential detail with owner +
  metadata + every finding that mentions it.
- `/identities`: person-grouped view; filter to cross-source only.
- `/persons/{source}/{id}`: per-person detail with all linked
  identities, owned credentials, and related findings.
- `/scan-history`: every `afterlife scan ...` run with status,
  records collected, and duration.

**Keyboard shortcuts:**

- `/` to focus the search box.
- `Esc` to blur input / close the help dialog.
- `?` to toggle the keyboard shortcut help.
- `g h` / `g f` / `g c` / `g i` to jump to Overview / Findings /
  Credentials / Identities.

**Per-finding ack:** click the `ack` button next to any finding to
acknowledge it. The state is stored in your browser's localStorage,
not the server. Acknowledged findings dim with a strikethrough but
stay visible; clicking ack again clears them.

---

## 6. Allowlist / suppression

`afterlife analyze --allowlist allowlist.yaml` reads a YAML file naming
findings to suppress.

```yaml
# Yearly audit role, intentionally dormant.
- rule_id: NEVER-USED
  credential_id: arn:aws:iam::123:role/SeasonalReportingRole
  reason: Used once a year for tax reporting
  until: 2027-01-01            # optional expiry; absent = forever

# Suppress all OFFBOARDED-OWNER findings for one specific identity
# while a manual cleanup is in flight.
- rule_id: OFFBOARDED-OWNER
  identity_source: google
  identity_id: 1234567890
  reason: Manual cleanup in flight, see ticket SEC-4521
  until: 2026-06-15

# Catch-all for a credential, all rules.
- credential_id: AKIA-BREAKGLASS
  reason: Break-glass admin key, intentionally dormant
```

**Matchers:** `rule_id`, `credential_id`, `identity_source`,
`identity_id`. All named fields must match. Empty entries (no matchers)
are refused at load time.

**Behavior:** suppressed findings are persisted with `suppressed=1` and
the reason. Reports and the dashboard hide them by default. The
dashboard's "Show suppressed (N)" toggle reveals them dimmed. The
console summary reports `(N suppressed by allowlist)`.

---

## 7. Tuning thresholds

Defaults live in `src/afterlife/config.py`:

```python
@dataclass
class Config:
    unused_days_threshold: int = 90    # UNUSED-CREDENTIAL + STALE-DEPLOY-KEY-WRITE
    never_used_grace_days: int = 30    # NEVER-USED grace before firing
    unrotated_key_days: int = 180      # UNROTATED-KEY (AWS + GCP)
    oauth_stale_days: int = 90         # STALE-OAUTH (planned)
    inactive_admin_days: int = 30      # INACTIVE-ADMIN
```

There is no built-in config file loader in v0.1; if you want
per-environment thresholds, the cleanest path is a small wrapper
script that imports `afterlife.config.DEFAULT` and overrides fields
before calling `afterlife.rules.registry.run_all(...)`.

---

## 8. CI integration

A production-ready GitHub Actions workflow ships at
[.github/workflows/afterlife.yml](../.github/workflows/afterlife.yml).
Adapt it to your repo:

```yaml
name: Afterlife weekly audit
on:
  schedule: [{ cron: "0 14 * * 1" }]    # Mondays at 14:00 UTC
  workflow_dispatch:
permissions:
  contents: read
  id-token: write       # AWS OIDC role assumption
  security-events: write   # SARIF upload
```

The workflow:

1. Assumes an AWS role via OIDC (no long-lived keys in CI).
2. Reads each source's credentials from repository secrets.
3. Runs every collector you've configured.
4. Runs `afterlife analyze --allowlist .github/afterlife-allowlist.yaml`.
5. Uploads SARIF to GitHub Code Scanning so findings appear in the
   Security tab.
6. Saves an HTML report as a 30-day artifact.

**Required repository secrets / variables:**

| Secret | Purpose |
|---|---|
| `AFTERLIFE_AWS_ROLE_ARN` | IAM role to assume via OIDC |
| `AFTERLIFE_GH_TOKEN` | PAT for the org being scanned (if not using `GITHUB_TOKEN`) |
| `AFTERLIFE_GOOGLE_SA_JSON` | Inline service-account JSON |
| `AFTERLIFE_OKTA_TOKEN`, `AFTERLIFE_SLACK_TOKEN`, ... | Per-source bearer tokens |

| Variable | Purpose |
|---|---|
| `AFTERLIFE_GH_ORG` | Org slug to scan |
| `AFTERLIFE_GOOGLE_ADMIN` | Workspace super-admin to impersonate |
| `AFTERLIFE_GCP_PROJECT`, `AFTERLIFE_GITLAB_GROUP`, ... | Per-source identifiers |

---

## 9. Real-world deployment patterns

### Weekly scheduled audit

Use the GitHub Action above. Most teams adopt this on day one.

### Event-driven scan after offboarding

In the long-term, scans should run within minutes of an offboarding
event (Okta `user.lifecycle.deactivate`, Workspace `DELETE_USER`, ...)
rather than on a weekly cron. The window between offboarding and the
next scheduled scan is the window attackers exploit.

A reasonable pattern: a small webhook receiver that listens for IdP
events and dispatches a one-shot `afterlife scan {affected_source}
&& afterlife analyze` job. Not built in v0.1 but the architecture
supports it; each collector accepts a single source / project / org as
input.

### Local laptop one-off

For "is my own account a mess?" auditing, just run the CLI locally
against a sandbox AWS profile and your personal GitHub PAT. The
dashboard is great for this; the SQLite DB stays on disk and only
your filesystem sees it.

---

## 10. Troubleshooting

### `afterlife serve` says "DB not found"

You haven't run `init` yet, or you're running `serve` from a different
directory than where the DB lives. Either:

```bash
.venv/bin/afterlife init
# or
.venv/bin/afterlife serve --db-path /path/to/afterlife.db
```

### PDF report fails with "Cannot generate PDF"

You haven't installed the `[pdf]` extra or the system Pango. Follow
the install instructions in §1 above. The error message reproduces
them as well.

### AWS scan returns 403 on `iam:ListAttachedUserPolicies`

The IAM principal you're using doesn't have full read on IAM. The
`ReadOnlyAccess` AWS-managed policy is the simplest fix; for least
privilege, attach the exact action list in §3.1.

### GitHub rate-limited

The CLI shows a 403 with `X-RateLimit-Remaining: 0`. Wait an hour or
use a token with a higher limit. The PAT-rate-limit is 5000 req/hour;
GitHub Apps get higher quotas. Most org scans use a few hundred
requests, so this rarely fires unless you're re-running tightly in a
loop.

### Empty results for Google Workspace

If `scan idp --provider google` returns zero users:

- The service account isn't enabled for domain-wide delegation, or
- The `admin@example.com` super-admin you're impersonating doesn't have
  Directory API access, or
- The Admin SDK API isn't enabled in the GCP project.

The collector logs the HTTP error on stdout; check for 403 with
`unauthorized_client` (DWD missing) or 400 `invalid_grant` (impersonated
user not authorized).

### Dashboard 404s on `/openapi.json`

This is intentional. The dashboard disables FastAPI's docs / redoc /
openapi endpoints to minimize introspection surface. Use the templates
under `src/afterlife/web/templates/` if you need to understand the API.

### `analyze` produces 21 findings the first time and 42 the second

You're not on the latest code. Pull master; the
`registry.run_all` function now clears the prior findings table before
inserting, so re-running `analyze` is idempotent.

---

## 11. FAQ

### Does Afterlife make any changes to my systems?

No. Every collector is read-only. No `delete`, no `disable`, no
`revoke`. Afterlife is a detective control; remediation is whatever
your team decides to do with the findings.

### What data does Afterlife store?

A SQLite file on the machine running the CLI. The schema is:

- `identities`: source-system view of a person (email, name, status,
  metadata blob).
- `credentials`: an access key / token / deploy key / SA key.
- `findings`: detection results with evidence.
- `scan_runs`: when each collector last ran.

No secrets, ever. Vault tokens / API keys / passwords are used to call
APIs but never written to the DB.

### Can I add my own detection rule?

Yes. Drop a file in `src/afterlife/rules/` with a function decorated
by `@rule(...)`. The function takes `(conn, config, graph)` and
returns `list[Finding]`. The rule registry auto-discovers it; no
central list to update. See any of the existing rules for the
pattern; `unused_credential.py` is the simplest.

### How does the identity graph work?

In short: identities from different systems are linked into a single
"person" by (1) shared lowercased email, and (2) HashiCorp Vault
aliases. Rules can then ask "is this credential's owner deprovisioned
in any linked system?" rather than "is this credential's direct owner
deprovisioned in its own system?". See
[docs/blog/the-graph-layer.md](blog/the-graph-layer.md) for the design
essay.

### Why doesn't ORPHANED-GITHUB / STALE-OAUTH / PRIVILEGE-DRIFT fire?

They're planned rules. Placeholders for work that requires data
sources we don't collect yet. See
[docs/DETECTIONS.md#planned](DETECTIONS.md#planned) for what data each
would need.

### Why dashboard runs only on localhost?

The dashboard has no authentication. Binding to `0.0.0.0` exposes
unauthenticated read access to your security findings on the local
network. If you want shared access, put it behind an authenticated
reverse proxy (Tailscale, Cloudflare Access, an ngrok with HTTP basic
auth, etc.).

### Is `afterlife.db` safe to commit?

No. Add `*.db` to `.gitignore`. The DB doesn't contain secrets but it
does contain your inventory of users, credentials, and findings. The
included `.gitignore` already covers `*.db`.

### How do I delete old findings?

`analyze` already replaces the findings table on each run, so old
findings are not retained. If you want historical snapshots, dump the
DB to a dated file before each analyze run:

```bash
cp afterlife.db "snapshots/afterlife-$(date +%F).db"
.venv/bin/afterlife analyze
```
