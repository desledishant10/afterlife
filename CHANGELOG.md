# Changelog

Notable changes to Afterlife, newest first. Each entry maps roughly to one
or two commits and one or two of the milestones below.

## Unreleased

## v0.3.1 (September 2026)

First PyPI release: `pip install afterlife-audit` is now live. Also ships offline
license revocation, the Get Pro call-to-action, license-key backup tooling, and a
marketing landing page.

### Distribution

- Published to PyPI: `pip install afterlife-audit` installs the CLI. The release
  workflow's PyPI job publishes via trusted publishing (OIDC, no stored API token)
- New landing page under `site/`, deployed to GitHub Pages by
  `.github/workflows/pages.yml` (serves only `site/`, keeping the internal docs
  off the public marketing URL)

### Commercial

- Free users now see a "Get Pro" call-to-action with the founding price
  (from $990/year) and a contact address, in both the README Editions section
  and the `afterlife license` output. Price/contact live as `PRO_PRICE` /
  `PRO_CONTACT` in `licensing.py`
- Licenses are now individually revocable. Every minted token carries a unique
  `jti` (printed by `issue_license.py`), and the verifier rejects any jti in a
  baked-in `_REVOKED_JTIS` set (revoke via release) or in the deployer-side
  `AFTERLIFE_LICENSE_DENYLIST` / `_FILE`. This is an offline kill switch for a
  leaked or refunded license that, unlike key rotation, leaves every other
  license working. Tokens minted before `jti` still verify. See
  [docs/KEY-MANAGEMENT.md](docs/KEY-MANAGEMENT.md#revoking-a-single-license)

### Operations

- `scripts/key_backup.sh` and `docs/KEY-MANAGEMENT.md`: back up, restore, and
  verify the irreplaceable license-signing private key. The backup encrypts with
  an operator-chosen passphrase (age/gpg/openssl) and round-trips it; `verify`
  confirms the key matches the embedded `VENDOR_PUBLIC_KEY`. Also tightened the
  key file to mode 600

## v0.3.0 (September 2026)

Deepens detection and sharpens the low-ops path. Adds a CloudTrail
usage-enrichment collector and folds its ground-truth usage into
PRIVILEGE-DRIFT, ships five new rules (STALE-OAUTH, ORPHANED-GITHUB,
PRIVILEGE-DRIFT, PUBLIC-ROLE-TRUST, USER-WITHOUT-MFA), a Trends dashboard, and
two Pro features (SSO/OIDC, Jira). 16 detection rules, 380+ tests.

### Collectors

- New **CloudTrail** usage-enrichment collector (`afterlife scan cloudtrail`):
  reads recent CloudTrail events and attaches observed last-use and
  used-services (`metadata.observed_services`) to the AWS credentials, advancing
  `last_used_at` to real activity. Adds no identities; run it after `scan aws`.
  It sharpens the usage-based rules with audit-log ground truth and is opt-in
  in `run`/`watch` (not auto-detected)

### Automation

- `run`/`watch` now reorder enrichment sources (cloudtrail) to run last, so a
  config that lists cloudtrail before aws no longer silently enriches nothing;
  the reference config and the weekly GitHub Action run `scan cloudtrail` after
  `scan aws`
- The weekly scheduled audit is now gated behind `AFTERLIFE_SCAN_ENABLED`, so it
  skips (instead of failing red on a timer) until the owner wires up credentials

### Dashboard

- New **Trends** page: charts finding history from the lifecycle timestamps
  (`first_seen` / `resolved_at`) -- open findings over time by severity, the
  new-vs-resolved flow per period, and headline stats (open now, seen ever,
  resolved, median days to resolve). Rendered server-side as CSS bars, so it
  stays within the dashboard's strict CSP with no charting dependency

### Detection

- New rule **STALE-OAUTH** (High): an active third-party OAuth grant with a
  write-tier scope unused for `oauth_stale_days` (default 90). The Google
  Workspace collector now ingests OAuth grants (from the Directory tokens API)
  as `oauth_grant` credentials, so grants are inventoried and OFFBOARDED-OWNER
  covers grants whose owner has left; full staleness detection needs a source
  that reports OAuth usage timestamps
- New rule **ORPHANED-GITHUB** (High): an active GitHub personal access token
  whose owning login is no longer a member or outside collaborator of the org.
  The GitHub collector now ingests PATs as `github_pat` credentials from the
  Enterprise SAML SSO credential-authorizations endpoint (best-effort; a
  non-Enterprise org simply yields none)
- New rule **PRIVILEGE-DRIFT** (Medium): an active IAM role granted access to
  far more AWS services than it uses. The AWS collector attaches per-service
  last-use from IAM Access Advisor to each role (best-effort). This was the
  last rule in the Planned section, which is now empty
- **PRIVILEGE-DRIFT** now folds in CloudTrail's observed usage when the
  cloudtrail collector has run: a granted service counts as used if either
  Access Advisor or CloudTrail saw it within the window (the more recent wins),
  cutting false positives where Access Advisor's last-accessed lags real
  activity. Findings carry `evidence.cloudtrail_refined`
- New rule **PUBLIC-ROLE-TRUST** (Critical): an IAM role assumable by any AWS
  principal via a wildcard `Principal` (`*`, `AWS: "*"`, or `arn:aws:iam::*:root`)
  with no restricting condition. CROSS-ACCOUNT-TRUST deliberately skips these
  wildcard forms, so they were silently passed before. Stays quiet when a
  condition constrains who may assume (`aws:PrincipalOrgID`, `sts:ExternalId`, ...)
- New rule **USER-WITHOUT-MFA** (Medium): an active non-admin identity (Google
  Workspace today) with no 2-step verification, the non-admin counterpart to
  ADMIN-WITHOUT-MFA. The Snowflake-2024 credential-stuffing pattern targeted
  exactly this population

### Pro features

- Jira ticketing integration: `afterlife analyze --notify` files a remediation
  issue for new and reopened findings when the license grants it;
  configured-but-unlicensed channels are reported with an upsell
- Single sign-on (OIDC) for the dashboard: `afterlife serve --sso` runs the
  OpenID Connect Authorization Code + PKCE flow against any standards-compliant
  provider (Google, Okta, Entra, Auth0, Keycloak), with state/nonce, strict
  id_token validation, signed session cookies, an optional email/domain
  allow-list, and open-redirect protection. httpx + pyjwt only, no new
  dependency

## v0.2.0 (September 2026)

Turns the v0.1 auditor into a continuously-monitoring, installable, self-hostable
product with an open-core commercial tier.

### Project foundation

- Developer CI (ruff + mypy + pytest on Python 3.11 and 3.12) on every push
  and pull request
- PyPI packaging as `afterlife-audit` with a Trusted-Publishing release
  workflow (the import package and `afterlife` command are unchanged)
- `CONTRIBUTING`, `SECURITY`, `CODE_OF_CONDUCT`, issue and PR templates
- `afterlife --version`; `make lint` / `typecheck` / `check`

### Continuous monitoring

- Findings are tracked across runs by a stable fingerprint and carry a
  lifecycle (open / resolved) with first-seen, last-seen, and resolved-at
- `analyze` reconciles against history instead of wiping, and reports the
  since-last-scan delta (new / reopened / resolved)
- Reports and the dashboard show open findings by default; the dashboard adds
  a status filter, a "new" badge, and per-finding first/last-seen

### Alerting

- `afterlife analyze --notify` sends new and reopened findings (at or above a
  severity threshold) to Slack, a generic webhook, and/or email over SMTP
- Channels and the threshold are configured via environment variables and are
  never persisted

### Deployability & continuous mode

- `afterlife run` executes the full pipeline once (scan configured sources,
  analyze, notify) and `afterlife watch` repeats it on an interval; both
  self-initialize the database and skip sources that are not configured
- Declarative run config (`afterlife.example.yml`) for the source list,
  cadence, and notification toggle
- Dockerfile (non-root, `/data` volume) for self-hosted, scheduled operation

### Commercial layer (open core)

- Offline license verification: a Pro license is an Ed25519-signed token
  (JWT/EdDSA) checked locally against an embedded public key -- no license
  server, nothing phones home
- `afterlife license` shows the current edition; licenses activate via
  `AFTERLIFE_LICENSE` or `AFTERLIFE_LICENSE_FILE`
- First Pro-gated feature: dashboard authentication
  (`afterlife serve --require-auth`), Basic-auth password protection so the
  dashboard can be exposed to a team; refused with an upsell on the free tier
- `scripts/issue_license.py` mints licenses vendor-side (private key never
  committed)

## v0.1 (May 2026)

Initial public-ready cut. Nine source systems, eleven detection rules,
identity-graph linking via email + Vault aliases, four report formats,
local web dashboard, allowlist/suppression, scan-run history, CI workflow.

### Source systems

- **AWS IAM**: users, access keys (with attached and inline policy
  enrichment), roles (with trust policies for CROSS-ACCOUNT-TRUST), STS
  caller identity for own-account detection
- **GCP IAM**: service accounts and user-managed keys
- **GitHub**: org members, outside collaborators, App installations,
  per-repo deploy keys
- **GitLab**: group members (with inheritance), per-project deploy keys
- **Google Workspace**: users, admin flag, 2-step verification state,
  last-login timestamp
- **Microsoft Entra ID (Azure)**: users via Microsoft Graph
- **Okta**: users with status mapping
- **Slack**: workspace members, admins, bots, guests, deleted
- **HashiCorp Vault**: entities with cross-system aliases (drives
  graph linking)

### Detection rules

Critical: OFFBOARDED-OWNER, CROSS-ACCOUNT-TRUST, ADMIN-CONCENTRATION,
ADMIN-WITHOUT-MFA. High: UNUSED-CREDENTIAL, STALE-DEPLOY-KEY-WRITE,
OUTSIDE-COLLAB-WITH-AWS, INACTIVE-ADMIN. Medium: UNROTATED-KEY,
NEVER-USED. Low: ORPHANED-IDENTITY.

### Other

- Identity graph with email + Vault-alias linking (NetworkX backed)
- Blast-radius scoring with explainable factors
- Allowlist / suppression via YAML
- Scan-run tracking with `/scan-history` page
- Per-finding acknowledge with localStorage
- Report formats: JSON, HTML, SARIF, PDF
- Web dashboard: 8 pages, HTMX live filtering, dark mode, keyboard
  shortcuts, copy-to-clipboard, print stylesheet
- Strict security headers (CSP, X-Frame-Options, COOP, etc.), disabled
  OpenAPI/docs surface
- Self-contained demo running every collector against in-memory mocks

## Milestones in order

The commit-by-commit narrative, useful for talking through the project's
evolution in interviews. Each milestone is a single commit (or a tightly
coupled pair).

1. **Initial scaffold.** Typer CLI, SQLite schema with `identities` /
   `credentials` / `findings`, decorator-based rule registry, the first two
   rules (OFFBOARDED-OWNER + UNUSED-CREDENTIAL), seven tests.

2. **AWS IAM collector.** Full `boto3` enumeration with `moto`-backed
   tests. Roles modeled as ownerless credentials.

3. **NEVER-USED + UNROTATED-KEY.** Two more rules using AWS-only data, so
   `scan aws -> analyze` produces real findings.

4. **Zero-setup demo with Makefile.** `make demo` runs moto + freezegun
   in-process, plants deterministic stale credentials, and writes a
   self-contained HTML report. `make demo` becomes the project's first
   demo-able artifact.

5. **GitHub collector + NEVER-USED hardening.** httpx + respx for HTTP
   mocking, App installations + deploy keys. NEVER-USED gains a
   types-without-usage-signal exclusion so it doesn't false-positive on
   types we can't observe.

6. **Identity graph + `afterlife identities`.** NetworkX-backed graph
   linking identities across sources by lowercased email. CLI command
   prints the person view.

7. **OFFBOARDED-OWNER graph-aware.** Rule signature refactored to
   `(conn, config, graph)`. OFFBOARDED-OWNER walks the same-person graph
   so a Google-deprovisioned user fires on her AWS keys, even though the
   AWS user shows `status=active` locally. This is the Uber-2022 case
   working end-to-end.

8. **Demo extended with GitHub data.** respx mocks alongside moto. Demo
   identity graph reaches 5 cross-source persons.

9. **Google Workspace collector.** OAuth 2.0 client-credentials with
   PyJWT-signed assertions, all over httpx (no `google-auth`).
   OFFBOARDED-OWNER finally fires in the demo against bob and carol.

10. **Em-dash cleanup.** 57 em dashes replaced with commas / colons /
    parentheses across 18 files. User preference; kept in memory.

11. **HTML report.** Self-contained file with severity tiles, expandable
    findings, identity graph. Demo writes one automatically.

12. **Okta collector.** Fourth source system. SSWS auth, Link-header pagination. Status map
    handles Okta's wider vocabulary (STAGED, LOCKED_OUT, etc.).

13. **SARIF report + GitHub Action workflow.** SARIF 2.1.0 output usable
    by Code Scanning. Workflow template assumes AWS OIDC.

14. **Blast-radius scoring.** Each finding gets a (score, factors) pair.
    Type prior plus elevated/read-only scope detection, with admin-flag
    bump. AWS collector enriched with attached policy names so
    AdministratorAccess actually shows up. Findings sort by
    (severity, -blast_score) within tiers.

15. **Local web dashboard.** FastAPI + Jinja2 + a sprinkle of vanilla JS.
    Three pages: overview, findings, identities.

16. **Dashboard hardening.** Security-headers middleware (CSP,
    X-Frame-Options, COOP/CORP, etc.). FastAPI docs/redoc/openapi
    endpoints disabled. CSS moved to a static file. HTMX bundled
    self-hosted. Dark mode via `prefers-color-scheme`.

17. **Dashboard detail pages + HTMX live filter + charts.** Finding /
    credential / person detail pages, all cross-linked. Global search +
    debounced HTMX swaps. Server-rendered bar charts on the overview.

18. **Dashboard polish.** Keyboard shortcuts (`/` `?` `g h/f/c/i` `Esc`),
    copy-to-clipboard on every `<pre>`, help modal, print stylesheet,
    sticky nav, hover lifts.

19. **3 more rules.** ORPHANED-IDENTITY (low), OUTSIDE-COLLAB-WITH-AWS
    (high), ADMIN-WITHOUT-MFA (critical). Google Workspace collector
    captures `isEnforcedIn2Sv`.

20. **Allowlist / suppression.** YAML config, `until` expiry, dashboard
    toggle to show suppressed.

21. **Scan-run tracking + `/scan-history`.** Every scan invocation is
    wrapped in a `record_run` context manager that writes started_at /
    finished_at / records_collected / error to a new `scan_runs` table.
    Overview surfaces last-scan-per-source.

22. **PDF export.** `report --format pdf -o report.pdf` via weasyprint
    in an optional `[pdf]` extra. Lazy import with actionable error
    message when system deps are missing.

23. **Per-finding Acknowledge.** Vanilla-JS button persisting state in
    `localStorage`. Survives HTMX swaps.

24. **Sortable tables.** Findings sort dropdown, credentials clickable
    column headers with `↑/↓` indicator. URL-driven, HTMX-friendly.

25. **INACTIVE-ADMIN rule.** Admin without recent login (default 30d).

26. **CROSS-ACCOUNT-TRUST.** AWS collector enriched with role trust
    policies + own-account-id via STS. Rule walks each role's policy
    statements and fires on foreign `Principal.AWS` ARNs.

27. **Microsoft Entra ID collector.** Fifth source system. Microsoft
    Graph OAuth 2.0 client-credentials flow.

28. **GitLab collector.** Sixth source system. PAT auth, group members,
    project deploy keys.

29. **ADMIN-CONCENTRATION.** Same person admin in 2+ systems
    (IdP `is_admin` + AWS AdministratorAccess + Slack admin / owner).

30. **STALE-DEPLOY-KEY-WRITE.** Focused subset of UNUSED-CREDENTIAL for
    push-capable deploy keys.

31. **GCP IAM collector.** Seventh source system. Service accounts and
    user-managed keys. UNROTATED-KEY extended to cover GCP keys.

32. **Slack collector.** Eighth source system. workspace members,
    bots, admins, guests, deleted.

33. **Vault collector.** Ninth source system. Entities + aliases. The
    identity graph gains alias-based linking, so a Vault entity bridges
    AWS + GitHub without needing a shared email.
