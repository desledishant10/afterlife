# Changelog

Notable changes to Afterlife, newest first. Each entry maps roughly to one
or two commits and one or two of the milestones below.

## v0.1 (May 2026)

Initial public-ready cut. Eight source systems, eleven detection rules,
identity-graph linking via email + Vault aliases, four report formats,
local web dashboard, allowlist/suppression, scan-run history, CI workflow.

### Source systems

- **AWS IAM** — users, access keys (with attached and inline policy
  enrichment), roles (with trust policies for CROSS-ACCOUNT-TRUST), STS
  caller identity for own-account detection
- **GCP IAM** — service accounts and user-managed keys
- **GitHub** — org members, outside collaborators, App installations,
  per-repo deploy keys
- **GitLab** — group members (with inheritance), per-project deploy keys
- **Google Workspace** — users, admin flag, 2-step verification state,
  last-login timestamp
- **Microsoft Entra ID (Azure)** — users via Microsoft Graph
- **Okta** — users with status mapping
- **Slack** — workspace members, admins, bots, guests, deleted
- **HashiCorp Vault** — entities with cross-system aliases (drives
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
- Web dashboard: 7 pages, HTMX live filtering, dark mode, keyboard
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

12. **Okta collector.** SSWS auth, Link-header pagination. Status map
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

27. **Microsoft Entra ID collector.** Fourth source system. Microsoft
    Graph OAuth 2.0 client-credentials flow.

28. **GitLab collector.** Fifth source system. PAT auth, group members,
    project deploy keys.

29. **ADMIN-CONCENTRATION.** Same person admin in 2+ systems
    (IdP `is_admin` + AWS AdministratorAccess + Slack admin / owner).

30. **STALE-DEPLOY-KEY-WRITE.** Focused subset of UNUSED-CREDENTIAL for
    push-capable deploy keys.

31. **GCP IAM collector.** Sixth source system. Service accounts and
    user-managed keys. UNROTATED-KEY extended to cover GCP keys.

32. **Slack collector.** Seventh source system. workspace members,
    bots, admins, guests, deleted.

33. **Vault collector.** Eighth source system. Entities + aliases. The
    identity graph gains alias-based linking, so a Vault entity bridges
    AWS + GitHub without needing a shared email.
