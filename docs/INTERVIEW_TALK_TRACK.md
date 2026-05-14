# Interview talk track

Practiced answers for "tell me about a project" and the technical follow-ups
you can expect. Calibrated for cybersecurity-focused and platform/backend
roles.

## The 30-second version (anywhere)

> Afterlife is a ghost-access auditor I built to detect credentials that
> outlive their owners. It pulls identities and credentials from eight
> systems (AWS, GCP, GitHub, GitLab, Google Workspace, Microsoft Entra,
> Okta, Slack, Vault), builds a cross-source identity graph, and runs
> eleven detection rules over it. The marquee detection is OFFBOARDED-OWNER,
> which catches the Uber 2022 pattern: an active AWS access key whose
> owner is suspended in the IdP. The graph layer is what makes this work;
> without joining the two views, you miss the link.

## The 90-second version (technical interviews)

> The core problem is that credentials and identities live in different
> systems with different APIs, different status vocabularies, and no shared
> ID. So I built an identity-graph layer that links source-system
> identities by lowercased email and, where available, by HashiCorp Vault's
> aliases, which are the only thing in the wild that explicitly says "this
> Vault entity is also this AWS ARN."
>
> On top of the graph there's a decorator-based rule registry. Each rule
> takes `(conn, config, graph)` and returns findings. The marquee rule,
> OFFBOARDED-OWNER, walks the graph from a credential's direct owner to
> all linked identities and fires if any of them have a deprovisioned
> status. So if Alice is suspended in Google Workspace but her AWS IAM
> user is still active, her AWS access keys fire as critical.
>
> Findings get a blast-radius score based on the credential's type and
> attached scopes. An AWS key with `AdministratorAccess` scores 0.85, a
> read-only deploy key scores 0.20. The score isn't used to filter; it's
> used to break ties within a severity tier and to give reviewers a
> "this one first" signal.
>
> Output is JSON, HTML, SARIF, or PDF. The SARIF path means the same
> findings flow into GitHub Code Scanning via a ready-to-adapt workflow.
> There's also a local FastAPI dashboard for browsing interactively.
>
> The whole thing has 250+ tests, in-process mocks for every collector,
> and a `make demo` that exercises the full pipeline in 30 seconds with
> no external setup.

## Angle: cybersecurity / IAM focus

When the interview is about security:

- **Lead with the breach narratives.** OFFBOARDED-OWNER ↔ Uber 2022.
  CROSS-ACCOUNT-TRUST ↔ Capital One 2019. ADMIN-CONCENTRATION ↔ Reddit
  2023 (employee-phishing → source-code-pull). These are the stories
  recruiters already know.
- **Talk about what's intentionally hard.** Stress that the rule logic
  is the easy part. The hard part is the cross-source identity graph,
  because every system has its own status vocabulary (Google
  `suspended/archived`, Okta `SUSPENDED/DEPROVISIONED/LOCKED_OUT`, GitLab
  `blocked/deactivated/banned`, Slack `deleted`, etc.) and you have to
  normalize them before any rule can work.
- **Discuss false positives explicitly.** Every rule's documentation has
  a "false positives" section. Be ready to explain why
  OUTSIDE-COLLAB-WITH-AWS deliberately fires once per credential rather
  than once per person, and why NEVER-USED excludes credential types
  whose source system doesn't publish a usable last-used signal.

Likely follow-ups:

- **"How would you handle Okta's MFA model?"** Okta's MFA enforcement
  lives in policies and conditional-access rules, not on the user
  object. So I'd need a separate collector call to enumerate
  group/factor bindings and then join them. That's the kind of work that
  gets disproportionately expensive to add late, which is why I focused
  on Google Workspace where the signal is per-user.

- **"What does blast-radius scoring actually catch?"** It catches the
  case where two findings have the same severity but very different
  real-world impact: an OFFBOARDED-OWNER on bob's admin AWS key
  (score 0.85 → broad) deserves attention before an OFFBOARDED-OWNER on
  a read-only deploy key (score 0.20 → limited). Severity alone wouldn't
  tier them.

- **"How would you scale this to a large org?"** Two answers depending on
  what they want to hear. Engineering answer: collectors are independent
  processes you'd run on a cron with their results written to a shared
  DB; the rules engine is pure compute that runs offline. Product
  answer: you don't want to scan everything every hour; you want delta
  scans triggered by IdP webhooks (offboarding events); that's where the
  real signal is.

## Angle: backend / platform engineering focus

When the interview is about engineering quality:

- **Lead with the boundaries.** Collectors are dumb, rules are dumb-er.
  Each layer can be swapped without touching the next. Talk about how
  the rule signature became `(conn, config, graph)` deliberately, so the
  identity-graph layer could be added later without rewriting every rule.
- **Talk about explainability.** Blast-radius scores aren't just numbers,
  they include a `factors` list. Every score can be traced back to which
  signals contributed. That matters in security because reviewers need
  to argue with the tool.
- **Demonstrate test pragmatism.** moto for AWS, respx for httpx, real
  RSA key generation for the OAuth JWT signing test, FastAPI TestClient
  for the dashboard, freezegun + monkey-patching of moto's internal
  state for the demo. The test suite is the docs.

Likely follow-ups:

- **"Walk me through a rule."** Pick OFFBOARDED-OWNER. Show how it
  queries credentials, looks up `person_for(owner_source, owner_id)` on
  the graph, walks all linked identities, and fires when any one is in
  the deprovisioned set. Then mention the case-insensitive status check
  for Okta's UPPERCASE statuses vs Google's lowercase.

- **"Why a rule registry instead of a flat module?"** Decorator-based
  registry means new rules drop into one file and are auto-discovered.
  No central list to update. The `Rule` dataclass carries metadata
  (severity, title, description) used by the dashboard and the SARIF
  driver advertisement without duplication.

- **"How do you handle schema migrations?"** Migrations are best-effort
  ALTER TABLE in `db._migrate`. Each new column has its own `if "col"
  not in cols: ALTER TABLE...` line. Fine for v0.1; long-term I'd move
  to a real migration tool like Alembic.

## Angle: full-stack / product engineering focus

When the interview emphasizes UI / breadth:

- **Lead with the dashboard.** Three commits to get from "renders three
  pages" to "filterable, sortable, searchable, with detail pages,
  acknowledgeable, with security headers, with dark mode, with a print
  stylesheet." Every layer was added intentionally, not by accident.
- **Talk about HTMX as a deliberate choice.** No build step, no JS
  framework, server-rendered HTML by default. Live filtering is just
  `hx-get` + `hx-target` with the server returning a partial when
  `HX-Request: true` is set. The whole dashboard is ~1500 lines of
  Python and ~700 lines of HTML/CSS/JS.
- **Show the security thinking.** Even though it's localhost-only, the
  dashboard has strict CSP, disabled introspection endpoints, and an
  XSS regression test. Defense-in-depth as a habit, not a feature.

Likely follow-ups:

- **"Why localStorage for ack instead of a server field?"** Because the
  server is read-only and that's a deliberate design choice. ack is
  per-reviewer, not a property of the finding. Persisting it server-side
  would require auth, which would require sessions, which would require
  the dashboard to write, and that's a much larger security surface for
  a feature that's purely UI.

- **"Why server-rendered SVG instead of Chart.js?"** No JS dep, zero
  runtime cost, the print stylesheet just works. The charts are also
  trivial (two-bar distributions); a real charting library would be
  overkill.

## What you learned (the personal-growth answer)

Three things, in order of how interviewers tend to value them:

1. **Designing for explainability.** Every output the tool produces has
   to justify itself: blast-radius `factors`, rule descriptions
   embedded in SARIF, the dashboard showing which identity in which
   system has which status. Security tools that just say "this is bad"
   without showing why are tools nobody trusts.

2. **Drawing layer boundaries before they're needed.** Splitting
   collector / store / graph / rule / report on day one meant I could
   add Vault's alias-based linking by touching exactly two files (the
   collector and the graph). If those had been one layer, Vault would
   have meant rewriting every rule.

3. **Treating false-positive notes as first-class documentation.**
   Every rule has a "false positives" section. That's the difference
   between a tool a security team will actually adopt and one they'll
   silently turn off.

## What you'd do next (the forward-looking answer)

In order of value:

1. **PRIVILEGE-DRIFT.** Needs CloudTrail data. The highest-value rule we
   haven't built. Real security teams cite "over-privilege" as the
   single biggest cloud risk surface; this is the rule that quantifies
   it.

2. **A delta-scan mode triggered by IdP webhooks.** Run the full pipeline
   in seconds when an offboarding happens, not on a weekly cron. The
   offboarding-to-credential-revocation window is where the breaches
   happen.

3. **Multi-tenancy.** Right now the dashboard is single-org. For real
   internal-tooling deployment, you'd want each org to have its own
   isolated DB + auth + role-based access. Maybe 5 commits.

4. **A public dataset.** Anonymize a real run and ship the JSON output
   as a research dataset. Useful for ML-based anomaly detection
   research; also a strong portfolio artifact in its own right.
