# Afterlife: Go-to-Market

> Strategy draft, 2026-09. A living document, not a contract: revisit each
> section as real signal (stars, installs, sales conversations) comes in.
>
> **Reconciled 2026-09-02 to the shipped product (v0.3.0, 16 rules).** Facts,
> version labels, and shipped-vs-roadmap status were corrected, and stray
> monthly price figures were aligned to the single authoritative Pricing
> section. Two changes are decisions for the founder, not edits, and are called
> out where they land:
>
> 1. **The open-core line moved.** STALE-OAUTH, PRIVILEGE-DRIFT, and the
>    CloudTrail enrichment shipped in the *free* core, not as the Pro
>    "heavier-data" rules this plan reserved them as. That is faithful to the
>    "never paywall detection" principle, but it leaves Pro as dashboard auth +
>    SSO/OIDC + Jira (all shipped). Name the replacement Pro levers before the
>    pricing page goes live: retention/trend analytics, multi-project, and
>    PagerDuty/ServiceNow are the standing candidates.
> 2. **Confirm the pricing regime.** The Pricing section is authoritative:
>    $990 founding / $1,900 list / $6,000+ Enterprise, flat per organization,
>    annual. Confirm that is current so the page and targets can be finalized.

**Product in one line.** Afterlife is the cross-source access review that your
CSPM and your IdP each do half of: it joins cloud IAM keys, code-host access,
and IdP lifecycle state into one identity graph and fires the moment a
credential is still live but the person behind it is gone. Self-hosted, so it
never holds your keys.

**Business model.** Open core. The full detection core is free forever; a
self-hosted Pro tier is unlocked by an offline, signed license key. No hosted
SaaS, no credential custody, no license server. The goal is recurring revenue
a single founder can run with minimal ops.

## TL;DR

- **Who buys it:** cloud-native Series A to C companies, roughly 50 to 500
  employees, with 5 to 15 source systems and no dedicated security team. The
  work lands on a platform lead or a security-team-of-one who cannot answer
  "who still has live access, and should they" across systems.
- **When they buy:** offboarding (a contractor rolls off, a layoff batch), a
  SOC 2 / ISO / security-questionnaire audit, or a peer-breach scare
  (Snowflake 2024, Okta 2023, Uber 2022).
- **The line:** you pay for team, scale, enterprise, and operational surface,
  never for detection quality or coverage. The core catches every ghost
  credential it can, free, forever.
- **Price:** a single flat per-organization annual license. Launch at a
  **$990/year founding rate** (price locked for life, first 50 organizations)
  while the Pro set is still landing; raise the list to **$1,900/year** once
  SSO plus one advanced rule ship. A hand-quoted **Enterprise floor from
  $6,000**, inbound only. Billing through a merchant of record so the only
  recurring task is a one-command license mint.
- **Launch move:** ship to PyPI, publish two breach-teardown posts, then a
  Show HN plus r/netsec plus security-newsletter push anchored on the
  offboarded-owner narrative. Convert stars to the first paying customer via
  the founding license.

## Contents

1. [Positioning and ideal customer](#positioning-and-ideal-customer)
2. [Free vs Pro (the open-core line)](#free-vs-pro-the-open-core-line)
3. [Pricing](#pricing)
4. [Launch plan](#launch-plan)
5. [Ongoing demand generation](#ongoing-demand-generation)
6. [Metrics, targets, and low-ops fulfillment](#metrics-targets-and-low-ops-fulfillment)
7. [Appendix: pricing models considered](#appendix-pricing-models-considered)

## Positioning and ideal customer

### One-line positioning

Afterlife finds the credentials that outlived their owners: it joins your cloud IAM keys, code-host access, and IdP lifecycle state into one identity graph and fires the moment a credential is still live but the person behind it is gone. It is the cross-source access review your CSPM and your IdP each do half of, self-hosted so it never holds your keys.

### Ideal customer profile

The company that buys Afterlife has outgrown "we know everyone here" but has not bought a dedicated identity-governance suite. Concretely:

- **Company type and stage.** Series A through C startups and scale-ups, roughly 50 to 500 employees, cloud-native, that ship on AWS or GCP, host code on GitHub or GitLab, and run an IdP (Google Workspace, Okta, or Entra). Security-conscious verticals (fintech, healthtech, dev-tools, infra) feel this first because they carry contractors and a SOC 2 obligation early.
- **The team.** There is rarely a "security team." The work lands on a platform or DevOps lead, a founding security engineer, or a head-of-security-of-one who also owns IAM, on-call, and the audit. They have five to fifteen source systems and no single place that answers "who still has live access, and should they."
- **The pain that makes them buy now.** They cannot answer that question across systems without a spreadsheet and a bad afternoon. AWS says an access key is active; nobody remembers it belongs to a contractor Okta suspended eight months ago. Offboarding is a manual checklist that silently misses the third and fourth systems a person touched. Each new cloud account, repo, and SaaS grant widens the gap. Afterlife turns that afternoon into one `afterlife run` and a ranked list.

They are not the buyer for hosted ITDR: too small for the price, too protective of their cloud keys to hand them to a SaaS vendor, and specifically shopping for the ghost-access answer rather than a platform.

### Trigger events

Adoption is event-driven, not budget-cycle-driven. The three that convert:

- **Offboarding.** A contractor rolls off, an employee resigns, or a layoff or RIF deprovisions a batch at once. This is the sharpest trigger: the offboarder wants proof that nothing live was left behind, and Afterlife's `OFFBOARDED-OWNER` rule is built for exactly this moment.
- **An audit or a questionnaire.** SOC 2 Type II access reviews, ISO 27001, or a prospect's security questionnaire demands evidence of who has access to what. Afterlife's HTML and PDF reports and the cross-source identity view become the artifact you attach.
- **A peer-breach scare.** Snowflake 2024, Okta 2023, and Uber 2022 were all some form of a live credential behind an absent or compromised owner. When one lands in the news or hits a company in their network, the founder or CTO asks "are we exposed to this?" and Afterlife is the fastest honest answer.

### Buyer versus user

- **User.** The platform or security engineer who runs the scans, reads findings, wires `afterlife report --format sarif` into CI, and lives in the dashboard. The entire free core is aimed at this person, and they are who adopts Afterlife building-in-public, off a README and `make demo`.
- **Buyer.** For a Pro license it is the engineering manager, head of security, or CTO who wants to expose the dashboard to the team behind auth (today's Pro feature), or wants the advanced rules, retention, and support on the roadmap. At this company size the buyer and user are often the same person, which is the point: Pro is a self-serve license key from a storefront (LemonSqueezy, Polar, or Gumroad), not an enterprise sales motion. That keeps the founder's ops and support burden low and the revenue recurring.

### Alternatives Afterlife displaces, and the gap it fills

Prospects are already running something. What they are running does one of two halves, never the join:

- **Prowler, ScoutSuite (free CSPM scanners).** Excellent at benchmarking one cloud's configuration. They will flag an unrotated AWS key, but they live entirely inside AWS (or one cloud at a time) and have no concept of the IdP, so they can never say "this key's owner was suspended in Okta." Afterlife consumes the same signal and adds the cross-source correlation they structurally cannot do.
- **CloudQuery, Steampipe (infra-as-SQL).** They give you the raw asset inventory across providers as queryable tables, which is a data layer, not a detection product. To catch ghost access you would write and maintain the cross-source join, the identity graph, and the blast ranking yourself. Afterlife is that join, opinionated and shipped.
- **Cartography (Lyft's asset graph, Neo4j).** Closest in spirit, a graph of infrastructure relationships. But it is a general-purpose graph you query yourself, heavier to stand up, and not focused on the offboarded-owner class or on ranking findings by blast radius out of the box. Afterlife is narrow on purpose: the ghost-access class, scored and remediated.
- **Push Security, Nudge Security, Oort / Cisco Identity Intelligence, Vanta-adjacent (commercial ITDR / ISPM / compliance).** These are hosted SaaS that center on the IdP and SaaS-sprawl layer (OAuth grants, shadow SaaS, identity threat signals) or on compliance evidence. They take custody or require broad OAuth, they price at enterprise levels, and they largely stop at the identity plane rather than joining it down to cloud IAM credentials. Afterlife covers the specific seam they leave open, at a self-hosted price and ops footprint a 200-person company adopts in an afternoon.

**The specific gap:** every one of these is single-source (one cloud, one IdP, one SaaS plane) or a raw data layer. None ships the cross-source join that catches a credential active in AWS but dead in the IdP. That offboarded-owner correlation is the whole product.

### Sharpest differentiator

Afterlife is the only tool that joins your cloud IAM keys to your IdP's lifecycle state and alerts when a credential is still live but its owner has been offboarded, and it runs entirely self-hosted so it never holds your keys.

## Free vs Pro (the open-core line)

The single rule that governs every future packaging decision: **you pay for team, scale, enterprise, and operational surface, never for detection quality or coverage.** A solo analyst auditing one org should be able to run Afterlife forever, catch every ghost credential it is capable of catching, and never hit a paywall. The cross-source detection is the reason the tool exists and the reason it earns trust in public; charging for it would gut both the wedge and the portfolio story.

### The principle

Everything through the current core stays free forever: all 9 collectors, the cross-source identity graph, all 16 shipped detection rules, blast-radius scoring, monitoring with finding history (new / reopened / resolved, first-seen / last-seen), alerting (Slack, webhook, email), `run` / `watch` continuous mode, Docker, all four report formats (JSON, HTML, SARIF, PDF), and the local read-only dashboard. Free is the full audit, not a teaser.

A feature is only eligible for Pro if it passes one of three tests:

1. **Team / enterprise.** It exists because more than one human, or a security or compliance function, shares the tool (dashboard auth, SSO, ticketing integrations, a support SLA).
2. **Scale.** It exists because there are many projects, accounts, or a long history to manage (multi-project, long-horizon retention and trends).
3. **Heavier data.** It requires a materially heavier new data pipeline than the free collectors. (STALE-OAUTH's OAuth-grant inventory, PRIVILEGE-DRIFT, and the CloudTrail enrichment were once reserved under this test but shipped in the free core instead; see the reconciliation note at the top.) Anything computable from data Afterlife already collects stays free.

Four anti-cripple guarantees make the line credible and are worth stating out loud in the README and the pricing page:

- The 16 shipped rules stay free forever. No new rule that runs on already-collected data will ever move behind Pro.
- No finding is ever hidden by edition. Pro never changes what the free tier detects or reports.
- No source system is paywalled. All 9 collectors are free; Pro never gates a data source.
- Alerting stays free. Turning Afterlife into a continuous monitor never costs money; only the team and scale surface around it does.

Put plainly: Pro makes Afterlife easier to run at team scale. It never makes the free tier wrong or incomplete.

### What stays free vs what is Pro

| Capability | Free | Pro |
|---|:---:|:---:|
| All 9 collectors (AWS, GCP, GitHub, GitLab, Google Workspace, Entra, Okta, Slack, Vault) | Yes | Yes |
| Cross-source identity graph (email + Vault-alias linking) | Yes | Yes |
| All 16 shipped detection rules | Yes | Yes |
| Blast-radius scoring with explainable factors | Yes | Yes |
| Monitoring + finding history (new / reopened / resolved, first / last seen) | Yes | Yes |
| Alerting: Slack, generic webhook, email (SMTP) | Yes | Yes |
| `run` / `watch` continuous mode + Docker | Yes | Yes |
| Reports: JSON, HTML, SARIF, PDF | Yes | Yes |
| Allowlist / suppression | Yes | Yes |
| Local read-only dashboard (all 8 pages) | Yes | Yes |
| Dashboard authentication (`afterlife serve --require-auth`) | No | Yes (shipped) |
| SSO / OIDC dashboard login | No | Yes (shipped) |
| Long-horizon retention + trend analytics (MTTR, burn-down) | Current state + since-last-run delta | Extended retention windows + trend views (roadmap) |
| Ticketing / on-call integrations | No | Jira (shipped); PagerDuty, ServiceNow (roadmap) |
| Multi-project / multi-config from one install | Single project | Yes (roadmap) |
| Advanced rules (STALE-OAUTH, PRIVILEGE-DRIFT) | Yes (shipped free) | Yes |
| Priority support (light SLA) | Community / issues | Yes |

### Pro roadmap: what to build after dashboard auth

> **Status update (2026-09-02):** items 1 (SSO/OIDC) and 3 (Jira) have shipped
> and are gated in `licensing.py`; item 5's advanced rules (STALE-OAUTH,
> PRIVILEGE-DRIFT) shipped in the *free* core instead. The remaining live Pro
> roadmap is retention/trend analytics, multi-project, and PagerDuty/ServiceNow.
> The ranking below is kept as the original decision trail.

Ranked by willingness-to-pay against build effort, with the solo-founder constraints (minimal build, minimal ops, recurring revenue, no credential custody) as tie-breakers.

| Pro candidate | Build effort | Willingness to pay | Ship order |
|---|---|---|:---:|
| SSO / OIDC dashboard login | Medium | High | 1 |
| Retention + trend analytics | Low | Medium-High | 2 |
| Jira / PagerDuty / ServiceNow (Jira first) | Low-Medium each | High | 3 |
| Multi-project / multi-config | Medium-High | High (MSPs, multi-account) | 4 |
| STALE-OAUTH, then PRIVILEGE-DRIFT | High | High (latent) | 5 |
| Priority support (light SLA) | Near-zero to build | Medium | ships with first paying customer |

**1. SSO / OIDC dashboard login.** Build this first because it completes the one Pro feature that already exists. Dashboard auth without SSO is only half of what a security team needs; SSO is the single most common hard gate on adopting any self-hosted tool inside a company (the well-known "SSO tax," catalogued at sso.tax). The OAuth machinery is not new territory here: the Google Workspace and Entra collectors already do OIDC-style client-credentials flows, so an Authlib-based login against the customer's own Okta / Google / Entra is medium effort, not a rewrite. Dashboard auth plus SSO together form the "team-ready" bundle that closes deals.

**2. Retention + trend analytics.** The cheapest high-value thing on the list, because the lifecycle data is already persisted (each finding carries first-seen, last-seen, resolved-at, and the new / reopened / resolved delta). Free keeps the current open set plus the since-last-run delta, which is everything a working analyst needs. Pro adds long retention windows and the trend surface on top of that plumbing: findings over 90 / 180 / 365 days, mean-time-to-remediate, per-source burn-down, historical export. Compliance and audit buyers (SOC2, board reporting) pay for the evidence trail. Low build, real pull.

**3. Ticketing / on-call integrations, Jira first.** These are the same shape as the existing `notify/` channels (Slack / webhook / email), so each is a self-contained connector, not a platform. Jira (most universal), then PagerDuty (Events API is trivial), then ServiceNow (Table API, slightly heavier). Ship and monetize after the first one lands rather than waiting for all three. High WTP because "we need it in our workflow" is the classic enterprise ask, and each connector is low-to-medium effort.

**4. Multi-project / multi-config.** Higher effort (DB scoping, dashboard routing, `run` / `watch` all need project awareness) for a narrower but well-paying audience: MSPs, security consultancies, and orgs juggling many AWS accounts or staging-vs-prod. This is the textbook "scale" feature and fits the Pro principle exactly. Build it when there is visible pull from that segment, not before.

**5. Advanced rules: STALE-OAUTH, then PRIVILEGE-DRIFT.** Highest latent value, highest effort, so they anchor the back of the roadmap. Each needs a genuinely new data pipeline: STALE-OAUTH wants per-user OAuth grant enumeration (Google tokens endpoint, Slack `admin.users.list` with apps), PRIVILEGE-DRIFT wants CloudTrail or IAM Access Analyzer usage data, which is high-volume and the widest new IAM read scope. Do STALE-OAUTH first because its data source is lighter. This is the most delicate line to draw against "never cripple the core," so the framing must be explicit: these are Pro because they require heavier data collection, not because detection is being paywalled, and the 16 existing rules never move.

**Priority support** is not an engineering item and does not compete for the build sequence. Turn it on the day Pro has its first paying customer, bundled into the price as a light SLA (for example, 2-business-day email), kept deliberately low-touch so it never becomes an on-call obligation for a solo founder.

### No credential custody, by construction

The business model forbids ever holding a customer's cloud keys, and every Pro feature above preserves that:

- **Dashboard auth**: the password hash lives in the customer's install; nothing leaves the box.
- **SSO / OIDC**: actively custody-reducing. Authentication is delegated to the customer's own IdP, so Afterlife holds no passwords at all. Configure with the customer's OIDC client secret in their environment.
- **Retention / trends**: data stays in the customer's SQLite on the `/data` volume.
- **Integrations**: safe only if the destination API token is read from the customer's environment at runtime, exactly like `AFTERLIFE_SLACK_WEBHOOK` and the SMTP settings today, and never routed through or stored by any vendor system. That discipline is the one thing to hold the line on as connectors get added.
- **Multi-project**: entirely local.
- **Advanced rules**: run against the customer's own read-only cloud / IdP credentials. PRIVILEGE-DRIFT's CloudTrail access is the widest read scope, so ship it with least-privilege IAM guidance.
- **Priority support**: no data path at all. Support runs on redacted findings and logs; customers are never asked to send their database or credentials.

The enforcement layer itself is zero-custody: a Pro license is an offline Ed25519-signed token verified locally against an embedded public key, with no license server and nothing phoning home. Even paying for Pro moves no customer data to the vendor, which is exactly the "constant money, less looking out" posture the model is built for.

## Pricing

### The recommendation, in one line

**Afterlife Pro is a single flat license, per organization, billed annually, self-hosted, delivered as the offline Ed25519 key the product already mints.** Unlimited seats, unlimited source systems, unlimited findings, every Pro feature present and future. One number, one decision.

Committed price points:

| What | Price (USD/year) | Who it is for |
|---|---|---|
| **Founding license** | **$990**, locked for the life of the subscription, first 50 organizations | The price you actually charge at launch, while the Pro set is still landing |
| **Afterlife Pro (list)** | **$1,900**, flat, per organization | The standing headline once SSO plus one advanced rule have shipped |
| **Enterprise** | **from $6,000**, quoted per deal, inbound only | The org that needs a PO, an MSA, invoicing, and a security questionnaire answered |

Everything below Enterprise is one line on the page: no per-seat math, no per-source meter, no usage band, no "contact sales."

### Why a single flat per-org license is the primary model

This is the load-bearing decision, and it falls out of two things that are already true about Afterlife.

First, the license is an offline Ed25519-signed token verified locally against an embedded public key. It cannot count seats and it never phones home. A per-seat or per-source price would force one of two bad outcomes: build a meter and a phone-home (and inherit the support tickets that come with limits), or run an honor system the buyer has to self-assess at checkout (friction, and undercounting). A flat per-org price needs no meter at all. The token already carries a customer name and an `exp` claim, and a Pro license with no explicit feature list grants every Pro feature. The pricing matches the crypto exactly: `issue_license.py --days 365`, unlock everything, count nothing. That is the "less looking out" the whole business is built around, expressed as a price.

Second, per-org is the honest shape for what Afterlife does. It is bought by a security or platform team to audit the whole company's identity surface across nine systems. Charging per seat or per source would tax exactly the teams that get the most value, the ones with the most systems to join, which is backwards for a tool whose entire wedge is the cross-source join.

Proposal 2's good-better-best ladder and Proposal 3's scale-by-identity bands both capture more value in theory, but both add ops a solo founder in a job hunt cannot afford right now: tier-gating support ("why am I on Growth"), a new `max_identities` claim and nudge banner to build, honor-system leakage to police, and, in Proposal 2's Enterprise, a named-contact plus shared-Slack plus four-business-hour SLA that is a standing support job. The flat model gives up some expansion revenue to buy near-zero ops, which is the right trade for this founder at this stage. The upside lever is recovered cheaply below.

### Why $1,900, and why $990 to launch

The list number is grounded in real self-hosted, license-key comps for dev and security teams:

| Tool | Model | Price | Read for Afterlife |
|---|---|---|---|
| Sidekiq Pro | Self-hosted key | about $1,200/yr | Closest structural match: small-team infra, flat annual key, near-zero ops |
| Sidekiq Enterprise | Self-hosted key | about $2,750/yr | Same vendor, higher tier. Afterlife sits between the two |
| Sentry Team | Self-hosted / SaaS | about $312/yr | The low anchor for a developer-tools entry price |
| GitLab Premium | Per user | $29/user/mo | About $3,480/yr for a 10-person team. Per-seat gets expensive fast |
| Snyk Team | Per contributor | about $25/contributor/mo | Security tooling per head, adds up quickly |
| Vanta / Drata | Compliance SaaS | roughly $10k to $30k+/yr | The real size of a security budget. $1,900 is noise next to it |
| Metabase Pro (self-hosted) | Seat-banded | historically near $10k/yr to start | The ceiling to avoid: that price needs a sales motion |

$1,900 lands deliberately between Sidekiq Pro and Sidekiq Enterprise. Security tooling supports higher willingness to pay than a background job queue, which argues up from Sidekiq Pro; Afterlife is early-stage and solo-maintained, with a small shipped Pro set (dashboard auth, SSO/OIDC, Jira), which argues against reaching for enterprise numbers. It clears the "is this serious" bar (a $99 tool reads as a hobby to a security team and earns no trust) and sits under the roughly $2,500 line where a purchase stops being a credit-card yes and starts triggering a PO, procurement, and a vendor questionnaire. Staying a card swipe is the entire point.

The honest launch price is lower, because today Pro is dashboard authentication plus priority support and the rest (SSO/OIDC, STALE-OAUTH, PRIVILEGE-DRIFT, Jira/PagerDuty/ServiceNow, retention and trend history, multi-project) is roadmap. Selling $1,900 against dashboard auth alone would be selling a promise at full price. So the launch offer is a **founding license at $990/year, locked for life for the first 50 organizations.** $990 is a clean sub-$1,000 card purchase, it is a real reason to buy now, it rewards early buyers who are partly funding the roadmap, and it quietly validates $1,900 as the rate everyone else pays later. Raise the headline to $1,900 only after SSO/OIDC plus at least one of STALE-OAUTH or PRIVILEGE-DRIFT have shipped; founding customers keep $990 forever.

### Why annual, and how billing stays near-zero-ops

Annual, not monthly, for two reasons. Recurring revenue arrives as one predictable renewal per customer per year, and the offline license wants a long expiry: a monthly key would mean reissuing tokens twelve times a year per customer, which is a support job, not a business. A 365-day key issued once and renewed once is the natural cadence of the existing issuer.

Run billing through a merchant of record (LemonSqueezy or Polar). The MoR owns checkout, global VAT and sales tax, invoices, receipts, failed-payment dunning, and the renewal charge. A small webhook handler calls `scripts/issue_license.py --days 365` on purchase and on renewal and emails the key; the private key stays offline. The founder's only recurring task is a one-command mint. That is the recurring revenue with minimal ops and no credential custody the model is designed for: Afterlife never touches a customer's cloud keys, and the vendor never runs a license server.

At expiry the behavior is clean open core: Pro features lock (they refuse and point at `afterlife license`), and the full free core keeps running forever. No lapsed customer becomes a "I lost my tool" support ticket, which removes the main objection to an annual commitment.

### The Enterprise floor (upside without an ops treadmill)

Keep one hand-quoted tier at **from $6,000/year, inbound only**, for the org that cannot buy on a card: PO or invoice instead of checkout, an MSA, and a vendor security questionnaire answered. It is not a second product to operate. No storefront listing, no standing SLA beyond best-effort priority, no shared Slack channel promised. It exists so a 1,000-person company does not bounce off a $1,900 self-serve page, and each deal is one manual `issue_license.py` run. Volume is low by construction, so manual is fine and it keeps procurement-heavy buyers off the storefront. $6,000 is accessible for a solo vendor and trivial against a single stale-credential breach of the Uber-2022 or Okta-2023 class the tool is built to catch; quote up from there per deal.

### Launch tactic

The founding license above is the launch tactic: **$990/year, price locked for the life of the subscription, first 50 organizations, standard rate $1,900.** Show it on the page as the standard number with the founding offer struck through against it, so the page still presents one price and one decision. Pair it with a public roadmap and a clear refund window so the early buyer can see what they are funding and can back out cheaply. Offer a two-year prepay at 15 percent off ($1,680 for two years at the founding rate) only at checkout, never on the main page, so it never adds a decision to the ten-second read.

### What to revisit or A/B later

- **The step to the $1,900 headline.** Gate it on SSO/OIDC plus one advanced rule shipping. Until then $990 is not a discount, it is the honest price.
- **A low entry tier.** A/B a single-team price near $490/year against the flat model, to see whether a cheaper on-ramp widens the funnel to solo and very small teams enough to justify a second SKU. Keep it only if the added conversions beat the added support surface.
- **Scale-by-identity bands (Proposal 3).** Adopt only if flat pricing demonstrably leaves large-org money on the table, and only once you are willing to add the `max_identities` claim and the soft nudge banner. Nothing phones home, so this feedback comes slowly and mostly from Enterprise conversations, not telemetry.
- **Perpetual fallback.** The issuer already supports `--days 0`. If a "what if I stop paying" objection recurs, add a JetBrains-style promise (keep the last version, lose only updates and new Pro features). Ship subscription first.
- **A monthly try-before-annual price** at a deliberate premium (for example $199/month) for buyers who want to pilot before committing a year, accepting that it means shorter-lived keys to reissue.

## Launch plan

You are one person with little cash and a job hunt running in parallel. So this plan optimizes for two things at once: durable signal that a hiring manager can see (stars, HN front page, newsletter mentions, a real writeup trail) and a slow trickle of self-hosted Pro sales that needs almost no ops. The rule underneath every step: stagger the channels so you can actually be present in each thread, and never lead with pricing.

### Pre-launch checklist (finish all of this before you tell anyone)

- **Ship `afterlife-audit` to PyPI cleanly.** Do a TestPyPI dry run through the existing Trusted-Publishing workflow, then cut the real `v0.3.0` tag. Verify in a throwaway virtualenv that `pip install afterlife-audit` then `afterlife --version` and `afterlife --help` work with zero repo checkout. A broken `pip install` on launch day is the one mistake you cannot recover from, so test it from a clean machine or a fresh Docker `python:3.12-slim`.
- **Cut a GitHub Release for v0.3.0.** Paste the CHANGELOG v0.3.0 highlights, embed `demo.gif`, and link the PLAYBOOK. Releases show up in feeds and give the repo a "this is real and versioned" signal.
- **README above the fold is already strong; tighten the first screen.** The `demo.gif` (900 KB, fine) should be the first visual, the one-line pitch ("credentials that outlive their owners") first, the cross-source paragraph second. Add a copy-pasteable `pip install afterlife-audit && afterlife --help` and the `make demo` line high up, because the demo produces 20 real findings in about a minute and that is your whole conversion pitch.
- **Set repo metadata.** Description, topics (`iam`, `identity`, `offboarding`, `detection-engineering`, `aws`, `okta`, `security`, `self-hosted`), and a social-preview/OG image (reuse an overview screenshot with the tagline) so every shared link renders a card instead of a bare URL.
- **Turn on GitHub Discussions** with Q&A, Ideas, and Show and tell categories. This is where "does it support X?" lands instead of cluttering Issues, and an active Discussions tab reads as a live project to both users and employers.
- **One-page landing site, free.** GitHub Pages off the repo (`/docs` or a `gh-pages` branch), single `index.html`: `demo.mp4` autoplaying muted on loop as the hero, the cross-source sentence, the three-step "install, scan, read," a Free-vs-Pro table lifted from the README Editions section, and one email capture. Use Buttondown's free tier (up to ~100 subscribers) or a Tally form for the capture. Frame it "get notified when Pro ships SSO/retention," not a hard sell. A cheap domain (Porkbun, roughly $10/yr, `getafterlife.dev` or similar) is the only spend worth making, and it is optional.
- **Write two breach-teardown posts.** These are your launch fuel and double as portfolio pieces. Post #1: "How the Uber 2022 breach was ghost access" mapped to `OFFBOARDED-OWNER` (active key, IdP-suspended owner, the graph join). Post #2: "The Snowflake 2024 breaches were stale credentials" (or the Okta 2023 support-token angle) mapped to `UNUSED-CREDENTIAL` / `NEVER-USED` and rotation. Each ends with the exact rule that would have fired and a real `analyze` snippet. Publish them in `docs/blog/` (next to `the-graph-layer.md`), mirror to dev.to and your personal blog for the backlinks. Submit the posts, never a naked repo link, to the strict communities.
- **Seed a baseline.** Before any big push, get the repo off zero: tell friends, post a build-in-public thread on your Mastodon/LinkedIn/X, ask 5 to 15 people who will actually try `make demo` to star it. A repo at 8 stars when HN hits converts far better than one at 0.

### Launch channels and the framing each one needs

Each channel wants a different first sentence. Same product, different door.

- **Hacker News (the anchor).** Title: `Show HN: Afterlife, find credentials that outlive their owners`. Post Tuesday or Wednesday, roughly 8 to 10am ET (skip the US Labor Day Monday, Sept 7). Link the repo, not the landing page. Immediately add a maker comment: the honest backstory (solo dev, built it because offboarding leaves live keys everywhere, and yes it doubles as portfolio and a small product), the technical wedge (an AWS key active locally while its owner is suspended in the IdP, caught only by joining the two), what is free forever vs the Pro tier (dashboard auth, SSO/OIDC, Jira), and a direct ask for the harshest technical critique. Then clear your calendar and answer every comment for the whole day. Lead with the mechanism, not the business model.
- **r/netsec.** Strict, allergic to "check out my tool." Submit teardown post #2 as technical content, tool mentioned once at the end. The writeup is the submission; the repo is a footnote.
- **r/devops.** Frame around the ops pain: "after someone leaves, can you actually prove no live keys are left across AWS, GitHub, and Okta?" Emphasize self-hosted, free core, SARIF into CI, and `run`/`watch` as a cron monitor. Practical, not academic.
- **r/selfhosted.** Their exact love language: runs on your own box, Docker one-liner, local dashboard, and critically never custodies your cloud keys or phones home (no license server, offline verification). Lead with a dashboard screenshot and the `docker run` line.
- **lobste.rs.** Higher signal than HN but invite-only, so line up an invite in advance from anyone you know there. Submit the graph-layer essay or a teardown under tags `security`, `devops`, `python`. Be technical, tag yourself as author, and do not repeatedly submit your own links; that community punishes marketing fast.
- **Product Hunt.** Lower priority for a dev tool, worth exactly one shot for the durable backlink and a burst of email signups. Prep the gallery from your existing screenshots, a one-line tagline, and a first comment; schedule a Tuesday; ask your week 1 to 3 signups to show up at 12:01am PT. Set expectations low and treat it as SEO plus a mailing-list bump, not a revenue event.
- **Security newsletters (the buyer-audience reach).** Pitch two or three sentences plus a link to a live teardown post, never a bare repo, and never an ask for money. Targets: **tl;dr sec** (Clint Gibler), huge appsec reach, use its "share a tool/link" submission; **Return on Security** (Mike Privette), the open-core and breach-class business angle is squarely his beat; **Detection Engineering Weekly** (Zack Allen), pitch the `OFFBOARDED-OWNER` cross-source rule as a detection-engineering writeup; **Last Week in AWS** (Corey Quinn), the "AWS key outlives its owner" plus `CROSS-ACCOUNT-TRUST`/Capital One angle is on-brand, submit via their tips link. Time these pitches for after the teardown posts are live and HN has given you a traction line to cite.

### Week by week (weeks 1 through 6, starting the week of Sept 1)

- **Week 1, foundation and soft launch.** Publish to PyPI and verify the clean install. Cut the v0.3.0 release. Stand up the landing page and email capture. Enable Discussions, set topics and the OG image. Publish teardown #1 (Uber -> `OFFBOARDED-OWNER`) to the blog, dev.to, and your site. Post the build-in-public thread and seed the first stars. Do not touch HN yet.
- **Week 2, the Show HN.** Tue or Wed morning: post the Show HN and spend the day in the thread. Publish teardown #2 (Snowflake/Okta -> stale-credential rules). Two or three days later, not the same day, post to r/selfhosted with the Docker and no-custody framing. Fold the best HN criticism into a same-week patch and say so publicly.
- **Week 3, Reddit and lobste.rs.** Submit teardown #2 to r/netsec. Post the ops framing to r/devops. Submit the graph-layer essay to lobste.rs with your invite. Pitch all the newsletters now, citing the live posts and whatever HN and Reddit numbers you got.
- **Week 4, newsletters land and Product Hunt.** Newsletter mentions surface this week (they publish weekly), which is your second traffic wave, so be ready to answer the issues and Discussions it brings. Launch on Product Hunt on Tuesday and email your signups to come support. Ship one visible, feedback-driven improvement (a requested collector tweak, a new rule, a real fix) and post "you asked, shipped" to give repeat visitors a reason to return.
- **Weeks 5 and 6, convert and sustain.** Email everyone on the waitlist and everyone who filed a substantive issue: offer a free 3-month Pro license in exchange for a 20-minute call. Stand up the storefront and wire it to `scripts/issue_license.py`. Ship the next Pro candidate the calls actually asked for (most likely dashboard SSO/OIDC as the natural follow-on to `--require-auth`, or finding retention and trend history). Keep publishing: one teardown or design note every couple of weeks keeps the repo and the mailing list warm at near-zero cost.

### From first stars to first paying customer

The product already contains its own upgrade trigger, so the funnel is short:

1. **Traffic to email and stars.** HN, Reddit, and newsletter clicks land on the repo and the landing page. Capture what you can (waitlist email, star, watch). Stars are the portfolio signal; emails are the sales list.
2. **Lurker to user.** The conversion event is `make demo` or a real scan producing findings. Keep that path frictionless: `pip install afterlife-audit`, `make demo`, 20 findings in about a minute. Someone who points it at their own org and gets real ghost access back is your buyer.
3. **User to buyer, built in.** The moment a team wants to expose that dashboard to more than one person, they hit `afterlife serve --require-auth`, which is Pro. That upsell already lives in the product, so your first paying customer is a small security or platform team that found real findings and now wants to share the view safely.
4. **Design-partner motion.** Do not wait for self-serve. DM or email the handful who engaged deeply (detailed issues, HN replies, waitlist notes), give them a free license, and ask what would make them pay. Turn those answers into the next Pro feature. One of these warm relationships, not cold Product Hunt traffic, becomes your first real invoice.
5. **Low-ops storefront.** Use LemonSqueezy or Polar as merchant of record so they handle VAT and tax (that is the "less looking out" part). On purchase, a webhook triggers `scripts/issue_license.py`, mints the Ed25519 key, and emails it automatically. No license server, nothing phones home, which is the whole point of the offline design. Pricing follows the Pricing section, not a separate monthly figure: the $990/year founding license (first 50 organizations, price locked for life), rising to the $1,900/year standard once SSO plus an advanced rule are the paid draw, billed annually through the merchant of record. Steer every buyer to that annual license; it is the recurring revenue the model is built around.

Realistic expectation: single digits of paying customers in the first quarter, and the first one almost certainly arrives through a warm thread, not a cold funnel.

### Budget and effort reality

Total cash outlay is roughly $0 to $30: a domain if you want one, and the storefront takes a cut only when you make a sale. Everything else runs on free tiers (GitHub Pages, PyPI, Buttondown free, Tally, LemonSqueezy/Polar pay-per-sale). The real cost is attention: block the two or three launch days so you can live in the threads, because presence is what converts a Show HN into stars and a stray comment into your first customer. Track just four numbers so you know what is working: GitHub stars, PyPI installs (pepy.tech), landing-page signups, and repo clone/visitor traffic from GitHub Insights.

## Ongoing demand generation

Launch is a spike. Demand generation is the flywheel that keeps qualified security people finding Afterlife for months after, on a budget of zero dollars and a few hours a week. The organizing principle for a solo founder is reuse: one substantial artifact (a breach teardown, an essay) gets sliced into a docs page, a Show HN, a newsletter pitch, five social posts, and a job-hunt portfolio piece. Never make a thing that only lives in one place.

Below, tactics are ranked by leverage per hour, highest first. Do the top of the list before you touch the bottom.

### The leverage ranking

| Rank | Tactic | Hours | Why it ranks here |
|---|---|---|---|
| 1 | Get listed in aggregators that already have the audience | 1 to 2 per listing, once | A single PR or pitch sends qualified traffic for years with no upkeep |
| 2 | Breach-teardown series (the flagship content engine) | 4 to 8 per episode | Evergreen SEO, natively shareable, demos the product, doubles as portfolio |
| 3 | Comparison and keyword landing pages | 2 to 3 per page, once | Captures high-intent searchers who are already looking for this exact thing |
| 4 | Timed launch moments (Show HN, r/netsec) tied to a teardown | 2 per moment | Spiky but cheap, and each one seeds the aggregators and newsletters above |
| 5 | Building-in-public drip that doubles as the job hunt | 20 to 30 min per post | Low per-post value but nearly free, compounds, and the founder is posting for jobs anyway |
| 6 | Community answering where ghost access naturally comes up | ongoing, opportunistic | Builds trust and backlinks, but does not scale and must never look like spam |

### 1. Get listed once, benefit for years

The single highest-leverage hour is landing Afterlife in a place that already aggregates this exact audience. These are one-time submissions with durable payoff:

- **Awesome-list PRs**: `awesome-security`, `awesome-cloud-security`, `awesome-iam`, `awesome-incident-response`. A clean one-line entry plus the cross-source wedge is usually enough to get merged, and these pages rank and get scraped endlessly.
- **Newsletters that feature new tools**, pitched with a specific teardown rather than a generic "check out my project": tl;dr sec (Clint Gibler), CloudSecList (Marco Lancini), and Detection Engineering Weekly (Zack Allen) all have tool and writeup sections and reach exactly the people who run offboarding audits. Latio Pulse (James Berthoty) reviews security tooling and would engage with the open-source-vs-Veza framing.
- **The business-of-security angle**, which most security tools ignore: Return on Security (Mike Privette) and Venture in Security (Ross Haleliuk) cover the open-core model itself. A "why I built a self-hosted, no-credential-custody Pro tier" note is on-topic for them and reaches founders and hiring managers at once.

Send each pitch when you have a fresh teardown to attach, so the ask is "here is a useful thing," not "please feature me."

### 2. Breach-teardown series (the flagship)

This is the content engine. Every real ghost-access breach becomes a "here is exactly how Afterlife would have caught it" post, using the demo to fire the matching rule against synthetic data that mirrors the incident. Build one reusable skeleton (what happened per the public post-mortem, the precondition Afterlife detects, a GIF of the demo firing the rule, the remediation), and each new episode is hours, not days.

The backlog maps cleanly onto rules Afterlife already ships:

- **Snowflake 2024** (UNC5537): stolen credentials, many tied to former employees, on tenants without MFA. Fires `OFFBOARDED-OWNER`, `ADMIN-WITHOUT-MFA`, and `UNUSED-CREDENTIAL`. Lead with this one: most recent, highest search volume, strongest fit.
- **Uber 2022**: the canonical offboarded-owner and admin-concentration story the README already cites. Fires `OFFBOARDED-OWNER` and `ADMIN-CONCENTRATION`.
- **Capital One 2019**: the cross-account-trust precondition. Fires `CROSS-ACCOUNT-TRUST`.
- **Okta 2023** (support-case session tokens): the stale-credential and dormant-session angle.
- **Microsoft Midnight Blizzard 2024** (a legacy non-prod tenant, an over-privileged OAuth app, no MFA): use this one to publicly preview the planned `STALE-OAUTH` Pro rule, so a teardown does double duty as a roadmap and an upsell.

The existing graph-layer essay (`docs/blog/the-graph-layer.md`) is the "why" pillar every teardown links back to: cross-post it to dev.to and Hashnode, and each teardown reinforces its core claim that only joining the views catches this class. Publish the whole series on a free MkDocs Material or GitHub Pages site so the posts, keyword pages, and comparison pages share one domain and compound each other's ranking.

### 3. SEO: the terms security people actually type

Build a small set of durable pages targeting the real searches, each answering the question first and introducing Afterlife as the concrete tool second. Two page types:

- **Keyword pages**, one per intent: offboarding audit, find stale credentials, orphaned IAM users, ghost access, dormant service accounts, unused AWS access keys, detect offboarded-employee access, cross-account trust audit, orphaned OAuth apps.
- **Comparison and alternative pages**, which capture buyers already evaluating something: "Afterlife vs Prowler" (Prowler scans one cloud in isolation and never joins the IdP view), "Afterlife vs Cartography" (Cartography is a graph but needs Neo4j and ships no ghost-access rules or blast scoring), "Afterlife vs ScoutSuite / Steampipe," and "open-source alternative to Veza / Sonrai." Be honest about the wedge in every one: cross-source identity join, ghost-access rules, blast-radius ranking, self-hosted, and no credential custody.

### 4. Timed launch moments

Do not treat Show HN and r/netsec as one-time launch events. Every strong teardown is a fresh, legitimate reason to post: "Show HN: how a $0 open-source auditor would have caught the Snowflake 2024 breach" is a submission, not an ad. r/netsec, r/blueteamsec, and r/AWS reward the teardown format when the writeup carries the value and the tool is the footnote. Space these out and let each one feed the newsletters and aggregators from tactic 1.

### 5. Building in public, doubling as the job hunt

The founder is running a high-volume job hunt into 2026, so building in public is not extra work, it is the same work aimed at two audiences. Set a sustainable solo rhythm, not a daily one:

- **Weekly**: one LinkedIn post tied to whatever shipped or whichever teardown went out. LinkedIn is where hiring managers see it; every teardown is a portfolio proof point and a post at the same time. Mirror to BlueSky and Mastodon (infosec.exchange) for the security crowd.
- **Every two to three weeks**: a build-log post drawn straight from the CHANGELOG milestone narrative, which already reads as a commit-by-commit story and is nearly free to repackage.
- **Continuously on GitHub**: keep the roadmap public (the free-vs-Pro line, `STALE-OAUTH`, `PRIVILEGE-DRIFT`) as issues, so the project visibly moves and interviewers can watch it evolve.

### 6. Community presence without spamming

Show up where the offboarding-and-stale-credentials conversation already happens, and add value before you ever mention the tool: the Cloud Security Forum Slack, the fwd:cloudsec community, and detection-engineering Discords. Answer the real question, link the relevant teardown only when it genuinely answers it, and let people find the repo from there.

### Measure so you can cut

On a solo budget you cannot run every channel forever. Check GitHub Insights, Traffic for referral sources and Google Search Console for which terms actually land people, monthly. Find the two channels that move stars and installs, pour the hours there, and quietly drop the rest.

## Metrics, targets, and low-ops fulfillment

Afterlife has a structural measurement problem that shapes every number below: nothing phones home. Offline Ed25519 license verification and "we never hold your credentials" are load-bearing selling points, so you cannot ship telemetry that reports installs, activation, or usage without contradicting the pitch. That means the middle of the funnel is inferred from community signal, not instrumented. Plan your metrics around what you can actually see (storefront, GitHub, package index) plus what people tell you, and stop pretending you can measure the rest.

### The funnel, and where it goes dark

```
GitHub stars ──► PyPI downloads ──► installs ──► ACTIVATION ──► continuous use ──► Pro conversion ──► MRR/ARR ──► churn
 (visible)        (visible, noisy)   (dark)      (ran analyze    (watch/cron,       (visible,          (visible)     (visible)
                                                  on real infra,   inferred)          storefront)
                                                  inferred)
```

- **Stars**: visible, and the cheapest proxy for "the wedge landed." Vanity, but the one vanity number worth watching because it tracks whether the cross-source story resonates in security circles.
- **PyPI downloads** (`afterlife-audit`): visible via pypistats, but heavily polluted by CI, mirrors, and bots. A download is not a human. Never report it as a user count.
- **Installs and activation**: dark by design. "Activation" (someone ran `afterlife scan` + `analyze` against real systems, not just `make demo`) is the number that actually predicts revenue, and it is exactly the one you blinded yourself to. Infer it from GitHub Discussions with real-infra questions, issues that quote real ARNs or Okta statuses, and design-partner conversations.
- **Continuous use** (`afterlife watch` on cron or Docker): the strongest free-tier signal of intent to pay, because a team running Afterlife continuously has already decided it belongs in their stack. Inferred, not measured.
- **Pro conversion, MRR/ARR, churn**: fully visible once the storefront exists. These are real, and small.

### The few metrics that actually matter in year one

Ignore the funnel top as a KPI. In year one the only numbers worth steering by are:

1. **Activation evidence, qualitative.** Count the times someone says "it caught a real ghost credential." Five credible "it found a key from an offboarded contractor" stories are worth more than 2,000 stars, both for the roadmap and for the job hunt (they are the interview and building-in-public content).
2. **Teams running `watch` continuously.** The closest free-tier proxy to a future customer.
3. **First paying customers and the reason each paid.** With a small Pro set today (dashboard auth, SSO/OIDC, Jira), the *why* matters more than the count: if buyers pay to expose the dashboard to a team behind SSO, that validates the team-access wedge and the multi-config roadmap; if nobody will pay for team access alone, you learn that before building more.
4. **Net paying logos (not MRR curves).** At this scale MRR moves one customer at a time, so track logos and reasons, not a smoothed revenue chart.

Downloads, stars, and MRR-to-two-decimals are reporting theater at this stage. Watch them monthly, optimize none of them.

### Realistic year-one targets

For a solo, self-hosted, open-core security tool with a niche wedge, launched via Show HN, r/netsec, and building in public, honest numbers look like this. "Base" assumes it resonates modestly; "stretch" assumes a strong HN day plus sustained content.

| Metric | Base | Stretch | How you see it |
|---|---|---|---|
| GitHub stars | 400-600 | 1,500-2,500 | GitHub |
| PyPI downloads (afterlife-audit) | 3k-8k | 20k+ | pypistats (CI/mirror-polluted, discount heavily) |
| Ran `analyze` on real infra | 40-120 | 300+ | inferred (Discussions, issues, Discord) |
| Teams running `watch` continuously | 8-20 | 40-60 | inferred / design-partner convos |
| Paying Pro customers | 3-12 | 25-40 | storefront |
| List price (self-hosted Pro) | $990/yr founding, $1,900/yr standard, flat per organization | same | you set it |
| ARR (exit) | ~$3k-12k | ~$25k-75k | storefront |
| Annualized MRR (exit) | ~$250-1,000 | ~$2k-6k | storefront |
| Gross annual churn | one cancel = 8-15% | <5% | storefront |

Revenue rows are derived: paying-customer targets times the flat annual license
($990 founding, blending toward $1,900 as the list rate), so they scale with the
Pricing section rather than the old monthly figure.

The honest framing for the founder and for interviews: **year one is not a business, it is proof the wedge converts.** A few thousand to low five figures in ARR from a self-hosted open-core tool built solo, plus a portfolio centerpiece that demonstrably caught real ghost access, is a genuinely good year-one outcome. The revenue matters less than the evidence that people will pay for the cross-source angle at all, which is what tells you whether to invest the next year.

### Fulfillment: which storefront issues the keys

The important, Afterlife-specific insight: **you are not buying the storefront's license system, you are buying merchant-of-record tax handling plus the ability to deliver one custom string.** Afterlife verifies licenses offline against an embedded public key, so the storefront's own key-generation and validation API are irrelevant. All you need it to do is take money globally (handle VAT/sales tax so you never touch a tax filing) and hand the buyer the exact Ed25519 token you minted. That reframes the comparison around fees, MoR, and "can I deliver my own token cleanly," not around license-key feature depth.

| | LemonSqueezy | Polar | Gumroad |
|---|---|---|---|
| Fee | 5% + $0.50/txn | 4% + $0.40/txn | 10% flat |
| Merchant of record (tax) | Yes, full MoR | Yes, full MoR | Yes for digital goods |
| Deliver your own token | Yes (supply your own key list, or per-order delivery/webhook) | Yes (custom license-key benefit, or webhook to deliver the token) | Yes but clunkier (its own key format; deliver token via content/redirect) |
| Dev/OSS ergonomics | Good, docs-heavy, now part of Stripe | Best: OSS-native, GitHub integration, clean API, subscription-first | Weakest: consumer-creator focus, dated for dev tooling |
| Recurring subscriptions | Yes | Yes | Yes but awkward |

**Recommendation: Polar as primary, LemonSqueezy as the fallback.** Polar is the lowest fee, is a full merchant of record, is built by and for developers selling software (subscriptions, an API you would actually enjoy, GitHub-native), and it fits the self-hosted open-core shape. Take LemonSqueezy if you want the Stripe-backed, most-battle-tested option or hit a Polar limitation. Skip Gumroad: the 10% flat fee is more than double Polar's, and its creator-economy surface is the wrong fit for a security tool sold to engineering teams.

### The buy -> issue_license.py -> deliver flow, in three tiers

Match automation to volume. Do not build a webhook pipeline for three customers.

- **Tier 0, manual (launch, up to a few sales a week).** Storefront emails you on each order. You run `scripts/issue_license.py` locally with the buyer's email and term, paste the token into the order's delivery message (or reply by email). Zero infrastructure, zero standing service, nothing to monitor. This is the "less looking out" default and it is genuinely fine at launch volume.
- **Tier 1, pre-minted pool (when manual gets annoying).** If `issue_license.py` can mint a term license that is not hard-bound to a specific email (for example a 13-month Pro token), batch-mint 50-100 tokens and upload them as the storefront's own license-key inventory (LemonSqueezy and Gumroad both let you supply your own key list; Polar can vend from a custom set). The storefront then hands one token per sale automatically, with no server on your side. You only touch it to refill the pool. Renewals are handled by minting and vending fresh tokens.
- **Tier 2, webhook automation (only once volume justifies it).** Storefront fires an `order_created` / `subscription_created` webhook at a tiny stateless function (Cloudflare Worker, Val Town, or even a GitHub Action) that mints a per-customer token via the same `issue_license.py` logic and delivers it. This is the only tier that introduces a service to keep alive, so defer it until Tier 1 genuinely can't keep up. Subscription renewals become fully hands-off here.

Ship on Tier 0, move to Tier 1 when minting-by-hand stops being a five-minute chore, and reach Tier 2 only if you are lucky enough to need it.

### Capping support burden

Support is where "constant money, less looking out" is won or lost. Set the policy explicitly and defend it.

- **Written policy, stated on the README and the pricing page:** "Afterlife is self-hosted. Free tier is community-supported via GitHub Discussions. Priority email support is a Pro line item." This makes support a paid feature, not an open-ended obligation, and it is honest: because Afterlife never holds customer credentials and runs entirely on their infrastructure, you genuinely cannot and should not be on call for their environment.
- **Docs absorb the repeat questions.** The existing `docs/PLAYBOOK.md`, `docs/DETECTIONS.md` (false-positive notes per rule), and `.env.example` already answer most of what people will ask. Keep a short FAQ / troubleshooting page for the top offenders: credential scoping per collector, "why did this rule fire," PDF/Pango system deps, and license activation via `AFTERLIFE_LICENSE`.
- **GitHub Discussions, not email or a support inbox,** for Free. It is public (one answer serves everyone), searchable, and doubles as building-in-public content. Turn recurring threads into doc pages so each question is answered at most twice.
- **Canned answers** for the predictable five: license not activating, a rule false-positive (point to the allowlist and the rule's false-positive notes), Docker `/data` volume permissions, collector auth scopes, and "is my data sent anywhere" (no, and here is why that is the whole point).
- **A triage rhythm, not a pager.** Batch Discussions and issues into one or two fixed windows a week. Nothing about a self-hosted auditor is an emergency for you; the customer owns their runtime. Protecting that boundary is what keeps this a recurring-revenue side product rather than a second job.

## Appendix: pricing models considered

Three pricing models were developed independently before settling on the flat per-org license above. Recorded here as a decision trail.

### Single flat tier (the chosen basis)

Afterlife Pro: $1,900 per year, flat, per organization (one legal entity), unlimited seats, sources, and findings. That is the whole price list. Monthly-equivalent framing for the page: about $158/month, billed annually. Optional launch tactic (not a second tier): a founding-customer price of $1,500 per year, locked for the life of the subscription, for the first 25 customers. Optional two-year prepay at $3,200 (about 15 percent off) for buyers who prefer to lock a budget line, offered only at checkout so it never adds a decision to the main page. Anchors: Sidekiq Pro is about $1,200/year and Sidekiq Enterprise about $2,750/year (self-hosted, license-key, small-team dev infra); Afterlife lands between them because security tooling carries higher willingness to pay than a job queue, but Afterlife is earlier and less proven. For contrast, GitLab Premium is $29/user/month (about $3,480/year for a 10-person team), Snyk Team runs roughly $25/contributor/month, Vanta and Drata start around $10,000 to $30,000/year, and Metabase Pro self-hosted historically opened near $10,000/year. At $1,900 flat, Afterlife Pro is a rounding error on a security budget and stays under the roughly $2,500 line where procurement, a PO, and a vendor security review tend to kick in, so it remains a credit-card purchase.

Pros: Dead simple: one number, one decision, expensable in ten seconds. Lowest possible buyer friction, which is what actually converts self-serve security purchases.; Near-zero ops: flat per-org means no meter to build, nothing to enforce, and no seat-limit support tickets. It matches the offline Ed25519 license design (issue one 365-day key, count nothing).; $1,900 stays under the roughly $2,500 line where procurement, POs, and vendor security reviews start, so it remains a credit-card purchase with no sales motion.; Steers toward fewer, higher-value customers instead of a long tail of cheap ones, minimizing support surface per dollar for a solo maintainer.; Recurring by construction: one annual renewal per customer through a merchant of record that handles tax, invoices, and dunning.; Per-org (not per-seat, per-source) rewards the exact teams that get the most value from the cross-source join, instead of taxing them for having more systems.; Sits defensibly between Sidekiq Pro and Enterprise and is trivial next to Vanta or GitLab budgets, so it reads as serious without needing justification..
Cons: Leaves money on the table with large enterprises who would happily pay $10k+; a flat $1,900 has no expansion lever as a customer grows. Mitigation: this is intentional for now, and a future usage-neutral Enterprise add-on (SLA, invoicing, MSA) can capture them later without touching the main tier.; The shipped Pro value today is thin (dashboard auth only), so early buyers are partly paying for a roadmap. Mitigation: the founding price and a public roadmap de-risk this; do not raise to $1,900 as the headline until SSO plus one advanced rule ship.; Flat per-org gives no price signal by company size, so a 5-person startup and a 500-person company pay the same. This can feel expensive to the tiny team and cheap to the giant. Acceptable given the simplicity payoff, but it is a real tradeoff.; No enforcement means the honor system on 'one organization per license.' A determined buyer could share a key across entities. Low risk at this price and audience, and enforcement would reintroduce exactly the ops burden the model avoids.; Annual-only raises the first-purchase commitment versus a low monthly entry point, which can slow the very first conversions. The founding discount and a clear refund window offset this.; A single price point is harder to A/B test than a ladder; you learn slower whether $1,900 is optimal. Mitigation: watch conversion at the founding cohort and adjust the standard rate once before locking it in..

### Good-better-best ladder

Team $499/year, Business $1,900/year, Enterprise from $6,500/year. All flat per self-hosted deployment, unlimited seats, delivered as an annual (365-day) license key. Enterprise is a "from" floor quoted per deal above that.

Pros: Flat per-deployment pricing needs no seat counting, which the offline license cannot enforce anyway, so it is both the honest option and the lowest-ops one.; Annual expiry is already in the token (the exp claim in licensing.py and issue_license.py), so recurring revenue needs zero new code, just a fresh key each renewal.; Three flat prices drop straight into a merchant-of-record storefront (LemonSqueezy or Polar), so tax, VAT, billing, and renewals run with near-zero founder ops.; Tier gating maps one-to-one onto the existing licensing.py features list, so no re-architecture is required to sell tiers.; SSO sits at the middle tier, which is defensible to a security audience, avoids the sso.tax backlash, and still drives most teams to the $1,900 line.; Prices land clearly under Vault, Teleport, and Metabase, so Afterlife reads as accessible rather than a stretch for a solo vendor, while Enterprise 'from' preserves upside on big deals..
Cons: Offline keys cannot be revoked mid-term or after a refund, so a leaked or refunded key keeps working until it expires; annual keys cap the exposure but do not remove it.; Flat per-deployment pricing leaves money on the table for very large orgs that would pay per seat, and the Enterprise 'from' quote is the only lever to recapture it.; Only one Pro feature (dashboard auth) ships today, so Team and especially Business are partly selling a roadmap; STALE-OAUTH, PRIVILEGE-DRIFT, SSO, and the Jira/PagerDuty/ServiceNow integrations must exist before those tiers are honest.; Nothing phones home means no telemetry on how many deployments exist or which features get used, so pricing and packaging feedback comes slowly.; The Enterprise promises (named contact, shared Slack channel, 4 business hour critical response) are a real support load for a solo founder in the middle of a job hunt.; Annual renewal by delivering a new key can feel clunky next to a card that simply re-bills, so the automated purchase-and-renewal email flow has to be smooth or renewals will leak..

### Scale-by-size bands

Four annual, self-hosted bands, all including the full Pro feature set:

- Team: up to 50 employees, identity ceiling 500, USD 900/year (about 1.80 per identity)
- Growth: 51 to 250 employees, identity ceiling 2,500, USD 3,000/year (about 1.20 per identity)
- Business: 251 to 1,000 employees, identity ceiling 10,000, USD 7,500/year (about 0.75 per identity)
- Enterprise: 1,000+ employees, unlimited identities, from USD 18,000/year (contact, quoted by identity count, typically 18k to 40k)

Optional 2-year prepay: 15 percent off (Team 1,530, Growth 5,100, Business 12,750 for two years). Effective per-identity cost falls as you scale, the standard volume-discount shape security buyers expect.

Pros: Buyer self-selects a band in seconds from headcount they already know, so the low and mid bands sell self-serve through LemonSqueezy or Polar with no sales call and no ops burden.; Zero metering infrastructure: the scale limit is a signed number in the offline JWT, checked locally, which fits the existing licensing.py design and keeps the 'nothing phones home' promise intact.; Price tracks value, not features. A bigger org has more ghost access and more blast radius, so it pays more for the same Pro bits, which is fair and legible to security buyers who already see per-identity pricing from Nudge and Push.; Built-in expansion revenue: as a customer's identity graph grows past its band ceiling, the in-product nudge drives an organic upgrade without any outreach.; Recurring annual revenue with a clean fallback: when a token lapses, Pro locks but the full free core keeps working, so no churned customer becomes a support ticket.; Does not touch the cross-source wedge: all 9 sources and all detection stay free, so nothing in the paywall undermines the reason teams adopt Afterlife in the first place.; The verified unit (identities in the graph) is objective and hard to fudge, which makes an honor-system model hold up better than headcount alone would..
Cons: Honor system leaks. A large company can buy the Team band and under-report headcount; enforcement is a soft banner by design, so expect some revenue leakage that is only partly checked by the harder-to-fudge identity ceiling.; Machine-identity sprawl can still surprise honest buyers. Even at 10x headcount ceilings, a heavy service-account or deploy-key footprint can push a team over its band and feel unfair, requiring a clear rule for what counts toward the ceiling.; Headcount correlates imperfectly with willingness to pay. A small high-risk shop underpays for its real blast radius and a large low-cloud-footprint company may balk at its band, and bands only smooth this partially.; Renewal re-issuance is manual at first. It is fine at launch volume, but staying near-zero-ops as sales grow means a webhook-mint function, which puts the private key online in a secrets manager and adds a small security surface to the one secret that can mint licenses.; More claims mean more support and more explaining. 'Why am I on Growth' and identity-count disputes are new question types the solo maintainer will field.; Subscription-only may cost a few conversions. Some self-hosted buyers prefer a perpetual license with a year of updates, and annual-only leaves that segment on the table unless a perpetual option is added later.; The identity ceiling is only as trustworthy as the buyer's willingness to run the full scan. Someone can point Afterlife at fewer sources to keep the counted-identity number low, so the honor element never fully disappears..

The flat single-tier model won on ops: it needs no meter, no phone-home, and no tier-gated support, matching the offline license and the founder's low-ops constraint. The scale bands remain the documented upgrade path if flat pricing leaves large-org money on the table.
