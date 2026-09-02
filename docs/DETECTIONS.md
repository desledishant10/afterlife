# Detection rules

Each rule documents: what it catches, where the signal comes from, known
false-positive shapes, and what remediation should look like. Rules live in
`src/afterlife/rules/` and are auto-discovered by the decorator-based registry.

Rules are listed below in severity order (critical first), with the planned
rules at the bottom for visibility.

---

## OFFBOARDED-OWNER

**Severity:** Critical &middot; **Status:** Implemented (graph-aware)

A credential is still active in a downstream system (AWS, GitHub, ...) but
its owner, or any identity linked to its owner via the cross-source identity
graph, has been deprovisioned (`status` in {suspended, deleted,
deprovisioned, inactive, archived}). This is the canonical "ghost access"
pattern.

**How the graph factors in:** Each `Identity` is one source-system view of a
person. An AWS IAM user named `alice` and an Okta identity for
`alice@example.com` are two graph nodes; the graph links them by shared
(lowercased) email, and by Vault aliases when a Vault entity names them. When
this rule evaluates a credential, it looks up the owner identity, asks the
graph for the full `Person` (every linked identity), and fires if any of
them are deprovisioned.

This is exactly the Uber-2022 case: the AWS access key's *direct* owner is
still "active" in AWS, but the linked Okta identity is suspended.

**Why it matters:** Offboarding flows propagate inconsistently. The IdP can
show a user as suspended while their long-lived AWS access key remains valid
for weeks or months. That window is what attackers exploit.

**False positives:**
- Service accounts intentionally created under a human's identity, then
  "owned" by a team after the human left. Mitigation: allowlist the
  credential ID.
- Identity match is incorrect (two humans share an email alias). Mitigation:
  the graph links by email and Vault alias only; login-equality and
  fuzzy-name heuristics are deferred until we have a corpus to tune against.

**Remediation:** Revoke the credential. Before deletion, confirm no
automation depends on it; if it does, transition ownership to a non-human
service account.

---

## CROSS-ACCOUNT-TRUST

**Severity:** Critical &middot; **Status:** Implemented

An IAM role's trust policy grants `sts:AssumeRole` (or
`AssumeRoleWithWebIdentity`, etc.) to an AWS principal in a different
account than the role's own. The check is conservative: AWS service
principals (`ec2.amazonaws.com`, `lambda.amazonaws.com`, ...), federated
identities, and same-account principals do not fire it. Only explicit
foreign `Principal.AWS` ARNs count.

**Why it matters:** Cross-account trust was the precondition for the Capital
One 2019 breach. A misconfigured WAF role was assumable from a foreign
account, and that path led to S3. Even when intentional, every external trust
is third-party-risk surface that benefits from periodic review.

**False positives:** Genuinely intentional inter-account access (audit
accounts, security-tools accounts, dev-vs-prod separation). Mitigation:
suppress via the allowlist once verified, ideally with an `ExternalId`
condition documented in the trust policy.

**Remediation:** Confirm the cross-account trust is intentional. If so,
scope the role's permissions to the minimum needed and require an
`ExternalId` in the trust policy condition. If not, restrict `Principal` to
your own account.

---

## PUBLIC-ROLE-TRUST

**Severity:** Critical &middot; **Status:** Implemented

An IAM role's trust policy grants `sts:AssumeRole` to a wildcard principal:
`Principal: "*"`, `Principal.AWS: "*"`, or an ARN whose account field is a
wildcard (`arn:aws:iam::*:root`). This is strictly worse than
CROSS-ACCOUNT-TRUST, which names a specific foreign account: here there is no
counterparty to vet at all. The rule fires only when the wildcard is
**unconstrained**, so it stays quiet when a `Condition` meaningfully restricts
who may assume (any of `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`,
`aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:SourceAccount`,
`aws:SourceOwner`, or `sts:ExternalId`).

**Why it matters:** An unconstrained wildcard trust lets any AWS account (or,
in the anonymous `*` form, anyone) assume the role and inherit its permissions.
It is a direct, un-vetted path into the account and one of the highest-signal
IAM misconfigurations. CROSS-ACCOUNT-TRUST deliberately skips these wildcard
forms, so without this rule they were silently passed.

**False positives:** Roles intentionally open org-wide usually carry an
`aws:PrincipalOrgID` condition, which suppresses the finding. A genuinely
public role with no condition is almost always a mistake worth reviewing.

**Remediation:** Replace the wildcard `Principal` with your own account id or
specific principal ARNs. If cross-account access is required, name the accounts
and add a `Condition` (`aws:PrincipalOrgID` or `sts:ExternalId`).

---

## ADMIN-CONCENTRATION

**Severity:** Critical &middot; **Status:** Implemented

A single identity-graph person holds admin-equivalent access in two or more
source systems. Today this means any of:

- IdP `is_admin: True` (Google, Slack, future Okta/Azure once we capture it)
- AWS credential owned by the person with `AdministratorAccess` or `*:*` in
  its scopes

If the same person satisfies the admin criterion in 2+ distinct sources,
fire.

**Why it matters:** Splitting admin authority is the simplest defense against
single-account compromise. When the same human is the Google super-admin
*and* the AWS account owner *and* the GitHub org owner, a phishing of that
human bypasses every system at once. Several public breach narratives include
this pattern (Reddit 2023, Uber 2022 to a lesser extent).

**Remediation:** Reduce admin scope: keep admin in the one system this
person genuinely needs day-to-day; downgrade the rest. If cross-system admin
is required, enforce 2-step verification everywhere and use a dedicated
admin-only account distinct from the daily login.

---

## ADMIN-WITHOUT-MFA

**Severity:** Critical &middot; **Status:** Implemented for Google Workspace

An IdP identity flagged as admin (Google `isAdmin: true`) does not have
2-step verification enforced. The check is conservative: it fires only when
`isEnforcedIn2Sv` is explicitly false, or both `isEnforcedIn2Sv` and
`isEnrolledIn2Sv` are missing/false. Voluntary enrollment is treated as
protective enough to avoid noise.

**Why it matters:** Admin-account compromise via password reuse or phishing
gives an attacker the keys to every downstream system the admin can
provision. 2FA is the minimum bar; enforced, org-level 2FA is the right one.

**Coverage gaps:** Okta and Azure MFA signals are policy/conditional-access
shaped, not on the user object; capturing them requires additional collector
calls not yet implemented.

---

## USER-WITHOUT-MFA

**Severity:** Medium &middot; **Status:** Implemented for Google Workspace

The non-admin counterpart to ADMIN-WITHOUT-MFA: an **active, non-admin** IdP
identity we can confirm has no 2-step verification. It uses the same
conservative signal (fires only when Google `isEnforcedIn2Sv` is explicitly
false, or enforcement is unknown and `isEnrolledIn2Sv` is false), skips admins
(reported at Critical by ADMIN-WITHOUT-MFA), and skips suspended accounts
(OFFBOARDED-OWNER's job).

**Why it matters:** The Snowflake 2024 campaign did not target admins; it
replayed stolen passwords against ordinary user accounts that had no second
factor, then exfiltrated data at scale. The population of password-only
non-admin accounts is exactly that attack surface.

**Coverage gaps:** Same as ADMIN-WITHOUT-MFA: only Google Workspace surfaces
the enforcement/enrollment signal on the user object today, so Okta and Entra
identities stay quiet rather than noisy.

**Remediation:** Enforce 2-step verification at the org-unit or group level so
existing and new users are covered, rather than relying on voluntary
enrollment.

---

## UNUSED-CREDENTIAL

**Severity:** High &middot; **Status:** Implemented

A credential is active and has a `last_used_at` timestamp older than the
configured threshold (default 90 days).

**Why it matters:** Unused credentials either represent forgotten automation
(which means no one is monitoring it for compromise) or pre-staged access
that an attacker is waiting to use.

**False positives:**
- Seasonal jobs (year-end reconciliation, tax filing) that legitimately use
  a key once every 364 days. Mitigation: suppress via the allowlist.
- Break-glass credentials intentionally left dormant. Mitigation: same.

**Remediation:** Confirm the owner still needs it. If yes, document the use
case and consider migrating to short-lived credentials (IAM Roles Anywhere,
Workload Identity Federation, GitHub OIDC).

---

## STALE-DEPLOY-KEY-WRITE

**Severity:** High &middot; **Status:** Implemented

A deploy key with push or write access has not been used in
`unused_days_threshold` days (default 90). Covers both GitHub (`write`
scope) and GitLab (`push` scope). A focused superset of UNUSED-CREDENTIAL
for the supply-chain-critical case.

**Why it matters:** A write-capable deploy key that nobody is touching is
the cleanest path for an attacker who has stolen a CI image or developer
laptop: still active, still trusted, but with nobody watching usage. The
attacker can push a poisoned commit, the existing CI consumes it, and the
trail looks legitimate.

**Remediation:** Remove the key. If CI still needs it, rotate to a fresh
key with a documented owner. If push is no longer required, replace with a
read-only key.

---

## STALE-OAUTH

**Severity:** High &middot; **Status:** Implemented

An active third-party OAuth grant carries a write-tier scope and has not been
used in `oauth_stale_days` days (default 90). Operates on `oauth_grant`
credentials; a scope counts as write-tier unless it is an identity scope
(openid / email / profile) or explicitly read-only.

**Why it matters:** Third-party OAuth grants accumulate and are almost never
revoked. The Zapier, analytics, or MailChimp integration authorized two years
ago for a one-off task is still authorized to read or modify data, unmonitored,
and is a quiet path to exfiltration if the app is compromised.

**Remediation:** Revoke the grant if the app is no longer needed. If it is
still required, confirm the owner, reduce its scopes to the minimum, and
document why it exists.

**Data source:** OAuth grants are ingested as `oauth_grant` credentials. The
Google Workspace collector enumerates them from the Directory tokens API
(scopes + app, best-effort so a missing token scope never breaks a scan). That
API returns no usage timestamp, so full staleness detection needs a source that
reports OAuth activity (e.g. the Google Reports API); grants without a usage
timestamp are still inventoried and still caught by OFFBOARDED-OWNER when their
owner leaves.

**False positives:** A legitimately dormant-but-needed integration (a seasonal
or annual job) will fire. Suppress it via the allowlist with a documented
reason rather than leaving it unreviewed.

---

## OUTSIDE-COLLAB-WITH-AWS

**Severity:** High &middot; **Status:** Implemented

A user marked as a GitHub outside collaborator (not a full org member) is
linked by email to an AWS IAM identity. Fires once per active AWS credential
the contractor owns; if no credentials exist but the IAM identity does, fires
once for the link itself.

**Why it matters:** External contractors and vendors should not hold
long-lived static cloud credentials. Their access should be time-boxed via
IAM Identity Center / Roles Anywhere. A GitHub outside collaborator with an
AWS access key is a frequent contractor-handoff oversight.

**Remediation:** Revoke the credential or migrate the workload to short-lived
credentials. Audit how the contractor was originally given AWS access.

---

## ORPHANED-GITHUB

**Severity:** High &middot; **Status:** Implemented

An active GitHub personal access token is owned by a login that is no longer a
member or outside collaborator of the organization. GitHub does not revoke a
member's tokens when they are removed, so the token keeps working against any
repository the former user can still reach.

**Why it matters:** A departed employee's PAT is standing, unmonitored access.
It survives offboarding, and the ex-user can regain reach to org repos as an
outside collaborator elsewhere, at which point the old token works again.

**Remediation:** Revoke the token in the org's SAML SSO credential
authorizations (Settings -> Authentication security) and confirm the user's
org membership was fully removed.

**Data source:** PATs are ingested by the GitHub collector from the Enterprise
SAML SSO `/orgs/{org}/credential-authorizations` endpoint as `github_pat`
credentials. The call is best-effort: a non-Enterprise org (404) or a missing
`admin:org` scope (403) simply yields no PATs. Deploy keys are out of scope
here; they are covered by UNUSED-CREDENTIAL and STALE-DEPLOY-KEY-WRITE.

---

## INACTIVE-ADMIN

**Severity:** High &middot; **Status:** Implemented

An IdP identity flagged as admin has not logged in for more than N days
(default 30). Dormant admin accounts compound the risk because their
credentials remain valid but nobody is watching for compromise signals.

**Why it matters:** Admin role + no recent login = either the user moved
roles and forgot to drop privileges, or the account is being saved for
"break-glass" use that nobody actively monitors. Both states are easy to
phish or credential-stuff into.

**False positives:** Genuine break-glass admin accounts that are
intentionally dormant. Mitigation: allowlist with an `until` date if dormancy
is time-bounded.

**Remediation:** Confirm whether the user still needs admin privileges.
Downgrade or deprovision if not. If yes, document the business reason and
enforce 2-step verification.

---

## UNROTATED-KEY

**Severity:** Medium &middot; **Status:** Implemented

Active static cloud credential (AWS access key, GCP service account key)
with `created_at` older than `unrotated_key_days` (default 180). For these
credential types, `created_at` is effectively the last rotation timestamp:
neither AWS nor GCP rotates keys in place; you create a new key and delete
the old.

**Why it matters:** Long-lived static credentials are the highest-EV target
for attackers because (a) their value persists indefinitely and (b)
compromise is often only detected by usage anomalies, not key age. AWS
Well-Architected guidance calls for rotating access keys at least every 90
days for human users.

**False positives:**
- Programmatic service accounts that legitimately need static credentials
  and cannot use IAM Roles Anywhere / Workload Identity Federation.
  Mitigation: allowlist.
- v0.1 fires for both human and service-account IAM users without
  distinction. Distinguishing them reliably requires a richer cross-source
  graph (e.g., the IAM user has no IdP linked identity, so it's clearly a
  service account).

**Remediation:** Rotate the key (create new, update consumers, verify,
delete old). Long-term, migrate the workload to short-lived credentials.

---

## NEVER-USED

**Severity:** Medium &middot; **Status:** Implemented

Credential has a `created_at` older than `never_used_grace_days` (default 30)
but no `last_used_at` value at all. Created and never touched.

**Why it matters:** Frequently the result of a "let me create this just in
case" moment that was forgotten. These credentials have no associated
baseline behavior, which makes anomaly detection on them impossible. Often
the easiest wins in an audit.

**False positives:**
- Break-glass credentials intentionally provisioned dormant. Mitigation:
  allowlist.
- Newly created credentials whose consumer hasn't been deployed yet.
  Mitigation: the grace period handles the common case.
- Credential types whose source system does not expose a last-used signal:
  `github_app_installation` and `gcp_service_account_key` are skipped
  entirely. See `TYPES_WITHOUT_USAGE_SIGNAL` in `rules/never_used.py`.

**Remediation:** Revoke. If it's intentionally dormant, allowlist it.

---

## ORPHANED-IDENTITY

**Severity:** Low &middot; **Status:** Implemented

An identity in an IdP (Google Workspace, Okta, Microsoft Entra ID) is active
but has no linked AWS or GitHub identity. Surfaced as a hygiene signal:
either the user does not need downstream access (legitimate), or downstream
provisioning has not completed.

**Why it matters:** Stale IdP-only accounts accumulate. Each one is a future
phishing target. Auditors want to see that "everyone with an active IdP
login needs it for something."

**False positives:** Plenty. Many companies use the IdP for non-technical
apps (SSO into Notion, Salesforce) without provisioning AWS/GitHub.
Mitigation: rule fires at low severity, treated as informational.

---

## PRIVILEGE-DRIFT

**Severity:** Medium &middot; **Status:** Implemented

An active IAM role is granted access to many AWS services its policies allow
but that it has not used within `privilege_drift_days` (default 90). The rule
fires when a role has an observed usage profile (at least one used service) yet
at least `privilege_drift_min_unused` granted-but-unused services.

**Why it matters:** The unused-but-granted services are ghost access: dead
weight for the workload, live blast radius for an attacker who compromises the
role. A role that touches three services but is granted three hundred is three
hundred services of attack surface for the price of three.

**Remediation:** Right-size the role's policies to the services it actually
uses (IAM Access Analyzer can generate a least-privilege policy from this same
access history), and remove or scope down the unused grants.

**Data source:** The AWS collector attaches per-service last-use to each role
from IAM Access Advisor (`GenerateServiceLastAccessedDetails`) as
`metadata.service_access`. The call is best-effort: it needs the
`iam:GenerateServiceLastAccessedDetails` permission and is unavailable in some
setups (and in the demo's mock), in which case the role is collected without
drift data. When the CloudTrail collector (`afterlife scan cloudtrail`) has also
run, each granted service's last-use is refined with `metadata.observed_services`
(audit-log ground truth): a service counts as used if either source saw it
within the window, whichever is more recent. This suppresses false positives
where Access Advisor's last-accessed lags behind real activity. Findings carry
`evidence.cloudtrail_refined` to show when audit-log data was folded in.

**False positives:** Roles with legitimately broad but rarely-exercised
permissions (break-glass, disaster recovery) will fire. Suppress them via the
allowlist with a documented reason.
