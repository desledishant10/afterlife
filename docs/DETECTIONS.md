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

## Planned

These rules are documented placeholders for work that requires data we don't
yet collect. They sit in the doc to signal intent and to make the gap
visible.

### STALE-OAUTH

**Severity:** High &middot; **Status:** Planned (needs OAuth grant inventory)

OAuth grant whose last API call is older than `oauth_stale_days` (default 90)
and whose granted scopes include any write-tier permission.

Third-party OAuth apps accumulate. The MailChimp / Slack / Zapier integration
someone set up two years ago for a one-time campaign is still authorized to
read every channel, and the company likely no longer monitors it for
compromise.

Requires: per-user OAuth grant enumeration from Google Workspace (tokens
endpoint), Slack (admin.users.list with apps), or similar.

### PRIVILEGE-DRIFT

**Severity:** Medium &middot; **Status:** Planned (needs CloudTrail data)

IAM role's attached policies grant permissions far broader than its observed
N-day usage profile. Surfaces the difference as a finding.

Over-privileged roles are "ghost access" for the unused subset of
permissions. The role works; the extra permissions sit there waiting to be
abused if the role's credentials are compromised.

Requires: CloudTrail collection, IAM Access Analyzer integration, or a
similar usage-data source.

### ORPHANED-GITHUB

**Severity:** High &middot; **Status:** Planned (needs PAT inventory)

GitHub PAT or deploy key whose owning user is no longer a member of the org.

GitHub does not automatically invalidate PATs when a user is removed from an
org. The token continues to work against any private repo the user still has
access to elsewhere, including org repos the ex-user re-gains access to via
outside-collaborator invites.

Requires: Enterprise SAML SSO credential-authorizations endpoint, or another
PAT-inventory source. Deploy keys are already covered by UNUSED-CREDENTIAL +
STALE-DEPLOY-KEY-WRITE.
