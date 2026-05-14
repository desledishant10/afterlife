# Detection rules

Each rule documents: what it catches, the SQL/graph query that powers it, known
false-positive shapes, and what remediation should look like. Rules are versioned
by file under `src/afterlife/rules/`.

---

## OFFBOARDED-OWNER

**Severity:** Critical
**Status:** Implemented (graph-aware)

A credential is still active in a downstream system (AWS, GitHub) but its
owner, or any identity linked to its owner via the cross-source identity
graph, has been deprovisioned (`status` ∈ {suspended, deleted, deprovisioned,
inactive, archived}). This is the canonical "ghost access" pattern.

**How the graph factors in:** Each `Identity` is one source-system view of a
person. An AWS IAM user named `alice` and an Okta identity for
`alice@example.com` are two nodes; the graph links them by shared (lowercased)
email. When this rule evaluates a credential, it looks up the owner identity
and then asks the graph for the full `Person` (every linked identity) and
fires if any of them are deprovisioned.

This means the rule catches the Uber-2022 case: the AWS access key's *direct*
owner (the AWS IAM user) is still "active" in AWS, but the linked Okta identity
is suspended. The graph walk surfaces that.

**Why it matters:** This is the precondition for the Uber 2022 breach.
Offboarding flows propagate inconsistently; the IdP can show a user as
suspended while their long-lived AWS access key remains valid.

**False positives:**
- Service accounts intentionally created under a human's identity, then "owned"
  by a team after the human left. Mitigation: maintain an allowlist of
  credential IDs that have been verified as legitimately ownerless.
- Identity match is incorrect (e.g., two humans share an email alias).
  Mitigation: the graph currently links by email only; login-equality and
  fuzzy-name heuristics are deferred until we have a corpus to tune against.

**Remediation:** Revoke the credential. Before deletion, confirm no automation
depends on it; if it does, transition ownership to a non-human service account.

---

## UNUSED-CREDENTIAL

**Severity:** High
**Status:** Implemented

A credential is active and has a `last_used_at` timestamp older than the configured
threshold (default 90 days).

**Why it matters:** Unused credentials either represent forgotten automation
(which means no one is monitoring it for compromise) or pre-staged access by an
attacker waiting to use it.

**False positives:**
- Seasonal jobs (year-end reconciliation, tax filing) that legitimately use a key
  once every 364 days. Mitigation: per-credential threshold overrides via config.
- Break-glass credentials intentionally left dormant. Mitigation: tag-based
  allowlist read from the credential's metadata.

**Remediation:** Confirm the owner still needs it. If yes, document the use case
and consider migrating to short-lived credentials (IAM Roles Anywhere, OIDC).

---

## NEVER-USED

**Severity:** Medium
**Status:** Implemented

Credential has a `created_at` older than `never_used_grace_days` (default 30) but
no `last_used_at` value at all. Created and never touched.

**Why it matters:** Frequently the result of a "let me create this just in case"
moment that was forgotten. These credentials have no associated baseline behavior,
which makes anomaly detection on them impossible. Often the easiest wins in an
audit.

**False positives:**
- Break-glass credentials intentionally provisioned dormant for use during
  incidents. Mitigation: tag-based allowlist read from credential metadata
  (planned).
- Newly-created credentials where the consumer hasn't been deployed yet.
  Mitigation: the grace period handles the common case; per-credential overrides
  are planned.
- Credential types whose source system does not expose a usable last-used
  signal (currently `github_app_installation`). These are skipped entirely;
  see `TYPES_WITHOUT_USAGE_SIGNAL` in `rules/never_used.py`.

**Remediation:** Confirm whether the credential was created for a use case that
ever materialized. If not, revoke. If it's a deliberate dormant credential, tag
it so future scans skip it.

---

## UNROTATED-KEY

**Severity:** Medium
**Status:** Implemented

Active AWS access key with `created_at` older than `unrotated_key_days`
(default 180). For an access key, `created_at` is effectively the last rotation
timestamp; AWS doesn't rotate keys in place, you create a new key and delete
the old.

**Why it matters:** Long-lived static credentials are the highest-EV target for
attackers because (a) their value persists indefinitely and (b) compromise is
often only detected by usage anomalies, not key age. AWS Well-Architected
guidance calls for rotating access keys at least every 90 days for human users.

**False positives:**
- Programmatic service accounts that legitimately need static credentials and
  cannot use IAM Roles Anywhere or OIDC. Mitigation: tag-based allowlist
  (planned).
- v0.1 fires for both human and service-account IAM users without distinction.
  Distinguishing them reliably requires IdP correlation (Week 5).

**Remediation:** Rotate the access key (create new, update consumers, verify,
delete old). Long-term, migrate the workload to short-lived credentials.

---

## STALE-OAUTH

**Severity:** High
**Status:** Planned (Week 6)

OAuth grant whose last API call is older than `oauth_stale_days` (default 90) and
whose granted scopes include any write-tier permission.

**Why it matters:** Third-party OAuth apps accumulate. The MailChimp / Slack / etc.
integration someone set up two years ago for a one-time campaign is still
authorized to read every channel, and the company likely no longer monitors it
for compromise.

---

## PRIVILEGE-DRIFT

**Severity:** Medium
**Status:** Planned (Week 6)

IAM role's attached policies grant permissions far broader than its observed
90-day usage profile (via CloudTrail). Surfaces the difference as a finding.

**Why it matters:** Over-privileged roles are effectively "ghost access" for the
unused subset of permissions. The role works; the extra permissions just sit
there waiting to be abused if the role's credentials are compromised.

---

## ORPHANED-GITHUB

**Severity:** High
**Status:** Planned (Week 6)

GitHub PAT or deploy key whose owning user is no longer a member of the org.

**Why it matters:** GitHub does not automatically invalidate PATs when a user is
removed from an org. The token continues to work against any private repo the
user still has access to elsewhere, including org repos the ex-user re-gains
access to via outside-collaborator invites.

---

## ORPHANED-IDENTITY

**Severity:** Low
**Status:** Implemented

An identity in an IdP (Okta or Google Workspace) is active but has no linked
AWS or GitHub identity. Surfaced as a hygiene signal: either the user does not
need downstream access (legitimate), or downstream provisioning has not
completed.

**Why it matters:** Stale IdP-only accounts accumulate. Each one is a future
phishing target. Auditors want to see that "everyone with an active IdP login
needs it for something."

**False positives:** Plenty. Many companies use the IdP for non-technical apps
(SSO into Notion, Slack) without provisioning AWS/GitHub. Mitigation: rule
fires at low severity, treated as informational unless paired with downstream
allowlists (planned).

---

## OUTSIDE-COLLAB-WITH-AWS

**Severity:** High
**Status:** Implemented

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

## ADMIN-CONCENTRATION

**Severity:** Critical
**Status:** Implemented

A single identity-graph person holds admin-equivalent access in two or more
source systems. Today this means IdP `is_admin: True` (Google) plus an AWS
credential with `AdministratorAccess` or `*:*` in its scopes, or two IdP
admin flags on the same person.

**Why it matters:** Splitting admin authority is the simplest defense against
single-account compromise. When the same human is the Google super-admin AND
the AWS account owner AND the GitHub org owner, a phishing of that human
bypasses every system at once. Several public breach narratives include this
pattern (Reddit 2023, Uber 2022 to a lesser extent).

**Remediation:** Reduce admin scope: keep admin in the one system this
person genuinely needs day-to-day; downgrade the rest. If cross-system
admin is required, enforce 2-step verification everywhere and use a
dedicated admin-only account distinct from the daily login.

---

## CROSS-ACCOUNT-TRUST

**Severity:** Critical
**Status:** Implemented

An IAM role's trust policy grants `sts:AssumeRole` (or
`AssumeRoleWithWebIdentity`, etc.) to an AWS principal in a different
account than the role's own. The check is conservative: AWS service
principals (`ec2.amazonaws.com`, `lambda.amazonaws.com`, ...), federated
identities, and same-account principals do not fire it. Only explicit
foreign `Principal.AWS` ARNs count.

**Why it matters:** Cross-account trust was the precondition for the
Capital One 2019 breach — a misconfigured WAF role was assumable from
a foreign account and that path was used to reach S3. Even when
intentional, every external trust is a third-party-risk surface that
deserves review.

**False positives:** Genuinely intentional inter-account access (audit
accounts, security-tools accounts, dev-vs-prod separation). Mitigation:
suppress via the allowlist once verified, ideally with an `ExternalId`
condition documented in the trust policy.

**Remediation:** Confirm the cross-account trust is intentional. If so,
scope the role's permissions to the minimum needed and require an
`ExternalId` in the trust policy condition. If not, restrict `Principal`
to your own account.

---

## INACTIVE-ADMIN

**Severity:** High
**Status:** Implemented

An IdP identity flagged as admin has not logged in for more than N days
(default 30). Dormant admin accounts compound the risk because their
credentials remain valid but nobody is watching for compromise signals.

**Why it matters:** Admin role + no recent login = either the user moved
roles and forgot to drop privileges, or the account is being saved for
"break-glass" use that nobody actively monitors. Both states are easy to
phish or credential-stuff into.

**False positives:** Genuine break-glass admin accounts that are
intentionally dormant. Mitigation: tag the credential in the allowlist and
add an `until` date if dormancy is time-bounded.

**Remediation:** Confirm whether the user still needs admin privileges.
Downgrade or deprovision if not. If yes, document the business reason and
enforce 2-step verification (the combination with ADMIN-WITHOUT-MFA is
particularly bad).

---

## ADMIN-WITHOUT-MFA

**Severity:** Critical
**Status:** Implemented for Google Workspace

An IdP identity flagged as admin (Google `isAdmin: true`) does not have
2-step verification enforced. The check is conservative: it fires only when
`isEnforcedIn2Sv` is explicitly false, or both `isEnforcedIn2Sv` and
`isEnrolledIn2Sv` are missing/false; voluntary enrollment is treated as
protective enough to avoid noise.

**Why it matters:** Admin account compromise via password reuse / phishing
gives an attacker the keys to every downstream system the admin can
provision. 2FA is the minimum bar; enforced, org-level 2FA is the right one.

**Okta:** Not yet covered. Okta's MFA enforcement signal is at the
group/policy level, not on the user object; capturing it requires an
additional collector call that is not yet implemented.
