# Detection rules

Each rule documents: what it catches, the SQL/graph query that powers it, known
false-positive shapes, and what remediation should look like. Rules are versioned
by file under `src/afterlife/rules/`.

---

## OFFBOARDED-OWNER

**Severity:** Critical
**Status:** Implemented

A credential is still active in a downstream system (AWS, GitHub) but the owning
identity has been deprovisioned in the IdP (`status` ∈ {suspended, deleted,
deprovisioned, inactive, archived}). This is the canonical "ghost access" pattern.

**Why it matters:** This is the precondition for the Uber 2022 breach. Offboarding
flows propagate inconsistently; the IdP can show a user as suspended while their
long-lived AWS access key remains valid.

**False positives:**
- Service accounts intentionally created under a human's identity, then "owned" by
  a team after the human left. Mitigation: maintain an allowlist of credential IDs
  that have been verified as legitimately ownerless.
- Identity match is incorrect (e.g., two humans share an email alias). Mitigation:
  add confidence scoring on the identity-join in Week 5.

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
**Status:** Planned (Week 6)

Credential has a `created_at` older than `never_used_grace_days` (default 30) but
no `last_used_at` value at all. Created and never touched.

**Why it matters:** Frequently the result of a "let me create this just in case"
moment that was forgotten. These credentials have no associated baseline behavior,
which makes anomaly detection on them impossible. Often the easiest wins in an
audit.

---

## UNROTATED-KEY

**Severity:** Medium
**Status:** Planned (Week 6)

AWS access key on a human user with `created_at` older than 180 days and no
rotation. Long-lived keys on humans violate the AWS Well-Architected security
pillar.

**Why it matters:** Long-lived static credentials are the highest-EV target for
attackers because (a) their value persists and (b) their compromise is often only
detected by usage anomalies, not key age.

---

## STALE-OAUTH

**Severity:** High
**Status:** Planned (Week 6)

OAuth grant whose last API call is older than `oauth_stale_days` (default 90) and
whose granted scopes include any write-tier permission.

**Why it matters:** Third-party OAuth apps accumulate. The MailChimp / Slack / etc.
integration someone set up two years ago for a one-time campaign is still
authorized to read every channel — and the company likely no longer monitors it
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
user still has access to elsewhere — including org repos the ex-user re-gains
access to via outside-collaborator invites.
