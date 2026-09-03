# The Uber 2022 breach was a blast-radius problem

A teardown of the September 2022 Uber breach through the lens of
[Afterlife](https://github.com/desledishant10/afterlife), a self-hosted
cross-source ghost-access auditor. I want to be honest up front about the thing
most vendor "we would have stopped this" posts are not: **Afterlife would not
have stopped the phish.** No access-review tool would. What it would have
surfaced is the reason a single phished contractor turned into "the attacker had
admin on basically everything," which is the part worth fixing, because the
phish is going to happen again.

## What actually happened

From Uber's own incident statement and the public reporting, the chain was
roughly:

1. An attacker (Uber attributed the intrusion to Lapsus$) obtained an **external
   contractor's** corporate password, most likely bought after a malware
   infection put it up for sale.
2. The contractor had MFA, so the attacker **spammed push notifications** and
   then messaged the contractor posing as Uber IT, convincing them to approve
   one. That is MFA fatigue, and it got the attacker onto the VPN and the
   internal network.
3. Once inside, the attacker found a network share with **PowerShell scripts
   containing hard-coded admin credentials** for a privileged access management
   (PAM) system.
4. That PAM unlocked secrets for a long list of internal systems: AWS, Google
   Workspace, cloud consoles, Slack, the finance tooling, and the internal
   HackerOne dashboard.

Step 1 and 2 are a phishing and MFA story. Steps 3 and 4 are the part that made
it a headline: one foothold reached administrative access **across every major
system at once**. That is not a phishing problem. That is a blast-radius
problem, and blast radius is exactly what a cross-source access review measures.

## The honest scope: what Afterlife does and does not see

Afterlife is a defensive posture tool. You run it against your own cloud, code
host, and IdP with your own read-only admin credentials, and it tells you who
can reach what. So, plainly:

- It would **not** have blocked the stolen password or the MFA-fatigue approval.
  That is EDR, phishing-resistant MFA (FIDO2), and number-matching territory.
- It would **not** have found the hard-coded credentials sitting in a PowerShell
  script. That is a secret scanner's job, not an identity graph's.

What it **would** have put on a ranked list, weeks before, is the standing
condition that turned one account into total compromise: a small number of
identities and credentials that could reach admin everywhere, and access that
outlived the people it belonged to. Here is how that maps to specific rules.

## 1. ADMIN-CONCENTRATION: one foothold, every system

This is the one. The damage at Uber scaled the way it did because the path from
"inside the network" to "admin on AWS, Google Workspace, Slack, and the rest"
was short and shared. When the same principal is administrative across many
systems, compromising it once compromises all of them.

`ADMIN-CONCENTRATION` fires when the identity graph shows a single person holding
admin-tier access in two or more sources. It joins the IdP admin flag, an AWS
credential carrying `AdministratorAccess` or `*:*`, GitHub org-owner, Slack
owner, and so on, onto one person node, and flags the humans who are a single
point of catastrophic failure.

On a synthetic Uber-shaped org, `afterlife analyze` surfaces it first, because
blast-radius scoring ranks "opens the most doors" at the top:

```
$ afterlife analyze
CRITICAL  ADMIN-CONCENTRATION    person raj@corp        admin in Google Workspace + AWS + GitHub + Slack
CRITICAL  OFFBOARDED-OWNER       aws iam key AKIA...9QF  owner (contractor) suspended in Okta 63d ago
CRITICAL  ADMIN-WITHOUT-MFA      google admin ops@corp  2-step verification not enforced
HIGH      OUTSIDE-COLLAB-WITH-AWS github outside collab  maps to active AWS access keys
MEDIUM    UNROTATED-KEY          aws key of automation   age 511d, past 180d threshold
```

The point of the top line is not "raj is bad." It is: if any one credential this
person holds is phished, the attacker inherits admin on four systems. The remedy
is boring and effective, split the admin, and keep day-to-day work on an account
that is not the break-glass one.

## 2. OFFBOARDED-OWNER and the contractor problem

The initial victim at Uber was a **contractor**. Contractors are where standing
access quietly accumulates: they are onboarded fast, given broad access to move
quickly, and offboarded inconsistently across systems. The IdP suspension lands;
the AWS key they minted six months ago does not.

`OFFBOARDED-OWNER` is built for exactly that gap. It walks the identity graph
from a live credential to its owner (and to every cross-source identity linked to
that owner by email or Vault alias), and fires the moment any linked identity is
deprovisioned while the credential stays active:

```
person: jordan (contractor)
  okta.status         = suspended     <- offboarded here
  aws_user.status     = active        <- but nobody automated the link
  aws_access_key      = still valid    <- OFFBOARDED-OWNER, Critical
```

Uber's contractor was not offboarded at the time, so this rule is not "the" Uber
rule. But the class it covers, a live credential behind an absent owner, is the
same standing-access rot, and it is the one you can actually clear before an
attacker finds it. `OUTSIDE-COLLAB-WITH-AWS` covers the live-contractor version:
a GitHub outside collaborator whose person also holds active AWS keys.

## 3. ADMIN-WITHOUT-MFA: where to spend your FIDO2 budget

Afterlife cannot see that a push was approved under social-engineering pressure.
But `ADMIN-WITHOUT-MFA` (and its non-admin sibling `USER-WITHOUT-MFA`, the
Snowflake 2024 pattern) tells you which accounts do not have MFA enforced at
all, and ranks the admins first. That is the prioritized list for rolling out
phishing-resistant MFA: start with the identities whose compromise reaches the
most systems, which is the same set `ADMIN-CONCENTRATION` surfaces. The two rules
read the same graph from two directions.

## Run it against your own org

Every rule above computes on data you already have, and the detection engine is
free forever (16 rules, MIT):

```bash
pip install afterlife-audit
make demo                      # 20 findings across 8 sources in about a minute
afterlife run --notify         # scan your own; alert on new ghost access
```

`make demo` reproduces output like the block above on synthetic data (one
`ADMIN-CONCENTRATION` across three systems, one `OFFBOARDED-OWNER`), so you can
see the shape before pointing it at anything real. Against your own environment
it uses read-only credentials from the environment and writes to a local SQLite
file. Nothing leaves your box, and nothing phones home.

## The takeaway

The Uber post-mortems all reach for the same lesson, "don't let one phish become
everything," and then stop, because the standing conditions that make that true
are invisible until you join your systems together. A phished contractor is a
Tuesday. A phished contractor who can reach admin on AWS, Google Workspace, and
Slack through one short path is a breach. Afterlife measures that second thing,
ranks it by blast radius, and hands you the short list to shorten the path,
before someone else measures it for you.

Afterlife is open source: [github.com/desledishant10/afterlife](https://github.com/desledishant10/afterlife).
The companion essay, [why a graph is the right shape for ghost access](the-graph-layer.md),
covers the identity-graph model the rules run on.
