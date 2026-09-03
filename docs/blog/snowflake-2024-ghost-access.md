# The Snowflake 2024 breaches were an MFA problem

A teardown of the 2024 Snowflake customer breaches through the lens of
[Afterlife](https://github.com/desledishant10/afterlife), a self-hosted
cross-source ghost-access auditor. I want to be honest up front, the same way I
was about Uber: **Afterlife would not have stopped this, and it does not even
collect Snowflake today.** What the Snowflake breaches are is the cleanest recent
example of the exact standing condition Afterlife is built to hunt, and unlike
most breach stories the lesson generalizes cleanly to every system you do point
it at.

In mid-2024 a single threat actor, which Mandiant tracks as UNC5537, worked
through around 165 organizations' Snowflake environments and walked out with
customer data from some of the largest brands online: Ticketmaster, AT&T,
Santander, and a long list of others.

## What actually happened

Snowflake itself was not breached. There was no vulnerability in the platform.
Mandiant's own summary is almost boringly precise: the actor succeeded against
accounts that met three conditions at once.

1. The account authenticated with a **single factor**, a username and password,
   with no MFA enforced.
2. The credentials had **already leaked**, mostly through infostealer malware on
   someone's machine, in some cases years earlier, with exposures dating back to
   2020.
3. The account had **no network allow list** restricting where it could be
   reached from.

Put plainly: the attacker logged in. With a valid password, to an account that
asked for nothing else, from anywhere. Some of those credentials belonged to
contractors, and some belonged to people who had already left. None of them
should still have worked the way they did.

That is not an exotic attack. It is the atmosphere a lot of SaaS lives in: a data
store behind a password, reachable from the internet, with a credential nobody
rotated and a second factor nobody enforced.

## The honest scope: what Afterlife does and does not see

Two hard limits first, because I would rather you find them here than in the
comments:

- Afterlife would **not** have stopped the infostealer or the credential theft.
  That is endpoint security and EDR.
- Afterlife does **not collect Snowflake today.** Its nine collectors cover cloud
  IAM, code hosts, and your IdP, not data warehouses, so I cannot claim it would
  have scanned those accounts directly. A SaaS-warehouse collector is the obvious
  next source, and this breach is most of why.

So why write this up at all. Because the two conditions that turned a leaked
password into 165 breached tenants, no second factor and a credential that
outlived its owner, are the two things Afterlife ranks for you across every
system it does cover. And in most orgs, the place those conditions are cheapest
to fix is the IdP that already fronts your SaaS.

## 1. USER-WITHOUT-MFA and ADMIN-WITHOUT-MFA: the missing second factor

This is the rule the Snowflake breaches are tagged to. `USER-WITHOUT-MFA` fires
on an active identity with no enforced second factor. `ADMIN-WITHOUT-MFA` is its
higher-severity sibling for privileged accounts, and blast-radius scoring pushes
the admins to the top. It is the prioritized list for exactly the rollout that
would have prevented this: turn on phishing-resistant MFA, starting with the
accounts whose compromise reaches the most.

Here is the shape on the sources Afterlife does read:

```
$ afterlife analyze
CRITICAL  ADMIN-WITHOUT-MFA   google admin ops@corp        2-step verification not enforced
HIGH      OFFBOARDED-OWNER    aws iam key AKIA...7QF        owner suspended in Okta 88d ago
MEDIUM    USER-WITHOUT-MFA    okta user contractor@vendor  active, password only, reaches 4 apps
MEDIUM    USER-WITHOUT-MFA    okta user dana@corp          active, password only
MEDIUM    UNUSED-CREDENTIAL   gcp sa key analytics         valid, unused 411d
```

There is an honest nuance here, and it is the useful part. The Snowflake accounts
that got hit were mostly using **local Snowflake logins**, not single sign-on. If
those same accounts had been behind your IdP with SSO and enforced MFA, they
would not have been password-only in the first place, and the IdP is exactly
where `ADMIN-WITHOUT-MFA` and `USER-WITHOUT-MFA` look. Afterlife cannot see a
local Snowflake password. It can tell you which of your IdP identities are one
leaked password away from everything the IdP fronts, which is the same question
one layer up.

## 2. OFFBOARDED-OWNER: credentials that outlived the people

The second condition is the one this whole tool exists for. Some of the
credentials the actor used were old, pulled from infostealer logs collected long
before, and in some cases they belonged to people who were no longer with the
company. A password leaked once, sat in a log, and stayed valid because nobody
tied "this person is gone" to "this credential is still live."

`OFFBOARDED-OWNER` is the join that closes that gap: it walks from a live
credential to its owner and every identity linked to that owner, and fires the
moment one of them is deprovisioned while the credential stays active.
`UNUSED-CREDENTIAL` and `NEVER-USED` catch the adjacent case, a credential that
is technically valid but has not been touched in a year. That is a credential you
can revoke today at zero cost, and one fewer entry in the next infostealer dump.

## Run it against your own org

The detection engine is free forever, 16 rules, MIT:

```bash
pip install afterlife-audit
make demo                      # 20 findings across 8 sources in about a minute
afterlife run --notify         # scan your own; alert on new ghost access
```

Point it at your IdP first. The single most Snowflake-relevant thing you can do
in the next hour is get the ranked list of active accounts with no enforced
second factor, admins at the top, and start turning MFA on from the top down.

## The takeaway

The Snowflake breaches got told as a story about one threat actor and a lot of
famous victims. The durable version is smaller and more uncomfortable: valid
passwords, no second factor, credentials that outlived their owners, reachable
from anywhere. Afterlife does not collect Snowflake, and it would not have
stopped the malware. What it does is hand you the ranked list of those same two
conditions everywhere they already exist, in your cloud, your code hosts, and
your IdP, so the next leaked password has nothing left to open.

Afterlife is open source: [github.com/desledishant10/afterlife](https://github.com/desledishant10/afterlife).
The companion teardown, [the Uber 2022 breach as a blast-radius problem](uber-2022-ghost-access.md),
covers what happens when one foothold reaches admin everywhere at once.
