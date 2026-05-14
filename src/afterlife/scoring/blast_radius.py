"""Blast-radius scoring.

For each finding, estimate what an attacker could do if the surfaced credential
were exfiltrated. The score is a float in [0, 1] with three labels:
  >= 0.7   broad
  >= 0.4   moderate
  <  0.4   limited

Scoring is intentionally explainable: every score has a `factors` list that
names the signals that produced it, so a reviewer can see why one OFFBOARDED-
OWNER finding outranks another.

This module operates entirely on data already in the SQLite store. No live API
calls. AWS policy enrichment (mapping access keys to attached managed policies)
happens at collector time and lands as the credential's `scopes` field.
"""

from __future__ import annotations

from afterlife.models import BlastRadius, Credential

# Base score by credential type. Reflects what the credential *can* be,
# before looking at attached policies/scopes.
TYPE_PRIORS: dict[str, float] = {
    "aws_access_key": 0.55,
    "aws_iam_role": 0.50,
    "github_app_installation": 0.45,
    "github_pat": 0.50,
    "github_deploy_key": 0.20,
}
DEFAULT_PRIOR = 0.30

# Substrings (in lowercased scope strings) that indicate elevated access.
ELEVATED_PATTERNS = (
    "administratoraccess",
    "poweruseraccess",
    "fullaccess",
    "*:*",
    "admin",
    "write:org",
    "delete_repo",
    "iam:",
    "sts:",
    "kms:",
    "secretsmanager:",
)

# Substrings that indicate read-only / low-impact access.
READONLY_PATTERNS = (
    "readonlyaccess",
    "viewonly",
    "viewer",
    "audit",
)

# A credential with more than this many scopes is "broad" almost by definition.
BROAD_SCOPE_COUNT = 5


def score(credential: Credential) -> BlastRadius:
    factors: list[str] = []

    base = TYPE_PRIORS.get(credential.credential_type, DEFAULT_PRIOR)
    factors.append(f"type prior: {credential.credential_type} ({base:.2f})")
    s = base

    scopes = credential.scopes or []
    if scopes:
        text = " ".join(scopes).lower()

        elevated = [p for p in ELEVATED_PATTERNS if p in text]
        if elevated:
            s += 0.30
            factors.append(f"elevated: {', '.join(elevated[:3])}")

        readonly = [p for p in READONLY_PATTERNS if p in text]
        if readonly and not elevated:
            s -= 0.15
            factors.append(f"read-only signal: {', '.join(readonly[:3])}")

        if len(scopes) >= BROAD_SCOPE_COUNT:
            s += 0.10
            factors.append(f"{len(scopes)} scopes attached")

    if credential.credential_type == "github_deploy_key" and "write" in scopes:
        s += 0.20
        factors.append("deploy key has write access")

    # AWS admin flag from IdP metadata bumps roles/users that act on behalf
    # of admins (set by AWSCollector when Path indicates an admin or when
    # the user has high-power policies).
    if (credential.metadata or {}).get("is_admin"):
        s += 0.15
        factors.append("flagged as admin in source system")

    s = max(0.0, min(1.0, s))
    return BlastRadius(score=round(s, 2), factors=factors)
