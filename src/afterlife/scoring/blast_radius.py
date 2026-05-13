"""Blast radius scoring.

For each finding, estimate what an attacker could do with the surfaced credential
if it were exfiltrated. Used to lift or lower a rule's default severity.

TODO Week 7:
  - AWS: iam.simulate_principal_policy() to enumerate effective permissions
  - GitHub: enumerate PAT scopes; weight by repo sensitivity (public vs private,
    monorepos vs throwaway)
  - OAuth: enumerate granted scopes; cross-reference with API criticality
  - SSH keys: enumerate the hosts the key is authorized on
"""
