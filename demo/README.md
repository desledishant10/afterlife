# Demo environment

A reproducible playground that plants stale credentials into LocalStack + a
throwaway GitHub org so anyone can `git clone && make demo` and see Afterlife
catch real findings in under five minutes.

Planned for Week 10. Will include:

- `seed_localstack.py` — boots LocalStack, creates IAM users with planted stale
  access keys (unused, never-used, owned-by-offboarded-user).
- `seed_github.py` — creates a test org with planted PATs and deploy keys for
  removed members. Requires a sandbox GitHub account.
- `seed_idp.py` — populates a fake Okta/Google Workspace tenant via the
  Directory API or a recorded fixture.

The demo is the single biggest hiring signal for this project. Build it before
adding new rules.
