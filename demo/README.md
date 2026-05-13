# Demo environment

A reproducible, zero-setup playground for Afterlife.

`demo/run.py` plants a synthetic mix of fresh and stale IAM credentials into
an **in-memory** AWS account (via [`moto`](https://github.com/getmoto/moto),
no Docker required), runs the real `AWSCollector` against it, then runs the
rules engine and prints findings.

## Run it

```bash
make demo
# or, without make:
.venv/bin/python demo/run.py
```

## What it plants

| Resource | Age | Last used | Fires |
|----------|-----|-----------|-------|
| user `alice` | 30d | 5d ago | nothing (fresh) |
| user `bob` | 200d | 120d ago | `UNUSED-CREDENTIAL`, `UNROTATED-KEY` |
| user `carol` | 90d | never | `NEVER-USED` |
| user `dave` | 250d | 5d ago | `UNROTATED-KEY` |
| user `eve` | 10d | never | nothing (within grace period) |
| role `LegacyDeployRole` | 300d | never | `NEVER-USED` |
| role `ForgottenAuditRole` | 250d | never | `NEVER-USED` |

Expected output: 6 findings (1 high, 5 medium).

## How the backdating works

AWS does not expose an API to set `CreateDate` or `LastUsedDate` directly —
those are populated server-side from real activity. To produce a
deterministic demo:

- `CreateDate` is controlled by wrapping `iam.create_user` / `iam.create_role`
  / `iam.create_access_key` calls in `freezegun.freeze_time(...)` — moto reads
  the (frozen) wall clock when stamping resources.
- `LastUsedDate` cannot be set via either the AWS API or freezegun, so the
  demo reaches into moto's in-process `iam_backends` and assigns an
  `AccessKeyLastUsed` object directly. This is intentionally fragile to moto
  internals, but the demo is the only consumer.

## What's *not* in the demo

- `OFFBOARDED-OWNER` — needs IdP data + cross-source identity correlation
  (Weeks 4 and 5).
- GitHub findings — needs the GitHub collector (Week 3).
- Real-world false positives — every planted credential is unambiguous so the
  expected output is fully predictable.
