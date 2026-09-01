# Contributing to Afterlife

Thanks for your interest in improving Afterlife. This guide covers local
setup, the checks your change must pass, and how the codebase is organized.

## Local setup

Afterlife targets Python 3.11+ and has no external services in its test suite
(every collector is tested against mocked APIs).

```bash
make install          # creates .venv and installs with dev extras
make demo             # sanity check: runs the self-contained synthetic demo
```

Override the interpreter with `make PYTHON=python3.12 install`.

## The checks

Every pull request must pass the same three gates CI runs:

```bash
make check            # runs lint + typecheck + tests
# or individually:
make lint             # ruff check .
make typecheck        # mypy src
make test             # pytest
```

CI runs these on Python 3.11 and 3.12 for every push and PR
(`.github/workflows/ci.yml`). A red check blocks merge.

## How the code is organized

Afterlife is five layers with narrow boundaries (see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)):

```
collectors/ -> SQLite -> identity graph -> rules engine -> scoring -> reports
```

- **Collectors** (`src/afterlife/collectors/`) are intentionally dumb: they
  pull identities/credentials and write to SQLite. No analysis, idempotent,
  tested against mocked APIs. Adding a source system means adding one
  collector file plus a test.
- **Rules** (`src/afterlife/rules/`) read from SQLite + the identity graph and
  emit `Finding`s. Each rule is one file, registered with the `@rule`
  decorator. Add the rule, document it in
  [docs/DETECTIONS.md](docs/DETECTIONS.md), and cover it in `tests/`.
- **Scoring, reporting, web** are pure readers over the same data.

## Adding a detection rule

1. Create `src/afterlife/rules/<your_rule>.py` and register it with `@rule`.
2. Add false-positive notes + remediation to `docs/DETECTIONS.md`.
3. Add the rule to the table in `README.md`.
4. Add tests to `tests/test_rules.py` (or a dedicated file).

## Commit / PR conventions

- Keep PRs focused; one logical change per PR.
- Update `CHANGELOG.md` under the appropriate section.
- No em dashes in user-facing docs or output (house style).
- Describe the change and how you tested it in the PR body.

## Reporting security issues

Do not open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md).
