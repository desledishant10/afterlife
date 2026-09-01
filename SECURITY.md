# Security Policy

Afterlife is a security tool, so we hold its own posture to a high bar. Thank
you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub
issues.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Provide a description, reproduction steps, affected version, and impact.

You will receive an acknowledgement, and we will work with you on a fix and a
coordinated disclosure timeline. Please give us a reasonable window to
remediate before any public disclosure.

## Scope

Afterlife runs locally and reads from cloud/IdP/SaaS APIs using credentials
you supply. Areas of particular interest:

- Any path that could leak collected credentials, tokens, or identity data
  (logs, reports, the local dashboard, error messages).
- The local web dashboard (`afterlife serve`): it is designed to be
  read-only, unauthenticated, and bound to localhost. Reports of it writing
  to the database, binding to non-local interfaces, or being exploitable via
  a crafted database are in scope.
- Report generation (HTML/PDF/SARIF/JSON): injection or path-traversal via
  attacker-influenced field values.
- Dependency vulnerabilities with a practical exploit path.

## Supported versions

Afterlife is pre-1.0. Security fixes land on the latest released version and
`main`. Older versions are not maintained; please upgrade.

## Handling of secrets

Afterlife never persists the credentials used to authenticate to source
systems; they are read from flags/environment at scan time and used only for
that scan. If you find a case where a credential is written to disk, the
database, or a report, treat it as a vulnerability and report it privately.
