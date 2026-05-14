# Producing the dashboard screenshots

The README references five dashboard screenshots in `docs/media/`. This doc
explains exactly which views to capture, the URLs (with `make demo` data
already loaded), and the suggested capture mechanics.

## Setup

```bash
# 1. Generate the demo state and leave the SQLite file at ./.afterlife-demo.db.
make demo

# 2. Start the dashboard against it.
.venv/bin/afterlife serve --db-path .afterlife-demo.db
# (Dashboard at http://127.0.0.1:8000)
```

Recommended:

- **Dark mode** at the OS level (System Settings → Appearance → Dark on
  macOS, similar on Linux). The dashboard's CSS variables follow
  `prefers-color-scheme: dark` and the dark palette is what's shown in
  marketing material.
- **Browser window width** consistent across all five shots so the
  dashboard renders identically. ~1400px wide works well.
- **Browser**: any modern Chromium / Firefox / Safari. Default DPI.
- **Capture tool**: Chrome DevTools' built-in "Capture full size
  screenshot" (Cmd+Shift+P, type "screenshot") gives clean PNGs with no
  window chrome. macOS's Screenshot.app (Cmd+Shift+4) also works for a
  region grab.

## The five shots

Save each as `docs/media/<name>.png`.

### 1. Overview (`overview.png`)

URL: `http://127.0.0.1:8000/`

Shows: severity tiles (3 critical, 3 high, 5 medium, 1 low), the severity
+ blast-tier bar charts, the last-scan-per-source table, the top
findings list. Single full-page capture.

### 2. Findings, critical filter (`findings-critical.png`)

URL: `http://127.0.0.1:8000/findings?severity=critical`

Shows: filter bar with severity=critical applied, the four critical
findings expanded inline (OFFBOARDED-OWNER on bob's key, OFFBOARDED-OWNER
on carol's key, CROSS-ACCOUNT-TRUST on the external role, ADMIN-CONCENTRATION
on dave). Click the chevron on a couple of findings before capturing so
the evidence/factors are visible.

### 3. Finding detail (`finding-detail.png`)

URL: `http://127.0.0.1:8000/findings/1` (or whichever OFFBOARDED-OWNER
is finding id=1 in your run)

Shows: severity + blast badges, linked owner person card with all
cross-source identities, linked credential card with scopes, full
evidence pre block, suggested remediation. This is the "everything
clicks together" shot.

### 4. Person detail, alice 7-way (`person-detail.png`)

URL: `http://127.0.0.1:8000/persons/aws/arn:aws:iam::123456789012:user/alice`

Shows: the identity graph payoff. Alice's 7 linked identities (aws,
azure, github, gitlab, google, slack, vault), her owned credentials
table, any findings against her. This is the screenshot that sells the
cross-source identity graph as the project's centerpiece.

### 5. Identities, cross-source only (`identities.png`)

URL: `http://127.0.0.1:8000/identities?cross_source_only=true`

Shows: the 6 cross-source persons, each with their per-system identity
breakdown and statuses (bob's google: suspended, carol's google:
archived, etc. shown in red). One full-page capture.

## After capturing

```bash
cd /Users/dishantdesle/Projects/afterlife
ls docs/media/
# overview.png  findings-critical.png  finding-detail.png  person-detail.png  identities.png

git add docs/media/*.png
git commit -m "Add dashboard screenshots"
git push
```

## File sizes

Optimize before committing if any single PNG is >500KB:

```bash
# pngquant gives the best size/quality ratio
brew install pngquant
pngquant --quality=70-90 docs/media/*.png --ext .png --force
```

A reasonable target is ~200-400KB per shot, ~1.5MB total. GitHub serves
them with caching so it's not a load issue, but smaller is nicer for
mobile viewers and people on slow networks.

## Where they end up in the README

Once committed, the README's "Web dashboard" section will pick them up.
Replace the prose paragraph today with a screenshot strip; an
`<details>` block can hide the per-page descriptions and just show the
images:

```markdown
## Web dashboard

`afterlife serve` launches a local FastAPI dashboard.

<p>
  <img alt="Overview" src="docs/media/overview.png" width="320">
  <img alt="Findings" src="docs/media/findings-critical.png" width="320">
  <img alt="Person detail" src="docs/media/person-detail.png" width="320">
</p>

<details>
<summary>More screenshots</summary>

| Finding detail | Identities |
|---|---|
| ![Finding](docs/media/finding-detail.png) | ![Identities](docs/media/identities.png) |

</details>
```
