<div align="center">

<img src="https://raw.githubusercontent.com/mangrisano/cvewatcher/main/docs/logo.svg" alt="CVE Watcher" width="440">

[![CI](https://github.com/mangrisano/cvewatcher/actions/workflows/ci.yml/badge.svg)](https://github.com/mangrisano/cvewatcher/actions/workflows/ci.yml)
[![Performance](https://github.com/mangrisano/cvewatcher/actions/workflows/performance.yml/badge.svg)](https://github.com/mangrisano/cvewatcher/actions/workflows/performance.yml)
[![Container](https://img.shields.io/badge/ghcr.io-cvewatcher-2496ED?logo=docker&logoColor=white)](https://github.com/mangrisano/cvewatcher/pkgs/container/cvewatcher)
[![Docker Pulls](https://img.shields.io/docker/pulls/micheleangrisano/cvewatcher?logo=docker&logoColor=white&color=2496ED)](https://hub.docker.com/r/micheleangrisano/cvewatcher)
[![Python](https://img.shields.io/badge/python-3-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Asset inventory · NVD + OSV.dev matching · CPE auto-resolution · KEV/EPSS · Finding triage · Background monitoring · Web dashboard · Dockerized**

[Quick start](#quick-start) · [Features](#features) · [How matching works](#how-vulnerability-matching-works) · [Dashboard](#web-dashboard) · [Auth](#authentication--access-control) · [API](#api-endpoints) · [Deployment](#deployment) · [Issues](https://github.com/mangrisano/cvewatcher/issues)

</div>

> **Tell it what software you run. Learn which CVEs actually affect it.**
> CVE Watcher keeps an inventory of your assets and matches each one against the
> NIST NVD — precisely by CPE, automatically by product name, or by keyword as a
> last resort. Self-hosted, JWT-secured, with a no-build web dashboard and a
> clean JSON API.

CVE Watcher is a self-hostable FastAPI service that turns the list of software
you run into an always-current view of the vulnerabilities affecting it. You
register assets (a name and a version is enough), and it queries the NIST NVD
(and OSV.dev for language ecosystems) on demand or on a schedule, then
deduplicates and ranks findings by severity.

```bash
# add an asset — just a name and a version — and list its CVEs
# (full walk-through in the End-to-End Example below)
curl -s "$BASE/assets/$ASSET/vulnerabilities" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# → 2 vulnerabilities  (CVE-2023-44487 HIGH 7.5 · CVE-2025-23419 MEDIUM 4.3)
```

## Features

- **Asset inventory** — track software with name, version, optional CPE, **ecosystem** and description, scoped per user.
- **SBOM import** — upload a **CycloneDX** or **SPDX** JSON SBOM to create one asset per package in one go, each with its OSV.dev ecosystem taken from the package URL (purl).
- **Precise CVE matching** — NVD `cpeName` lookups evaluate version ranges server-side (no keyword 100-result cap).
- **Automatic CPE resolution** — derive a CPE from a product name via the NVD CPE dictionary.
- **Keyword fallback** — free-text NVD search with local product/version filtering to cut the noise.
- **OSV.dev for packages** — assets that declare an ecosystem (PyPI, npm, Go, Maven, …) are matched on OSV.dev, plus NVD when they also carry a CPE; CVSS vectors are parsed into a base score and severity band.
- **Exploitation intelligence** — every finding is flagged with **CISA KEV**
  (actively exploited in the wild) and scored with **FIRST.org EPSS** (exploit
  probability), and results are ranked KEV-first.
- **Finding triage** — mark each finding `open` / `acknowledged` / `fixed` / `false_positive` / `accepted_risk`; suppressed states are hidden by default.
- **Global findings view** — a cross-asset summary and table (`/findings`) with severity/status counts and **CSV/JSON export**.
- **Search, filters & sorting** — filter by severity, status and time window; search by CVE or asset; sort every column.
- **Background monitoring** — opt-in scheduler that rescans assets and alerts on new CVEs, plus an optional **per-user email digest**.
- **Prometheus metrics** — aggregate assets and findings exposed at `/metrics`.
- **Web dashboard** — redesigned single-page UI (vanilla JS + hand-written CSS, **no build step, no CDN**) with Overview / Assets / Vulnerabilities sections and light/dark themes.
- **Secure JSON API** — JWT auth, per-user isolation, OpenAPI docs at `/docs` and `/redoc`.
- **Self-hosted** — PostgreSQL + Alembic migrations, shipped as a Docker image on GHCR.

## Requirements

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose (recommended), **or**
- Python >= 3.13 and a PostgreSQL database for a local run

## Quick start

```bash
git clone https://github.com/mangrisano/cvewatcher.git
cd cvewatcher
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
```

Then open:

- API — http://localhost:8000
- Interactive docs (Swagger UI) — http://localhost:8000/docs
- Web dashboard — http://localhost:8000/dashboard

## Web Dashboard

A self-contained single-page dashboard is served at
[`/dashboard`](http://localhost:8000/dashboard). It needs **no build step and no
CDN** (vanilla JavaScript + hand-written CSS), keeps the JWT in `localStorage`,
and has **light and dark** themes (toggle in the user menu). It is organised into
three sections:

- **Overview** — your security posture at a glance: total findings, KEV
  (actively exploited) count, Critical + High count and asset count, plus
  breakdowns by severity and by triage status.
- **Assets** — full inventory management: add / edit / delete assets (with an
  optional **ecosystem** to enable OSV.dev), **import an SBOM** and filter by name.
- **Vulnerabilities** — a cross-asset table of every finding, each with a linked
  CVE id, colour-coded **severity** badge, CVSS **score**, **KEV** badge, **EPSS**
  probability and an inline **triage status** selector. You can search by CVE or
  asset, filter by severity/status, toggle suppressed findings, sort any column,
  page through the results (50 per page), **export** to CSV/JSON, and **Rescan**
  to scan all your assets now.

The dashboard reads findings **from the database**, as stored by the last scan,
so it stays fast with thousands of findings and keeps working when NVD or
OSV.dev are down. A new, imported or re-identified asset is scanned in the
background right away; the Vulnerabilities page shows when the last scan ran.

If the NIST NVD service cannot be reached, the dashboard surfaces the error
rather than an empty list — an empty result only means NVD reported no matching
CVEs.

The login card can toggle to a registration form, but **public sign-up is
closed by default**: only the very first account (bootstrap) can always
register — after that, new sign-ups require `REGISTRATION_ENABLED=true` (see
[Authentication & Access Control](#authentication--access-control)). Sessions
refresh themselves silently in the background using the refresh token, so you
stay signed in without re-entering credentials until the refresh token itself
expires (`JWT_REFRESH_TOKEN_EXPIRE_DAYS`). Refresh tokens are single-use: each
refresh returns a new one, so a stolen token stops working as soon as the real
user refreshes.

## Authentication & Access Control

| Variable                          | Default | Description                                                              |
| --------------------------------- | ------- | ------------------------------------------------------------------------ |
| `REGISTRATION_ENABLED`            | `false` | Allow new sign-ups after the first (bootstrap) account is created        |
| `REGISTER_MAX_ATTEMPTS`           | `5`     | Max `/auth/register` attempts per IP within the window                   |
| `REGISTER_WINDOW_SECONDS`         | `3600`  | Rate-limit window (seconds) for registration attempts                    |
| `LOGIN_MAX_ATTEMPTS`              | `5`     | Max failed `/auth/login` attempts per email+IP within the window         |
| `LOGIN_IP_MAX_ATTEMPTS`           | `30`    | Max failed `/auth/login` attempts per IP (any account) within the window |
| `LOGIN_WINDOW_SECONDS`            | `300`   | Rate-limit window (seconds) for failed login attempts                    |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `30`    | Access token lifetime; the dashboard refreshes it silently on expiry     |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS`   | `7`     | Refresh token lifetime; expiry forces a real re-login                    |

The very first account created on a fresh install always succeeds — this
bootstrap exception lets you stand up an admin user without pre-configuring
anything. Once at least one user exists, further registration is gated by
`REGISTRATION_ENABLED`. Check `GET /auth/registration-status` to see whether
sign-up is currently open.

**Behind a reverse proxy** (nginx, traefik, …) rate limits are keyed on the
client IP, so uvicorn must trust the proxy's `X-Forwarded-For`: set
`FORWARDED_ALLOW_IPS` to the proxy's IP or subnet (e.g. the Docker network).
Otherwise every client appears as the proxy and shares one limit. Avoid `*`
unless port 8000 is reachable only through the proxy: anyone reaching it
directly could forge the header and bypass the limits.

## How Vulnerability Matching Works

CVE Watcher matches an asset to CVEs in three ways, chosen automatically:

1. **CPE lookup** — if the asset has a CPE 2.3 id, the query is delegated to
   NVD's `cpeName` filter, which evaluates version ranges server-side. Partial
   CPEs are padded to the full 13-component form.
2. **Automatic CPE resolution** — with no CPE, the product name is looked up in
   NVD's CPE dictionary (applications, operating systems and hardware),
   following `deprecatedBy` links. A candidate matches only on an exact
   (separator-insensitive) `product` or `vendor+product`, so `Apache HTTP
Server` resolves to `apache:http_server` while `nginx` never pulls in
   `nginx_proxy_manager`. The asset version is injected and the lookup from
   step 1 runs for each resolved pair.
3. **Keyword search** — last resort when the name can't be resolved: an NVD
   keyword search filtered locally by product identity and version range,
   falling back to the CVE summary when a CVE carries no CPE data.

> **OSV.dev covers assets that declare an `ecosystem`** (PyPI, npm, Go, Maven,
> …), the domain NVD/CPE matches poorly. Such an asset is looked up on OSV.dev
> only, unless you also give it a CPE: then NVD is queried too, and the results
> are merged and deduplicated by CVE. This keeps a large SBOM import from
> exhausting NVD's rate limit. CVSS vectors are parsed into a base score and
> severity band.

> **You usually only need a name and a version** — a CPE is an optional
> precision lever. Provide one when the name you track differs from the
> canonical token (e.g. `IIS` is
> `cpe:2.3:a:microsoft:internet_information_services`); look it up in the
> [NVD CPE dictionary](https://nvd.nist.gov/products/cpe/search).

## Background Monitoring & Notifications

The application can periodically scan every registered asset against the NIST NVD
and alert on newly discovered vulnerabilities. It is **opt-in** and configured via
environment variables (see `.env.example`):

| Variable                   | Default   | Description                                     |
| -------------------------- | --------- | ----------------------------------------------- |
| `MONITOR_ENABLED`          | `false`   | Enable the background scheduler                 |
| `MONITOR_INTERVAL_MINUTES` | `360`     | Minutes between scans                           |
| `SCAN_NEW_ASSETS`          | `true`    | Scan an asset as soon as it is added or changed |
| `ENRICH_ENABLED`           | `true`    | Add CISA KEV flag + FIRST.org EPSS score        |
| `DIGEST_ENABLED`           | `false`   | Email each user a periodic digest of findings   |
| `DIGEST_INTERVAL_MINUTES`  | `1440`    | Minutes between digest emails                   |
| `NOTIFY_CONSOLE`           | `true`    | Log alerts via the application logger           |
| `NOTIFY_WEBHOOK_URL`       | _(unset)_ | POST every alert as JSON to this URL            |
| `NOTIFY_SLACK_WEBHOOK_URL` | _(unset)_ | Post every alert to a Slack incoming webhook    |
| `NOTIFY_EMAIL_HOST` …      | _(unset)_ | SMTP relay for all emails (see `.env.example`)  |

When enabled, a scan runs at startup and then on the configured interval. An
alert is raised when a CVE is first found on an asset, and when a known one
**enters the CISA KEV catalog** or **its severity rises** (NVD often publishes
CVEs unscored and rates them days later). Each alert includes the KEV flag and
EPSS score. Manual scans (`/assets/{id}/monitor`, `/assets/monitoring/scan-all`)
raise the same alerts. Scans of the same asset never overlap, so a finding is
announced once even if a manual scan starts while another is running.

Manual scans and `GET /cves/search` query NVD live, so each user gets
`LIVE_LOOKUPS_PER_HOUR` of them (default 30); past that they answer **429**
with `Retry-After`. Reading stored findings is never limited.

Alerts go to two audiences:

- **Admins** receive every alert on the `NOTIFY_*` channels; the email feed goes
  to `NOTIFY_EMAIL_TO` and to every address in `ADMIN_EMAILS`.
- **Each user** receives the alerts on their own assets, by email to their
  account address (always on when SMTP is configured) and optionally on their
  own Slack, Microsoft Teams or Discord webhook, or Telegram bot. In the
  dashboard (user menu →
  _Notifications_) each user picks the minimum severity (default **High**),
  whether KEV findings always alert, and whether to be told about escalations.
  Findings marked _fixed_ or _false positive_ never alert; _accepted risk_ ones
  only alert when they enter KEV.

Independently, `DIGEST_ENABLED` emails each user a periodic digest of their
active findings.

## API Endpoints

### Authentication

- `GET /auth/registration-status` - Check whether public sign-up is currently open
- `POST /auth/register` - Register new user (subject to registration gating and rate limiting)
- `POST /auth/login` - User login (rate-limited per email+IP)
- `POST /auth/refresh` - Exchange a refresh token for a new access token **and a new refresh token** (the one sent is revoked: store the new one)
- `POST /auth/logout` - Logout user (revokes access and refresh tokens)

### Asset Management

- `POST /assets/` - Create new asset
- `POST /assets/import-sbom` - Create assets from a CycloneDX or SPDX JSON SBOM (max 5 MB, 2000 components)
- `GET /assets/` - List user's assets
- `GET /assets/{asset_id}` - Get specific asset details
- `PATCH /assets/{asset_id}` - Update asset information
- `DELETE /assets/{asset_id}` - Remove asset

### CVE Monitoring

- `GET /assets/{asset_id}/vulnerabilities` - The asset's findings from its last scan
- `PATCH /assets/{asset_id}/vulnerabilities/{cve_id}` - Set a finding's triage status
- `GET /assets/{asset_id}/monitor` - Monitor single asset for CVEs
- `POST /assets/monitoring/scan-all` - Scan all user assets
- `GET /assets/monitoring/report` - Report of recent CVEs from the last scans

### Findings

- `GET /findings` - Cross-asset findings from the last scan: counts plus one page (`limit` ≤ 500, `offset`), filtered by `severity`, `status`, `q`, `days`, sorted by `sort`/`order`; `?refresh=true` scans first
- `GET /findings/export` - Export findings as CSV or JSON (`?format=csv|json`)

### CVE Data

- `GET /cves/fetch-recent` - Fetch and store recent CVEs from NIST NVD (admin only: `ADMIN_EMAILS`)
- `GET /cves/recent` - List stored CVEs that affect your assets
- `GET /cves/search` - Search CVEs by product (and optional version)
- `GET /cves/vulnerabilities` - All findings across your assets, from the last scans

### User & Health

- `GET /user` - Get the current user's profile
- `POST /user/password` - Change your password: `current_password` + `new_password`. Signs out every other session and returns a fresh token pair for this one; the owner gets an email when SMTP is configured. Wrong current passwords are rate-limited (5 per 15 minutes)
- `GET /user/notifications` - Your alert settings (webhook URLs and bot tokens are never returned, only whether they are set)
- `PUT /user/notifications` - Update them: `min_severity`, `always_kev`, `escalations`, `slack_webhook_url`, `teams_webhook_url`, `discord_webhook_url`, `telegram_bot_token` + `telegram_chat_id` (only the fields sent change; `""` removes a channel; each URL must be an HTTPS webhook of that service)
- `POST /user/notifications/test` - Send a test alert to your channels (5 per hour)
- `GET /health` - Service health check
- `GET /metrics` - Prometheus metrics (aggregate assets & findings)

### Web UI

- `GET /dashboard` - Single-page web dashboard (assets & vulnerabilities)

## Technology Stack

- **Backend**: FastAPI (Python)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Authentication**: JWT with joserfc
- **Migration**: Alembic
- **Scheduling**: APScheduler (optional background monitoring)
- **Container**: Docker & Docker Compose
- **External data**: NIST NVD & OSV.dev, enriched with CISA KEV and FIRST.org EPSS (CVSS parsed with `cvss`)
- **Frontend**: single-page dashboard in vanilla JS + hand-written CSS (no build step, no CDN)

## Deployment

CVE Watcher ships as a Docker image and a Compose stack (app + PostgreSQL).

### Docker Compose

The Compose file lives in `docker/`, so pass it with `-f` (or `cd docker`
first). It reads configuration from `.env` in the repo root — copy
`.env.example` to `.env` before the first run.

```bash
docker compose -f docker/docker-compose.yml up --build -d   # start app + database in the background
docker compose -f docker/docker-compose.yml logs -f app     # follow the application logs
docker compose -f docker/docker-compose.yml down            # stop and remove the stack
```

### Prebuilt image

Every tagged release publishes the image to **GHCR** and **Docker Hub**. Point
your own Compose file or `docker run` at it instead of building locally:

```bash
docker pull ghcr.io/mangrisano/cvewatcher:latest          # GitHub Container Registry
docker pull micheleangrisano/cvewatcher:latest           # Docker Hub
```

Provide the database URL and secrets through environment variables (see
`.env.example`); never ship the defaults to production.

## End-to-End Example (curl)

A complete flow from zero to a list of CVEs, using only the API. The same thing
can be done click-by-click in the [dashboard](http://localhost:8000/dashboard).

```bash
BASE=http://localhost:8000

# 1. Register a user
curl -s -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"ciso","email":"ciso@example.com","password":"Password123"}'

# 2. Log in and capture the JWT access token
TOKEN=$(curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"ciso@example.com","password":"Password123"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# 3. Add an asset — just a name and a version, no CPE needed
ASSET=$(curl -s -X POST "$BASE/assets/" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"nginx","version":"1.24.0","description":"edge reverse proxy"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])")

# 4. Ask for its vulnerabilities (all time, any severity)
curl -s "$BASE/assets/$ASSET/vulnerabilities" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

You can narrow the result with query parameters:

```bash
# Only HIGH severity, published in the last 365 days
curl -s "$BASE/assets/$ASSET/vulnerabilities?severity=HIGH&days=365" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

| Query parameter | Values                                 | Meaning                                                          |
| --------------- | -------------------------------------- | ---------------------------------------------------------------- |
| `severity`      | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` | Keep only findings at that severity                              |
| `days`          | integer (e.g. `30`, `90`, `365`)       | Only CVEs published in the last N days; omit or `0` for all time |

> If NVD is unreachable the endpoint returns **HTTP 503** rather than an empty
> list, so an empty `vulnerabilities` array always means "no known CVEs", never
> "the lookup failed".

### Importing an SBOM

Instead of adding packages one by one, generate an SBOM with a tool such as
[Syft](https://github.com/anchore/syft) and import it:

```bash
syft dir:. -o cyclonedx-json > sbom.json

curl -s -X POST "$BASE/assets/import-sbom" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  --data-binary @sbom.json | python3 -m json.tool
```

Each component with a package URL of a supported type (`pypi`, `npm`, `golang`,
`maven`, `cargo`, `gem`, `nuget`, `composer`, `pub`, `hex`) becomes an asset
with the matching ecosystem. The response lists what was skipped: packages you
already track (same name and version), names or versions too long to store, and
components without a supported purl. The new assets are scanned in the
background right after the import (see `SCAN_NEW_ASSETS`).

## Development

```bash
uv sync                                 # install dependencies into .venv
uv run ruff check app tests             # lint
uv run ruff format --check app tests    # formatting check
uv run pytest -q                        # run the test suite
```

The test suite mocks the NIST NVD client, so it never touches the network.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

If CVE Watcher is useful to you, the best ways to support it are:

- Star the repo to help others discover it
- [Open an issue](https://github.com/mangrisano/cvewatcher/issues) for bugs or ideas
- Send a pull request
- Share it with others who track software vulnerabilities

## License

This project is licensed under the [MIT License](LICENSE).

---
