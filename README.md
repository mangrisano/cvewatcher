<div align="center">

<img src="https://raw.githubusercontent.com/mangrisano/cvewatcher/main/docs/logo.svg" alt="CVE Watcher" width="440">

[![CI](https://github.com/mangrisano/cvewatcher/actions/workflows/ci.yml/badge.svg)](https://github.com/mangrisano/cvewatcher/actions/workflows/ci.yml)
[![Performance](https://github.com/mangrisano/cvewatcher/actions/workflows/performance.yml/badge.svg)](https://github.com/mangrisano/cvewatcher/actions/workflows/performance.yml)
[![Container](https://img.shields.io/badge/ghcr.io-cvewatcher-2496ED?logo=docker&logoColor=white)](https://github.com/mangrisano/cvewatcher/pkgs/container/cvewatcher)
[![Docker Pulls](https://img.shields.io/docker/pulls/micheleangrisano/cvewatcher?logo=docker&logoColor=white&color=2496ED)](https://hub.docker.com/r/micheleangrisano/cvewatcher)
[![Python](https://img.shields.io/badge/python-3-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Asset inventory · NVD-powered CVE matching · CPE auto-resolution · Severity & time filters · Background monitoring · Web dashboard · Dockerized**

[Quick start](#quick-start) · [Features](#features) · [How matching works](#how-vulnerability-matching-works) · [Dashboard](#web-dashboard) · [API](#api-endpoints) · [Deployment](#deployment) · [Issues](https://github.com/mangrisano/cvewatcher/issues)

</div>

> **Tell it what software you run. Learn which CVEs actually affect it.**
> CVE Watcher keeps an inventory of your assets and matches each one against the
> NIST NVD — precisely by CPE, automatically by product name, or by keyword as a
> last resort. Self-hosted, JWT-secured, with a no-build web dashboard and a
> clean JSON API.

CVE Watcher is a self-hostable FastAPI service that turns the list of software
you run into an always-current view of the vulnerabilities affecting it. You
register assets (a name and a version is enough), and it queries the NIST NVD on
demand or on a schedule, then deduplicates and ranks findings by severity.

```bash
# add an asset — just a name and a version — and list its CVEs
# (full walk-through in the End-to-End Example below)
curl -s "$BASE/assets/$ASSET/vulnerabilities" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# → 2 vulnerabilities  (CVE-2023-44487 HIGH 7.5 · CVE-2025-23419 MEDIUM 4.3)
```

## Features

- **Asset inventory** — track software with name, version, optional CPE and description, scoped per user.
- **Precise CVE matching** — NVD `cpeName` lookups evaluate version ranges server-side (no keyword 100-result cap).
- **Automatic CPE resolution** — derive a CPE from a product name via the NVD CPE dictionary.
- **Keyword fallback** — free-text NVD search with local product/version filtering to cut the noise.
- **Triage filters** — filter findings by severity and time window (last 30/90/365 days).
- **Exploitation intelligence** — every finding is flagged with **CISA KEV**
  (actively exploited in the wild) and scored with **FIRST.org EPSS** (exploit
  probability), and results are ranked KEV-first.
- **Background monitoring** — opt-in scheduler that rescans assets and alerts on new CVEs.
- **Web dashboard** — single-page UI (vanilla JS + Tailwind, no build step).
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

A self-contained web dashboard is served at [`/dashboard`](http://localhost:8000/dashboard).
It requires no build step (vanilla JS + Tailwind via CDN) and lets you:

- Sign in with your CVE Watcher credentials (the JWT is kept in `localStorage`).
- Add assets with name, version, CPE and description.
- Browse your asset inventory, **filter it by name and version**, and **edit**
  or delete each entry inline.
- Inspect the vulnerabilities of an asset, filtered by a **time period**
  selector (All time, last 30/90/365 days) and by **severity**
  (Critical/High/Medium/Low). Each finding shows the CVE id (linked to MITRE),
  a colour-coded severity badge, CVSS score and summary.

If the NIST NVD service cannot be reached, the dashboard shows an explicit
warning banner instead of an empty list — an empty result is only displayed
when NVD genuinely reports no matching CVEs.

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

> **You usually only need a name and a version** — a CPE is an optional
> precision lever. Provide one when the name you track differs from the
> canonical token (e.g. `IIS` is
> `cpe:2.3:a:microsoft:internet_information_services`); look it up in the
> [NVD CPE dictionary](https://nvd.nist.gov/products/cpe/search).

## Background Monitoring & Notifications

The application can periodically scan every registered asset against the NIST NVD
and alert on newly discovered vulnerabilities. It is **opt-in** and configured via
environment variables (see `.env.example`):

| Variable                   | Default   | Description                                  |
| -------------------------- | --------- | -------------------------------------------- |
| `MONITOR_ENABLED`          | `false`   | Enable the background scheduler              |
| `MONITOR_INTERVAL_MINUTES` | `360`     | Minutes between scans                        |
| `ENRICH_ENABLED`           | `true`    | Add CISA KEV flag + FIRST.org EPSS score     |
| `NOTIFY_CONSOLE`           | `true`    | Log new findings via the application logger  |
| `NOTIFY_WEBHOOK_URL`       | _(unset)_ | POST new findings as JSON to this URL        |
| `NOTIFY_SLACK_WEBHOOK_URL` | _(unset)_ | Post findings to a Slack incoming webhook    |
| `NOTIFY_EMAIL_HOST` …      | _(unset)_ | Send findings over SMTP (see `.env.example`) |

When enabled, a scan runs at startup and then on the configured interval; only
newly detected CVEs trigger notifications. Each notification includes the KEV
flag and EPSS score so the most urgent findings stand out.

## API Endpoints

### Authentication

- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout user

### Asset Management

- `POST /assets/` - Create new asset
- `GET /assets/` - List user's assets
- `GET /assets/{asset_id}` - Get specific asset details
- `PATCH /assets/{asset_id}` - Update asset information
- `DELETE /assets/{asset_id}` - Remove asset

### CVE Monitoring

- `GET /assets/{asset_id}/vulnerabilities` - Get vulnerabilities for specific asset
- `GET /assets/{asset_id}/monitor` - Monitor single asset for CVEs
- `POST /assets/monitoring/scan-all` - Scan all user assets
- `GET /assets/monitoring/report` - Generate monitoring report

### CVE Data

- `GET /cves/fetch-recent` - Fetch and store recent CVEs from NIST NVD
- `GET /cves/recent` - List recently stored CVEs
- `GET /cves/search` - Search CVEs by product (and optional version)
- `GET /cves/vulnerabilities` - Check vulnerabilities across all your assets

### User & Health

- `GET /user` - Get the current user's profile
- `GET /health` - Service health check

### Web UI

- `GET /dashboard` - Single-page web dashboard (assets & vulnerabilities)

## Technology Stack

- **Backend**: FastAPI (Python)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Authentication**: JWT with joserfc
- **Migration**: Alembic
- **Scheduling**: APScheduler (optional background monitoring)
- **Container**: Docker & Docker Compose
- **External API**: NIST NVD API integration

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
