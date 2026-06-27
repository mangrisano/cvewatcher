# CVE Watcher

A FastAPI-based application for monitoring and tracking CVE (Common Vulnerabilities and Exposures) vulnerabilities for your software assets.

## Overview

CVE Watcher helps organizations and developers monitor their software assets for security vulnerabilities by:

- **Asset Management**: Track your software components, versions, and CPE identifiers
- **CVE Monitoring**: Automatically monitor for new vulnerabilities affecting your assets
- **Real-time Alerts**: Get notified when new CVEs are discovered for your tracked software
- **Vulnerability Reports**: Generate detailed reports on security issues affecting your infrastructure
- **User Management**: Secure user authentication and authorization

## Features

- 🔐 **User Authentication**: Secure JWT-based authentication system
- 📦 **Asset Tracking**: Manage your software inventory with detailed metadata
- 🔍 **CVE Monitoring**: Integration with NIST NVD for real-time vulnerability data
- 📊 **Severity Filtering**: Filter vulnerabilities by severity level (Critical, High, Medium, Low)
- 📈 **Reporting**: Generate monitoring reports and vulnerability summaries
- 🎯 **Targeted Scanning**: Monitor specific assets or scan all assets at once
- 🔄 **Real-time Updates**: Automatic vulnerability detection and updates
- ⏰ **Background Monitoring**: Optional scheduler that periodically scans every asset
- 🔔 **Notifications**: Alert on newly discovered vulnerabilities (console and webhook)
- 🖥️ **Web Dashboard**: Single-page UI to manage assets and review vulnerabilities

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

CVE Watcher resolves the vulnerabilities of an asset in one of two ways,
chosen automatically per asset:

### 1. CPE lookup (precise, preferred)

When an asset declares a **CPE 2.3** identifier (e.g.
`cpe:2.3:a:f5:nginx:1.24.0`), the query is delegated to NVD's `cpeName`
filter. NVD evaluates the version ranges declared in every CVE configuration
server-side, so the result contains exactly the CVEs that affect that product
and version. Partial CPEs are padded to the full 13-component form before the
lookup. This path avoids both the keyword 100-result cap and the false
positives/negatives of free-text search.

### 2. Keyword search with local filtering (fallback)

When no CPE is known, CVE Watcher falls back to an NVD keyword search and then
filters each candidate locally to cut the noise of free-text matching:

- **Product identity** — a candidate is kept only if one of its affected-product
  CPEs matches the asset name (separator-insensitive exact match), so `nginx`
  no longer matches unrelated products such as `nginx_proxy_manager`.
- **Version range** — if the asset has a version, the candidate must declare a
  version range (or exact CPE version) that actually includes it; CVEs fixed in
  earlier releases are dropped.
- **Text fallback** — when a CVE carries no CPE data at all, the asset name (and
  version, if present) is matched against the CVE summary.

> Tip: provide a CPE for every asset you can. The CPE path is materially more
> accurate than keyword search and is the only one that reliably avoids false
> negatives.

## Background Monitoring & Notifications

The application can periodically scan every registered asset against the NIST NVD
and alert on newly discovered vulnerabilities. It is **opt-in** and configured via
environment variables (see `.env.example`):

| Variable                   | Default   | Description                                 |
| -------------------------- | --------- | ------------------------------------------- |
| `MONITOR_ENABLED`          | `false`   | Enable the background scheduler             |
| `MONITOR_INTERVAL_MINUTES` | `360`     | Minutes between scans                       |
| `NOTIFY_CONSOLE`           | `true`    | Log new findings via the application logger |
| `NOTIFY_WEBHOOK_URL`       | _(unset)_ | POST new findings as JSON to this URL       |

When enabled, a scan runs at startup and then on the configured interval; only
newly detected CVEs trigger notifications.

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

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:

```bash
git clone https://github.com/mangrisano/cvewatcher.git
cd cvewatcher
```

2. Start the application:

```bash
docker-compose up --build
```

3. Access the API:

- API: http://localhost:8000
- Interactive API docs: http://localhost:8000/docs
- Alternative docs: http://localhost:8000/redoc

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the [MIT License](LICENSE).

---
