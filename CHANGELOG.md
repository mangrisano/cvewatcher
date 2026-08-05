# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.1] - 2026-08-05

### Fixed

- **Alembic migrations now run automatically on startup against Postgres**
  (`app/database/init_schema`), instead of relying on a commented-out
  `RUN alembic upgrade head` in the Dockerfile that never executed. Upgrading
  an existing deployment to a version that changes the schema no longer
  requires manually running migrations — they apply on the next restart.
  SQLite (used for local/dev/test runs) is unaffected: Alembic's migrations
  use Postgres-specific types, so it keeps using `create_all()`.

## [2.3.0] - 2026-08-05

### Added

- **Registration gating & rate limiting**: sign-up is closed by default once the
  first account exists (`REGISTRATION_ENABLED` opts back in), and
  `POST /auth/register` is now rate-limited per IP (`REGISTER_MAX_ATTEMPTS`,
  `REGISTER_WINDOW_SECONDS`). `GET /auth/registration-status` lets the UI hide
  the sign-up option when it's closed. The dashboard login card can toggle
  between sign-in and registration.
- **Silent session refresh**: the dashboard now exchanges the stored refresh
  token via `POST /auth/refresh` on a 401 instead of forcing a re-login, with
  concurrent requests sharing a single in-flight refresh. Logout revokes both
  the access and refresh tokens.
- **Rebranded public landing page**: the marketing page at `/` now uses the
  project's actual logo mark/wordmark (matching the dashboard sidebar) instead
  of a generic icon, and its color palette (hero gradient, buttons, links) is
  aligned with the app's navy/cyan brand instead of a generic blue/purple
  theme.

## [2.2.0] - 2026-08-05

### Added

- **OSV.dev findings now carry severity and score**: the CVSS vector returned by
  OSV.dev is parsed (via the `cvss` library) into a numeric base score and a
  severity band, so OSV findings are no longer scoreless/`UNKNOWN` when a vector
  is available. When the same CVE appears more than once across sources, the
  merge keeps the record that carries severity/score.
- **Redesigned dashboard**: a new single-page UI (sidebar with Overview /
  Assets / Vulnerabilities sections, dark & light themes, user menu) served at
  `/dashboard` from static assets under `app/static`. It surfaces the security
  posture (findings by severity/status, KEV), full asset management with an
  **ecosystem** field (enables OSV.dev), and a global **Vulnerabilities** table
  with inline **triage status** (persisted via `PATCH`), severity/KEV/EPSS
  badges, text search, sortable columns, filtering, **force rescan** (cache
  bypass) and CSV/JSON export.

## [2.1.0] - 2026-08-05

### Added

- **Finding triage**: mark a per-asset CVE finding as `open`, `acknowledged`,
  `fixed`, `false_positive` or `accepted_risk` (with optional notes) via
  `PATCH /assets/{asset_id}/vulnerabilities/{cve_id}`. Every finding now carries
  its `status`, persisted in the `asset_cves` association.
- **Global findings view**: `GET /findings` returns a cross-asset summary
  (total, KEV count, counts by severity and by status) plus the findings; and
  `GET /findings/export?format=csv|json` downloads them. Suppressed findings
  (`fixed` / `false_positive` / `accepted_risk`) are hidden unless
  `include_suppressed=true`.
- **OSV.dev as a secondary source**: an asset can declare an `ecosystem` (PyPI,
  npm, Go, Maven, …); when set, OSV.dev is queried alongside NVD and merged,
  greatly improving coverage for language-package dependencies.
- **Prometheus metrics** at `GET /metrics` — aggregate assets and findings by
  severity and triage status (no live NVD calls).
- **Scheduled email digest** (`DIGEST_ENABLED`, `DIGEST_INTERVAL_MINUTES`): a
  periodic per-user summary of active findings, emailed to each user.

## [2.0.0] - 2026-08-05

### Changed

- **BREAKING:** `GET /assets/{id}/vulnerabilities` now defaults `days` to `0`
  (all time) instead of `30`, matching `GET /cves/vulnerabilities` and the
  documented behaviour; the old default silently hid CVEs older than 30 days.
- Unified the vulnerability finding schema: `GET /cves/vulnerabilities` and
  `GET /assets/{id}/vulnerabilities` now return the same typed
  `VulnerabilityResponse` (adds `cve_url`, `modified_date`, `relevance_reason`),
  and the asset endpoint declares a response model so it appears in the OpenAPI
  schema.
- CVE links now point to `https://www.cve.org/CVERecord?id=...` instead of the
  legacy MITRE cgi-bin URL.

### Added

- `days` is now validated (`>= 0`) on `GET /assets/{id}/vulnerabilities`.

## [1.0.0] - 2026-08-05

### Changed

- **BREAKING:** the minimum supported Python is now 3.13 (dropped 3.12). Docker
  images are built on `python:3.13-slim` and CI runs on 3.13 only.

## [0.7.0] - 2026-08-05

### Added

- **Threat-intelligence enrichment** for every finding: a `kev` boolean from the
  CISA Known Exploited Vulnerabilities catalog (actively exploited in the wild)
  and an `epss` exploit-probability score from FIRST.org. Both feeds are cached
  in-process and best-effort — a network failure degrades gracefully. KEV
  findings are ranked first, then by severity, then by EPSS. Disable with
  `ENRICH_ENABLED=false`.
- **Slack notifier** (`NOTIFY_SLACK_WEBHOOK_URL`) posting a formatted message to
  an incoming webhook.
- **Email notifier** (`NOTIFY_EMAIL_*`) sending findings over SMTP.
- Web dashboard now shows **KEV** and **EPSS** columns for each finding.

### Changed

- `GET /cves/vulnerabilities` now uses the same precise, CPE-aware,
  version-filtered and KEV/EPSS-enriched matching engine as
  `GET /assets/{id}/vulnerabilities`, instead of the old keyword-only search
  (which was capped at 100 results and did no version filtering). Its response
  now includes `kev` and `epss`.
- **Faster lookups**: when an asset resolves to several vendor CPEs, the NVD
  searches now run concurrently instead of sequentially, and NVD search results
  are cached in-process for a short TTL (`NVD_CACHE_TTL_SECONDS`, default 600s)
  so repeated identical queries (e.g. re-opening an asset or changing the
  dashboard severity filter) no longer re-hit the API. Scheduled background
  monitoring bypasses the read cache so newly published CVEs are never missed.
- Added database indexes on `assets.user_email` (used by every asset query) and
  `cves.publish_date` (used to order `/cves/recent`), avoiding full scans.
- `GET /cves/vulnerabilities` now looks up a user's assets concurrently instead
  of one at a time. A per-request semaphore bounds total NVD concurrency
  (`NVD_MAX_CONCURRENCY`, default 3 without an API key and 10 with one) so the
  fan-out across assets and CPEs never bursts past NVD's rate limit.

### Fixed

- Periodic monitoring no longer scans the entire `cves` table for every asset:
  the "already seen" lookup is restricted to the CVEs just found, so a scan cost
  no longer grows with the total number of stored CVEs.
- Assets without a version now resolve correctly: NVD's exact `cpeName` filter
  returns 404 for a wildcard version, so versionless CPEs are queried with
  `virtualMatchString` instead.
- An NVD `404` is treated as "no results" rather than a service outage, so a
  lookup no longer misreports as HTTP 503 ("NVD unavailable").

### Removed

- Dead, unused `scan_for_new_cves_since` service method, which also queried
  assets across all users without per-user scoping.

### Security

- API error responses no longer echo internal exception details to the client;
  the exception is logged server-side and a generic message is returned.
- Fixed a cross-tenant data leak: `GET /cves/recent` could expose other users'
  email addresses and asset names, which the periodic monitor had stored inside
  the shared `cves.affected_products` column. Per-asset CVE links now live in a
  dedicated `asset_cves` association table, the shared CVE rows no longer carry
  tenant data, and a migration backfills the association and scrubs the existing
  rows. The endpoint also filters out any legacy tracking entries defensively.
