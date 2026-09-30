# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.10.0] - 2026-09-30

### Added

- **Change your password from the app**: a new _Change password_ item in the
  user menu (`POST /user/password`). It asks for the current password, signs
  out every other session, keeps the current one signed in, and emails the
  owner when SMTP is configured. Wrong current passwords are rate-limited.
- **Forgot password**: with SMTP and the new `PUBLIC_URL` setting, the login
  page offers _Forgot password?_ (`POST /auth/forgot-password`,
  `POST /auth/reset-password`). The emailed link is valid for 30 minutes and
  works once; only its hash is stored, the answer never reveals whether an
  account exists, and a reset signs out every session.

### Security

- **Sessions end when the password changes**: tokens now carry a session
  version, so a password change (or a reset with `utils/reset_password.py`)
  invalidates every token issued before it. Tokens of a deleted account are
  rejected at once instead of working until they expire.

## [2.9.1] - 2026-09-30

### Fixed

- **A finding could be announced twice**: a manual scan started while another
  scan of the same asset was running (for example right after an SBOM import)
  could report the same finding as new again. Scans of one asset now run one
  at a time, and a scan whose results cannot be stored sends no alerts.
- **The SBOM section of the README** still said the import does not scan.

### Security

- **Per-user limit on live lookups**: manual scans and `GET /cves/search` query
  NVD on every call, so a single user could exhaust NVD's rate limit for the
  whole instance. Each user now gets `LIVE_LOOKUPS_PER_HOUR` of them (default
  30), after which they get **429** with `Retry-After`.

### Changed

- **`GET /assets/{id}/vulnerabilities`, `GET /cves/vulnerabilities` and
  `GET /assets/monitoring/report` read the stored findings**, like the
  dashboard: they answer instantly, match the dashboard, and work while NVD is
  down (they no longer return 503).
- **The overview counts assets on the server** instead of downloading every
  asset; `GET /findings` returns `total_assets`.

## [2.9.0] - 2026-09-30

### Changed

- **Findings are read from the database**: scans store every finding with its
  score, KEV and EPSS, and the dashboard, `/findings` and the export read them
  back instead of querying NVD and OSV.dev on every page load. Pages load fast
  with thousands of findings and keep working while NVD is down. A full scan
  removes findings that no longer apply (triaged ones keep their status in case
  they return); a scan where a source did not answer removes nothing.
- **`GET /findings` is paginated**: it returns the counts plus one page
  (`limit`, default 100, max 500; `offset`), with `severity`, `status`, `q`,
  `sort` and `order` parameters, `matched`, `last_scan` and
  `unscanned_assets`. `refresh=true` now scans your assets before reading.
  API clients that expected every finding in one response must page.

### Added

- **Assets are scanned as soon as they are added**, imported from an SBOM or
  change name, version, CPE or ecosystem, in the background
  (`SCAN_NEW_ASSETS`, default on).
- **Paged vulnerability table**: 50 rows per page, with filters, search and
  sorting done by the server, and the time of the last scan.

## [2.8.0] - 2026-09-30

### Added

- **SBOM import**: `POST /assets/import-sbom` and an "Import SBOM" button in the
  dashboard create one asset per package listed in a CycloneDX or SPDX JSON
  SBOM. The ecosystem comes from each package URL (purl), so OSV.dev matching
  works right away. Packages already tracked are skipped, and the response says
  what was skipped and why. Limits: 5 MB and 2000 components per file.

### Security

- **Stronger password hashing**: passwords are hashed with PBKDF2-HMAC-SHA256
  at 600,000 iterations (OWASP's current minimum) instead of 100,000, and the
  stored hash now records its iteration count. Existing hashes keep working and
  are upgraded the next time each user logs in; nobody has to reset a password.
- **Login no longer reveals which emails are registered**: an unknown email
  now takes as long as a wrong password, since it runs the same password hash.

### Fixed

- **Login did nothing after an upgrade**: the browser could reuse a cached
  dashboard page from an older release, whose buttons the new security policy
  blocks. HTML pages are now sent with `Cache-Control: no-cache`, so the
  browser always checks for the current version.
- **The dashboard showed at most 50 assets**: it now loads every page of the
  asset list, and `GET /assets/` has a stable order so paging never repeats or
  skips assets created at the same moment.
- **NVD rate limiting was retried instantly**: NVD answers "429 Too Many
  Requests" with `Retry-After: 0`, so all three retries failed at once and
  assets lost their NVD results. Retries now wait at least the backoff (6 s,
  12 s, …), and a `Retry-After` given as a date no longer breaks the request.

### Changed

- **Packages are matched on OSV.dev only, unless they have a CPE**: an asset
  with an ecosystem and no CPE no longer guesses a CPE on NVD. OSV.dev already
  covers these packages, and the extra NVD requests made a large SBOM hit NVD's
  rate limit (5 requests every 30 s without an API key). Set a CPE on the asset
  to query NVD as well.

## [2.7.1] - 2026-09-30

### Security

- **Chat webhooks and bot tokens are encrypted at rest**: they were stored in
  plain text, so a leaked database or backup let anyone post to the users'
  Slack, Teams, Discord or Telegram channels. They are now encrypted with
  Fernet using `SECRETS_ENCRYPTION_KEY`, or a key derived from
  `JWT_SECRET_KEY` when it is not set; the upgrade encrypts the existing
  values. Keep the key out of database backups. Changing it makes the stored
  secrets unreadable: they read as not configured and must be entered again.

## [2.7.0] - 2026-09-30

### Added

- **Per-user alerts**: each user now gets the alerts on their own assets, by
  email to their account address (whenever SMTP is configured) and optionally
  on their own Slack, Microsoft Teams or Discord webhook, or Telegram bot.
  Users choose the
  minimum severity (default High), whether KEV findings always alert and
  whether to hear about escalations, from _Notifications_ in the user menu or
  via `GET/PUT /user/notifications`; `POST /user/notifications/test` sends a
  test alert. Webhook URLs must belong to the chosen service; webhook URLs and
  bot tokens are never returned by the API.
- **Escalation alerts**: a known finding raises an alert when it enters the
  CISA KEV catalog or when its severity rises (e.g. an unscored CVE rated
  Critical days later). The first scan after upgrading records the current
  state without alerting.

### Changed

- The admin email feed now also goes to every address in `ADMIN_EMAILS`, not
  only to `NOTIFY_EMAIL_TO`. Admins still receive every alert on the
  `NOTIFY_*` channels.
- Manual scans (`/assets/{id}/monitor`, `/assets/monitoring/scan-all`) now
  send alerts. They record new findings as seen, so until now the scheduler
  never alerted on findings a manual scan found first.
- Notifiers report whether delivery succeeded, and a webhook answering with an
  HTTP error is logged as a failure. Webhook URLs are no longer written to the
  logs.

### Fixed

- **Unreadable form errors in the dashboard**: a rejected login, registration
  or asset form showed "[object Object]" when the server listed validation
  errors (e.g. a password without an uppercase letter). The messages are now
  shown.
- **Login applied the password rules**: a password shorter than 8 characters
  got "Password must be at least 8 characters long" instead of "Invalid
  credentials", which revealed the policy and skipped the failed-login counter.
  It is now an ordinary wrong password (401, rate-limited).

## [2.6.2] - 2026-09-30

### Security

- **Possible stored XSS in the dashboard**: the severity of a finding and the
  triage-status chips were inserted into the page without escaping, and OSV
  severities outside the known bands were stored as-is. A crafted advisory
  could run script in the dashboard and read the tokens kept in the browser.
  The dashboard now escapes these values, and OSV severities other than
  CRITICAL/HIGH/MEDIUM/LOW fall back to the band of the CVSS score.
- **Security headers**: every response now carries `X-Content-Type-Options`,
  `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`. Every response
  except the landing page and the API docs also carries a
  `Content-Security-Policy` that allows scripts only from the app itself. The
  dashboard's inline event handlers moved into `app.js` so they still work
  under it.

## [2.6.1] - 2026-09-29

### Security

- **Admin rights through a differently-cased email**: `ADMIN_EMAILS` is
  compared case-insensitively, but registration and login compared emails
  exactly, so `ADMIN@example.com` could register next to `admin@example.com`
  and be treated as an admin. Emails now identify an account regardless of
  case: a case variant of an existing email can't register, new emails are
  stored lowercased, and logging in with any casing gets a token for the
  stored email. Existing accounts are unchanged.
- **Logout could revoke another user's refresh token**: a refresh token passed
  to `/auth/logout` is now revoked only if it belongs to the caller.

### Changed

- The Compose `db` service no longer publishes port 5432 on the host, so the
  stack starts even when a local PostgreSQL already uses it. The app reaches
  the database over the Compose network; to inspect it, use
  `docker exec -it cvewatcher_db psql -U <user> <database>`.

## [2.6.0] - 2026-09-29

### Security

- **Refresh tokens are now rotated**: `/auth/refresh` revokes the refresh
  token it receives and returns a new `refresh_token` next to the access token.
  Previously the same refresh token could mint access tokens for its whole
  7-day lifetime, even if stolen. API clients must store the new token; the
  dashboard does, and a tab that loses the race with another tab reuses the
  pair that tab stored instead of logging out.
- **`/cves/recent` exposed other users' findings**: it listed the shared
  `cves` table, which the monitoring of every user's assets fills, so anyone
  could infer which CVEs affect other tenants. It now returns only CVEs linked
  to the caller's own assets.
- **Any user could trigger `/cves/fetch-recent`**, a bulk NVD download (up to
  30 days, thousands of CVEs) written to the shared table. It is now limited
  to the emails listed in the new `ADMIN_EMAILS` setting (empty by default,
  i.e. nobody).
- **Docker image hardening**: a `.dockerignore` keeps `.env` (JWT secret, SMTP
  password), `.venv`, `.git` and local databases out of locally built images
  (a local build used to copy `.env` into the image); the app runs as an
  unprivileged `cvewatcher` user instead of root; compilers live only in a
  build stage, so the image drops from ~850 MB to ~480 MB. The compose file
  binds Postgres to `127.0.0.1` instead of every interface.

## [2.5.0] - 2026-09-29

### Changed

- **Configuration is validated at startup**: every environment variable is now
  declared once, with its type and default, in `app/config.py`
  (`pydantic-settings`, new dependency). A malformed value such as
  `MONITOR_ENABLED=maybe`, `NVD_MAX_CONCURRENCY=0` or a non-numeric interval
  now stops the app with a clear error instead of being silently read as
  `false`/ignored. Empty variables still mean "use the default".

### Fixed

- **`GET /assets/monitoring/report` listed unrelated CVEs**: it ran its own
  NVD keyword search with no relevance or version filtering, ignored CPEs and
  OSV, and returned HTTP 200 with an `error` field when something failed. It
  now uses the same engine as `/findings` (CPE-aware, version-filtered, all
  sources, KEV/EPSS and triage status on each entry), keeps one entry per CVE,
  and fails with a proper 503/500. Entries carry `relevance_reason` instead of
  `matched_query`.
- **`days` was ignored for OSV advisories**: OSV has no date filter, so
  `/findings?days=N`, `/assets/{id}/vulnerabilities?days=N` and the monitoring
  report returned every OSV advisory ever published for the package (e.g. 63
  instead of 8 for django 3.2.0 over 120 days). OSV findings are now filtered
  on their publication date whenever a window is requested.

## [2.4.0] - 2026-09-29

### Added

- **Per-IP login limit** (`LOGIN_IP_MAX_ATTEMPTS`, default 30 failures per
  `LOGIN_WINDOW_SECONDS`) on top of the per email+IP one, so a single source
  can no longer try one password against thousands of accounts. A successful
  login does not reset it.
- **Reverse-proxy note**: README and `.env.example` document
  `FORWARDED_ALLOW_IPS`, without which every client behind a proxy shares the
  proxy's IP and therefore one rate limit.

### Security

- **Refresh tokens were accepted as access tokens**: any endpoint took a
  7-day refresh token as a bearer token. Access tokens now carry
  `type: "access"` and anything else is rejected (tokens issued before this
  change, which have no `type`, stay valid until they expire).
- **`JWT_SECRET_KEY` must now be at least 32 bytes** (RFC 7518 §3.2); a
  shorter secret stops the app at startup. Check your `.env` before upgrading.
- **`PATCH /assets/{id}/vulnerabilities/{cve_id}` accepted any string**, which
  was stored in the shared `cves` table and shown to every user by
  `/cves/recent`. The id must now look like a CVE or OSV id (max 20 chars).
- **A Redis outage could let revoked tokens through**: a worker that could not
  reach Redis at startup silently used the database blocklist forever, which
  does not see revocations stored in Redis. With `REDIS_URL` set, Redis is now
  the only backend: when it is unreachable authenticated requests get 503
  (fail closed), and the client reconnects on its own once it is back.

### Fixed

- **The app crashed on startup when `DATABASE_URL` was unset**: the engine
  defaulted to SQLite but `init_schema()` took the Alembic path with no URL.
  It now follows the engine's dialect and passes the same URL to Alembic
  (with `%` escaped, so URL-encoded passwords work).
- **Findings without a severity (e.g. OSV advisories without CVSS) crashed**
  the severity filter (HTTP 500) and the scheduled monitoring cycle; the
  failed cycle had already stored the CVEs, so their notifications were lost.
- **`days` above 120 silently returned no vulnerabilities**: NVD rejects
  wider date windows with a 404, which was read as "no results". `days` is now
  capped at 120 (422 above) on `/findings`, `/findings/export`,
  `/assets/{id}/vulnerabilities` and `/assets/monitoring/report`.
- **`PATCH /assets/{id}` cleared every field not sent** and allowed
  duplicates. It is now a partial update (`null`/empty clears an optional
  field) and rejects a name/version already used by another asset.
- **Changing an asset's name, version, CPE or ecosystem kept the old
  findings**, so digests and metrics still reported CVEs of the previous
  version. Untriaged (`open`) findings are now dropped on such a change and
  the next monitoring cycle re-links those that still apply; triaged ones keep
  their status and notes.
- **A slow NVD froze the whole server**: `/cves/fetch-recent` and
  `/cves/search` called NVD synchronously (retries included, with
  `time.sleep`) inside `async` routes, blocking the event loop for every user;
  the other lookups held a threadpool thread per waiting request, which also
  serves authentication. All outbound HTTP (NVD, OSV, CISA KEV, FIRST EPSS,
  webhook/Slack notifiers) is now async; SMTP runs in a worker thread.
- **CVEs not yet scored by NVD were reported as LOW (score 0.0)**, hiding
  freshly published critical issues. They now have no severity/score and show
  as `UNKNOWN`.
- **NVD results were silently capped at 2000**: CPE lookups and
  `/cves/fetch-recent` read only the first page (e.g. `linux_kernel` has over
  19,000 CVEs). They now follow `totalResults` up to 20 pages, pausing 6s
  between pages without an API key, and log a warning if still truncated.
- **The login/registration rate limiter leaked memory**: every lookup created
  a key that was never removed (50,000 logins with distinct emails left 50,000
  entries). Lookups no longer create keys, empty keys are dropped and expired
  ones are swept periodically.
- **The database token blocklist was never pruned** (`purge_expired_tokens`
  had no caller), and two simultaneous logouts of the same token could fail
  with a 500. Expired rows are now removed on every revocation and a duplicate
  revocation is ignored.
- **Auto-running Alembic migrations was silently killing app logging**:
  `alembic/env.py` calls `fileConfig()` when the Alembic `Config` has a config
  file attached, and `fileConfig()` defaults to `disable_existing_loggers=True`
  — disabling every logger not declared in `alembic.ini` (i.e. everything but
  `root`/`sqlalchemy`/`alembic`), including `app.main` and, critically,
  `uvicorn.access`. Since 2.3.1 runs migrations in-process on startup, this
  meant HTTP access logs (and any `app.*` log call) silently stopped appearing
  after the first request, with no error. `init_schema()` now builds the
  Alembic `Config` without a config file (setting `script_location` directly)
  so `fileConfig()` never runs.

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
