# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
