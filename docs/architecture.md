# warden architecture (Phase 1a)

## Module map

| Module | Role |
|---|---|
| `config` | Env-var config (`Config::from_env`, testable `from_lookup`). |
| `db` | r2d2 pool (WAL, busy_timeout, foreign keys), `rusqlite_migration` migrations, `db::repo` functions (tracked products, per-source cursor/status). `Db::call` runs closures on the blocking pool. |
| `model` | Shared types: `TrackedProduct`, `CveRecord`, `Cvss`, `KevEntry`, `EpssScore`, `Delivered`, `SourceStatus`, `FeedItem`, `FeedEnvelope`. |
| `monitors::cve` | First monitor. `normalize` (done, tested), `matcher`, `discovery`, `sync`, `feed` (stubs), `sources/{cvelist,nvd_feed,nvd_api,kev,epss}` (stubs implementing the `Source` trait, each with a typed cursor struct). |
| `http` | axum router; `/healthz` only. |
| `mcp`, `auth` | Empty placeholders for Phase 2 (rmcp, API key + OAuth AS). |

Future SSL/uptime monitors become siblings of `monitors::cve`. No shared plugin trait yet.

## Data flow (target)

KEV -> cvelist delta zips -> NVD modified feed -> EPSS, each updating its own `source_status` row. Records are upserted into `cves` + `cve_affected`, then `matcher` fills `cve_product_matches` for tracked products. `feed::get_new(consumer)` joins matches with `delivered` snapshots; `ack` writes snapshots. Fetching never consumes.

Stubs return `Err("not implemented")` (no `todo!()` panics) and are not called at startup.

## Schema

- Migration 001: `tracked_products`, `cves` (per-source CVSS columns cna/adp/nvd + `cvss_all` JSON, SSVC, fixed versions, optional `raw`), `cve_affected` (raw + normalized vendor/product, squashed product, CPE vendor/product, versions JSON), `cve_product_matches`, `kev`, `epss`, `delivered`, `source_status`.
- Migration 002: `oauth_clients`, `oauth_codes`, `oauth_tokens` (secrets stored hashed).
- Indexes: `cves(last_modified)`, `cve_affected(vendor_norm, product_squash)`, `(product_squash)`, partial `(cpe_vendor, cpe_product)`, `delivered(cve_id)`, matches by product.
- Tables are `STRICT`; timestamps are RFC 3339 UTC text.

## Research decisions

Applied: cvelist/NVD/KEV/EPSS roles and per-source cursors; normalized record precedence (stored per source, chosen in code); product shape and normalization (token + squashed forms, vendor suffix stripping, CPE unescape); delivered snapshots for `kev_added`/`cvss_changed`; thin rows for untracked CVEs.

Deviations / notes:
- `tracked_products.id` is a slug and `discovery_evidence` is not stored yet (add if discovery needs it).
- `r2d2_sqlite` 0.34 / `rusqlite` 0.39 / `rusqlite_migration` 2.5 chosen as the newest set that shares one `libsqlite3-sys` and builds on rustc 1.94 (newer releases need 1.95). `scheduled-thread-pool` is pinned to 0.2.7 in `Cargo.lock` for the same reason.
- `zip` and `flate2` are declared for Phase 1b sources and currently unused.
- `#![allow(dead_code)]` at the crate root until the stubs are wired up.
