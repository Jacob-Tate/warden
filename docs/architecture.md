# warden architecture (Phase 2a)

## Module map

| Module | Role |
|---|---|
| `config` | Env-var config (`Config::from_env`, testable `from_lookup`). |
| `db` | r2d2 pool (WAL, busy_timeout, foreign keys), `rusqlite_migration` migrations, `db::repo` functions (tracked products, per-source cursor/status). `Db::call` runs closures on the blocking pool. |
| `model` | Shared types: `TrackedProduct`, `CveRecord`, `Cvss`, `KevEntry`, `EpssScore`, `Delivered`, `SourceStatus`, `FeedItem`, `FeedEnvelope`. |
| `monitors::cve` | First monitor. `normalize`, `matcher`, `discovery`, `sources/{cvelist,nvd_feed,nvd_api,kev,epss}` (`Source` trait, typed cursors), `sync` (orchestration, scheduler, retention), `feed` (`get_new`, `ack`, `cve_detail`), `tracked` (add/update/remove/list helpers for MCP and the CLI). |
| `http` | axum router: `/healthz` (unauthenticated; only `{"status":"ok"|"stale"}`, 503 `degraded` if the DB is down) and `/mcp` behind auth, a 1 MB body limit and a 120 s request timeout. |
| `mcp` | rmcp 3.11 server: stateless streamable HTTP with JSON responses, built per request by the service factory. |
| `auth` | Bearer-token middleware, `TokenValidator` trait, API-key validator, failed-auth limiter, `hash-key`. OAuth AS arrives in Phase 2b. |

Future SSL/uptime monitors become siblings of `monitors::cve`. No shared plugin trait yet.

## Data flow

cvelist delta -> NVD modified feed -> KEV -> EPSS, each updating its own `source_status` row. Records are upserted into `cves` + `cve_affected`, then `matcher` fills `cve_product_matches` for the CVE ids that changed. `feed::get_new(consumer)` joins matches with `delivered` snapshots; `feed::ack` writes snapshots. Fetching never consumes.

## Sync (`monitors::cve::sync`)

- `Syncer::trigger_sync()` runs one pass: cvelist, nvd_feed, kev, epss (in that order), then `match_cves` over the union of every source's `changed_ids` and `new_ids` (new KEV ids included). A failing source is recorded in `source_status.last_error` and the pass continues. Overlapping runs are refused (returns `None`). One summary line per run with per-source counts/timings.
- Scheduler (`run_scheduler`): first run 20 s after startup, then every `WARDEN_SYNC_INTERVAL` (default 1h; `30m`, `3600`, ...; `WARDEN_SYNC_INTERVAL_SECS` still works; minimum 60 s).
- `nvd_api` is a catch-up only: if `nvd_feed` last succeeded more than 7 days ago (the feed window is ~8 days) the CVEs modified since then are pulled from the API (<=3 windows of 120 days). Not on normal runs, and not on a fresh install.
- New KEV entries (added within the backfill window) that match a tracked product's KEV names but whose CVE is not stored are fetched from NVD by id (at most 15 per run/add).
- Retention, once a day (`source_status` key `retention`): delete `cves` (and `cve_affected` by cascade) with `last_modified` older than `WARDEN_RETENTION_DAYS` (default 180) that match no product, were never delivered and are not in KEV.

## Feed semantics (`monitors::cve::feed`)

`get_new(db, consumer, FeedOptions{limit (50, max 200), product, min_cvss, include_acked, backfill_days})` returns `FeedEnvelope{generated_at, items, more, stale, health}`. One item per (cve, product): `cve, product (name), published, cvss, cvss_source (nvd|cna|adp), severity, kev, epss, change, summary (<=200 chars, word boundary, ellipsis), fixed_versions, source_url`. Sorted KEV first, CVSS desc (nulls last), published desc.

- CVSS choice: NVD Primary > CNA > CISA-ADP > NVD Secondary (each source's best version, v4.0 > v3.1 > v3.0 > v2.0, is stored by the sync). Severity is derived from the score.
- No acked row for the consumer: `new` (subject to backfill below). REJECTED CVEs are hidden.
- Acked row: hidden unless the CVE entered KEV since the snapshot (`kev_added`), the chosen CVSS moved by >= 1.0 or crossed a severity band or got its first score (`cvss_changed`), or it was rejected (`rejected`, once; the ack stores the state). `include_acked` also lists unchanged acked items (reported as `new`).
- `ack(consumer, cve_ids)` (every product the CVE matches) and `ack_items(consumer, items)` (exact (cve, product) pairs) upsert `delivered` with the current CVSS/KEV/state snapshot and return the row count.
- Health: per source `{last_success, last_error, stale}`; stale after cvelist 3h, nvd_feed 26h, kev 26h, epss 50h. `stale` on the envelope is true if cvelist or kev is stale (or never synced).
- `cve_detail(id)`: full record (all CVSS with sources, affected rows, KEV, EPSS, SSVC, refs, matches); unknown ids are fetched from the NVD API, stored and matched.

### Backfill policy (new products)

Adding a product matches it against every stored CVE, which would flood the agent with old news. A matched CVE without an acked row is therefore eligible only if `published >= product.created_at - WARDEN_BACKFILL_DAYS` (default 14), or it was added to KEV (`kev.date_added`) within that window. Published before the product was added (but inside the window): `change = backfill`; eligible only through KEV: `kev_added`; published after the product was added: `new`. Everything older stays hidden (and is still visible via `cve_detail`).

## Matching notes

`cve_affected.product_squash` is `squash(product_raw)`. The matcher compares vendor-stripped, edition-stripped, list-split forms (and initialisms), so migration 004 adds `cve_affected.product_keys`: those forms for the row, space-delimited, filled on insert and at startup for old rows. `rematch_product`'s prefilter queries `product_keys LIKE '% form %'` in addition to the exact/LIKE `product_squash` lookups, so it cannot miss rows the matcher would accept (`Apache HTTP Server` vs `HTTP Server`, `Fortinet FortiOS` vs `FortiOS`, `Cisco IOS and IOS XE` vs `IOS`). Vendor names are compared after `normalize_vendor` (corporate suffixes incl. `Inc`, `Labs`, `Pty`, `Software Foundation` stripped) and a row vendor that starts with a known vendor token-wise is accepted (`Moodle Pty` ~ `moodle`). A known row vendor that is not one of the product's vendors rejects the match even for vendor-less alias keys.

Discovery merges CPE rows with the same `vendor:product` across parts (`a`/`o`/`h`) into one candidate (the part with most live rows wins; the others are listed in evidence notes).

## CLI

`warden [serve]` (HTTP + scheduler), `hash-key [name]` (new API key + config line), `sync-once`, `discover <name>`, `track-add <name> [--pick N]`, `tracked`, `rematch`, `feed [--consumer X] [--limit N] [--product P] [--min-cvss S] [--include-acked] [--ack]`, `cve <id>`. Logs go to stderr; JSON results to stdout. Config comes from the environment (`.env.example`).

## MCP server (`mcp`)

Mounted at `/mcp`, stateless (`with_legacy_session_mode(false)`, `NeverSessionManager`, `with_json_response(true)`): no `Mcp-Session-Id`, no server push (so no progress notifications; long tools simply run up to their own timeout while other requests proceed). Server name `warden`, version from Cargo, `instructions` describe the get -> summarize -> ack loop and discover-before-add. Allowed hosts: `localhost`, `127.0.0.1`, `::1` and the host of `WARDEN_PUBLIC_URL`; allowed origins: the public origin, `https://claude.ai`, loopback (requests without `Origin` pass). Host/Origin failures are 403 (they are checked after auth, so only authenticated callers see them).

| Tool | Purpose |
|---|---|
| `get_new_cves {consumer?, limit?, product?, min_cvss?}` | `FeedEnvelope` for the consumer; read-only. |
| `ack {consumer?, cve_ids}` | Mark seen; returns `{acked, consumer}`. Ids validated against `^CVE-\d{4}-\d{4,}$`. |
| `cve_detail {cve_id}` | Full record; id validated before any network call. |
| `list_tracked {}` | Products with definitions and match counts. |
| `discover_product {name}` | Discovery candidates, each with an `index`; results cached 15 min per name; 60 s overall timeout. |
| `add_tracked {name, candidate_index?, overrides?}` | Uses the cached/new discovery, saves candidate N (default 0) with `overrides` (cpes, cna_names, kev_names, aliases, keywords, exclude_keywords, match_mode). If discovery fails and `overrides` has cpes/keywords, saves a manual product. Returns the saved product and initial match counts. |
| `update_tracked {id, name?, cpes?, ...}` / `remove_tracked {id}` | Edit (re-matches) / delete. |
| `sync_status {}` | Per-source health, `stale`, `running`, last run summary (in-memory, this process). |
| `trigger_sync {}` | Spawns a sync and returns; refused if a pass started < 5 min ago (scheduler runs count) or one is running. |

User mistakes (bad id, unknown product, rate limit, discovery timeout) are tool results with `isError: true` and an actionable message; only internal serialization failures are protocol errors.

## Auth (`auth`)

- `/mcp` needs `Authorization: Bearer <key>`. `WARDEN_API_KEYS` is a comma-separated list of `name:sha256hex` (no plaintext keys are accepted). `warden hash-key [name]` makes a random 32-byte key (base64url), prints it once and the config line. Validation hashes the presented token and compares against every entry in constant time (`subtle`).
- Failure: `401` with `WWW-Authenticate: Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource"`. In-memory per-peer-IP limiter: 10 failures in 5 minutes -> `429` (+ `Retry-After`) for that IP; it uses the TCP peer address (behind a reverse proxy this is the proxy's address, so a flood of bad tokens can lock out everyone for 5 minutes; fix later by trusting a forwarded header from a known proxy).
- `TokenValidator` (async `validate(&str) -> Option<Principal>`) is the extension point: `AppState.validators` is tried in order; Phase 2b adds an OAuth access-token validator beside `ApiKeyValidator`.
- Principal -> consumer: the middleware puts `Principal{name}` in the request extensions; rmcp copies the HTTP `Parts` into the MCP request context, and `get_new_cves`/`ack` read it (`Extension<Parts>`) to default `consumer` to the key name (explicit `consumer` wins; fallback `default`). Separate keys therefore have separate ack cursors.

## Schema

- Migration 001: `tracked_products`, `cves` (per-source CVSS columns cna/adp/nvd + `cvss_all` JSON, SSVC, fixed versions, optional `raw`), `cve_affected` (raw + normalized vendor/product, squashed product, CPE vendor/product, versions JSON), `cve_product_matches`, `kev`, `epss`, `delivered`, `source_status`.
- Migration 002: `oauth_clients`, `oauth_codes`, `oauth_tokens` (secrets stored hashed).
- Migration 003: per-source `fixed_cna`/`fixed_nvd`, `adp_kev_date`, `ssvc_timestamp`. Migration 004: `cve_affected.product_keys` (see Matching notes).
- Indexes: `cves(last_modified)`, `cve_affected(vendor_norm, product_squash)`, `(product_squash)`, partial `(cpe_vendor, cpe_product)`, `delivered(cve_id)`, matches by product.
- Tables are `STRICT`; timestamps are RFC 3339 UTC text.

## Research decisions

Applied: cvelist/NVD/KEV/EPSS roles and per-source cursors; normalized record precedence (stored per source, chosen in code); product shape and normalization (token + squashed forms, vendor suffix stripping, CPE unescape); delivered snapshots for `kev_added`/`cvss_changed`; thin rows for untracked CVEs.

Deviations / notes:
- `tracked_products.id` is a slug and `discovery_evidence` is not stored yet (add if discovery needs it).
- `r2d2_sqlite` 0.34 / `rusqlite` 0.39 / `rusqlite_migration` 2.5 chosen as the newest set that shares one `libsqlite3-sys` and builds on rustc 1.94 (newer releases need 1.95). `scheduled-thread-pool` is pinned to 0.2.7 in `Cargo.lock` for the same reason.
- `#![allow(dead_code)]` stays at the crate root (some model/db helpers are test-only or wait for Phase 2b).
- Discovery's CVE probe samples the newest CVEs for a CPE (count query, then a 120-day `pubStartDate` window, falling back to the last page `startIndex = total - 5`), newest first: the oldest records carry vendor `n/a` and teach no CNA names.
