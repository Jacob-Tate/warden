# warden architecture (Phase 2b)

## Module map

| Module | Role |
|---|---|
| `config` | Env-var config (`Config::from_env`, testable `from_lookup`). |
| `db` | r2d2 pool (WAL, busy_timeout, foreign keys), `rusqlite_migration` migrations, `db::repo` functions (tracked products, per-source cursor/status). `Db::call` runs closures on the blocking pool. |
| `model` | Shared types: `TrackedProduct`, `CveRecord`, `Cvss`, `KevEntry`, `EpssScore`, `Delivered`, `SourceStatus`, `FeedItem`, `FeedEnvelope`. |
| `monitors::cve` | First monitor. `normalize`, `matcher`, `discovery`, `sources/{cvelist,nvd_feed,nvd_api,kev,epss}` (`Source` trait, typed cursors), `sync` (orchestration, scheduler, retention), `feed` (`get_new`, `ack`, `cve_detail`), `tracked` (add/update/remove/list helpers for MCP and the CLI). |
| `http` | axum router: `/healthz` (unauthenticated; plus the OAuth routes when enabled; only `{"status":"ok"|"stale"}`, 503 `degraded` if the DB is down) and `/mcp` behind auth, a 1 MB body limit and a 120 s request timeout. |
| `mcp` | rmcp 3.11 server: stateless streamable HTTP with JSON responses, built per request by the service factory. |
| `auth` | Bearer-token middleware, `TokenValidator` trait, API-key validator, failed-auth limiter, client-IP resolution (`WARDEN_TRUSTED_PROXIES`), `hash-key`. |
| `oauth` | Single-user OAuth 2.1 authorization server (metadata, DCR, authorize/consent, token, revoke), `OAuthValidator`, passphrase and registration limiters, `hash-passphrase`. |

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

`warden [serve]` (HTTP + scheduler), `hash-key [name]` (new API key + config line), `hash-passphrase` (owner passphrase hash from stdin), `sync-once`, `discover <name>`, `track-add <name> [--pick N]`, `tracked`, `rematch`, `feed [--consumer X] [--limit N] [--product P] [--min-cvss S] [--include-acked] [--ack]`, `cve <id>`. Logs go to stderr; JSON results to stdout. Config comes from the environment (`.env.example`).

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
- Failure: `401` with `WWW-Authenticate: Bearer resource_metadata="<public_url>/.well-known/oauth-protected-resource"`; when a token was presented but rejected the challenge also carries `error="invalid_token"`. Unknown paths stay 404 (auth is a `route_layer` on `/mcp`).
- Failed-auth limiter: in-memory, per client IP, 10 failures in 5 minutes -> `429` (+ `Retry-After`). Only requests that present a bad token count; requests with no credentials do not, and a request with a valid token is always served, even from a blocked address (tokens are 256-bit random, so this gives a guesser nothing).
- Client IP (`auth::resolve_client_ip`, set on every request by `client_ip_layer`): the TCP peer, unless the peer is inside `WARDEN_TRUSTED_PROXIES` (IPs/CIDRs). Then the hop chain from `X-Forwarded-For` (else `Forwarded`, else `X-Real-IP`) is walked from the right, skipping trusted proxies; the first untrusted hop is the client. An unparsable hop, or a chain made only of trusted hops, falls back to the peer (never to a spoofable left-most value). Headers from an untrusted peer are ignored.
- `TokenValidator` (async `validate(&str) -> Option<Principal>`) is the extension point: `AppState.validators` is tried in order; `OAuthValidator` sits beside `ApiKeyValidator` when OAuth is enabled.
- Principal -> consumer: the middleware puts `Principal{name}` in the request extensions; rmcp copies the HTTP `Parts` into the MCP request context, and `get_new_cves`/`ack` read it (`Extension<Parts>`) to default `consumer` to the key name (explicit `consumer` wins; fallback `default`). Separate keys therefore have separate ack cursors.

## OAuth authorization server (`oauth`)

Enabled only when `WARDEN_OWNER_PASSPHRASE_HASH` (argon2id PHC string, made by `warden hash-passphrase`) is set; otherwise the routes do not exist (404) and a startup log line says so. An invalid hash fails startup.

| Endpoint | Notes |
|---|---|
| `GET /.well-known/oauth-protected-resource` (+ `/mcp` suffix) | RFC 9728: `resource` = `<public>/mcp`, `authorization_servers` = [`<public>`], `bearer_methods_supported`, `scopes_supported`. |
| `GET /.well-known/oauth-authorization-server` (+ `openid-configuration` alias) | RFC 8414: issuer, authorize/token/register/revoke endpoints, `code`, `authorization_code`+`refresh_token`, `S256`, auth method `none`, `authorization_response_iss_parameter_supported` (RFC 9207). `client_id_metadata_document_supported` is omitted on purpose (CIMD would mean fetching client-supplied URLs). |
| `POST /register` | RFC 7591 JSON. 1-5 `redirect_uris`, each https (or http on loopback) and in `WARDEN_OAUTH_REDIRECT_ALLOW`. Always a public client (`none`). Limits: 10/hour per IP, 100/hour global, 50 clients; when full, never-authorized clients are evicted oldest first (clients holding tokens are protected, so a registration flood cannot displace the owner); clients unused for 30 days are pruned. |
| `GET /authorize` | Validates client, `redirect_uri` (exact; loopback ignores the port), `response_type=code`, PKCE `S256` (43-char challenge), `resource` (if sent, must equal `<public>/mcp`). Bad client/redirect: error page, never a redirect. Other errors redirect with `error`, `state`, `iss`. Renders a self-contained consent page (CSP, `X-Frame-Options: DENY`, no-store) showing client name and redirect host, a passphrase field and a connection-name field. |
| `POST /authorize` | Double-submit CSRF cookie (`warden_csrf`, HttpOnly, SameSite=Strict) checked first; request re-validated; Deny redirects `access_denied`; passphrase checked (argon2 on the blocking pool); success stores a code and 302s to `redirect_uri?code&state&iss`. |
| `POST /token` | form-encoded. `authorization_code` (PKCE, client, redirect, resource) and `refresh_token`. `Cache-Control: no-store`; errors are OAuth JSON (`invalid_request|invalid_client|invalid_grant|invalid_target|unsupported_grant_type`, HTTP 400). |
| `POST /revoke` | RFC 7009; revokes the presented token's whole family; always 200. |

Tokens and lifetimes: code 60 s, single use; access token 1 h; refresh token 30 days (`WARDEN_OAUTH_REFRESH_DAYS`), sliding (each rotation issues a fresh 30 days). All are 32 random bytes (base64url); only SHA-256 hashes are stored. Expiry is evaluated by SQLite's clock. A code is burned by any exchange attempt; replaying a used code revokes every token issued from it. Each refresh exchange issues a new pair, marks the old refresh token rotated and revokes the family's older access tokens; presenting a rotated refresh token revokes the whole family. Tokens are bound to the resource; `OAuthValidator` only accepts live, unrevoked access tokens whose resource equals `<public>/mcp`.

Principal / consumer: the consent page's connection name (default `claude-ai` for Anthropic callbacks, else the sanitized client name or `client-<id>`; `[A-Za-z0-9._-]{1,48}`) is stored on the code and tokens; the principal is `oauth:<name>`, so it defaults the MCP `consumer`. Clients that share a name share a cursor.

Wrong-passphrase limiter (in memory, per client IP): 3 free failures, then locks of 10 s, 20 s, 40 s ... capped at 15 min; 30 failures from anywhere in 15 minutes lock the page for everyone until the window drains. Refused attempts still return 429 for the correct passphrase. CSRF/validation failures do not count.

Maintenance: the daily prune also deletes codes/tokens expired for over a day and stale clients (`oauth::cleanup`).

Threat notes:
- The passphrase page is the only human-facing attack surface; use a long passphrase and consider restricting `/authorize` at the proxy to your own IP/VPN. Do not restrict `/authorize` to Anthropic's egress ranges (160.79.104.0/21, 153.61.208.0/20): the owner's browser, not Anthropic, loads it. Those ranges may be required for `/mcp`, `/token`, `/register`, `/.well-known/*` as optional extra hardening.
- Open registration lets anyone create client rows, but a client is useless without the passphrase at `/authorize`; the redirect allowlist stops an attacker-registered client from receiving codes elsewhere.
- A trusted-proxy misconfiguration (proxy not listed) makes every client share the proxy address; listing a non-proxy lets that peer choose its identity.
- Loopback redirects are inherently claimable by any local process; the consent page warns. Passphrase-guessing and token-guessing are bounded by the limiters and 256-bit tokens respectively.
- No CORS headers (browser-based Inspector will not work against the OAuth endpoints), no scope enforcement (one scope, `warden`), no CIMD, no confidential clients.

## Schema

- Migration 001: `tracked_products`, `cves` (per-source CVSS columns cna/adp/nvd + `cvss_all` JSON, SSVC, fixed versions, optional `raw`), `cve_affected` (raw + normalized vendor/product, squashed product, CPE vendor/product, versions JSON), `cve_product_matches`, `kev`, `epss`, `delivered`, `source_status`.
- Migration 002/005: `oauth_clients`, `oauth_codes`, `oauth_tokens` (secrets stored hashed); 005 recreates them with resource, consumer label, token family, rotation and last-use columns.
- Migration 003: per-source `fixed_cna`/`fixed_nvd`, `adp_kev_date`, `ssvc_timestamp`. Migration 004: `cve_affected.product_keys` (see Matching notes).
- Indexes: `cves(last_modified)`, `cve_affected(vendor_norm, product_squash)`, `(product_squash)`, partial `(cpe_vendor, cpe_product)`, `delivered(cve_id)`, matches by product.
- Tables are `STRICT`; timestamps are RFC 3339 UTC text.

## Research decisions

Applied: cvelist/NVD/KEV/EPSS roles and per-source cursors; normalized record precedence (stored per source, chosen in code); product shape and normalization (token + squashed forms, vendor suffix stripping, CPE unescape); delivered snapshots for `kev_added`/`cvss_changed`; thin rows for untracked CVEs.

Deviations / notes:
- `tracked_products.id` is a slug and `discovery_evidence` is not stored yet (add if discovery needs it).
- `r2d2_sqlite` 0.34 / `rusqlite` 0.39 / `rusqlite_migration` 2.5 chosen as the newest set that shares one `libsqlite3-sys` and builds on rustc 1.94 (newer releases need 1.95). `scheduled-thread-pool` is pinned to 0.2.7 in `Cargo.lock` for the same reason.
- `#![allow(dead_code)]` stays at the crate root (some model/db helpers are test-only).
- Discovery's CVE probe samples the newest CVEs for a CPE (count query, then a 120-day `pubStartDate` window, falling back to the last page `startIndex = total - 5`), newest first: the oldest records carry vendor `n/a` and teach no CNA names.
