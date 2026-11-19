# warden

A small self-hosted monitor that tells an AI agent what changed in the software you run.

The first monitor is a **CVE feed**: it watches new and changed CVEs, CISA KEV and EPSS, filters them to the products you track, and hands back a short, ranked JSON list of what's new since the last time you asked. It's exposed as an **MCP server**, so Claude (or any MCP client) can read the feed and add or remove tracked products as it goes.

SSL certificate and HTTP uptime monitors are planned for later.

## Status

The CVE sync, matching, discovery and the MCP server work, with API keys (Claude Code) and a built-in single-user OAuth server (claude.ai custom connectors and routines).

## Quick start

```bash
cargo build --release
./target/release/warden hash-key claude-code     # prints the key once + the config line
export WARDEN_API_KEYS=claude-code:<hash printed above>
export WARDEN_PUBLIC_URL=https://warden.example.com   # host is allowed on /mcp
./target/release/warden serve                    # listens on WARDEN_BIND (default 0.0.0.0:8080)
```

Several keys: `WARDEN_API_KEYS=claude-code:<hash>,routine:<hash>`. Each key name is that client's default `consumer`, so every client has its own "already seen" cursor.

Connect Claude Code:

```bash
claude mcp add --transport http warden https://HOST/mcp --header "Authorization: Bearer KEY"
```

Put an HTTPS reverse proxy in front (forward `Host`, do not buffer `/mcp`). `/healthz` is unauthenticated and reports only `ok` or `stale`.

## claude.ai custom connector (OAuth)

claude.ai connectors (and scheduled routines, which reuse them) cannot send a static key, so warden contains a small OAuth 2.1 authorization server for one user: you.

1. Pick a passphrase and hash it (reads stdin; hidden prompt on a terminal):

   ```bash
   ./target/release/warden hash-passphrase
   ```

   Put the printed `WARDEN_OWNER_PASSPHRASE_HASH='$argon2id$...'` in the environment. In docker compose or an `.env` read by compose, write every `$` as `$$`. Without this variable the OAuth endpoints answer 404 and only API keys work.
2. Set `WARDEN_PUBLIC_URL` to the exact public HTTPS origin (no path) and `WARDEN_TRUSTED_PROXIES` to your reverse proxy (see below).
3. In claude.ai: Settings > Connectors > Add custom connector, URL `https://HOST/mcp`. Leave client ID and secret blank: Claude registers itself (dynamic client registration). Claude opens warden's consent page; enter the passphrase. The "connection name" on that page (default `claude-ai`) becomes the consumer `oauth:<name>`, i.e. its own "already seen" cursor. Routines use the same connector, so they share that cursor.
4. Claude Code can keep using an API key (`--header`), or use OAuth (`claude mcp add --transport http warden https://HOST/mcp`, then `/mcp` login); it redirects to a loopback address.

Redirect URIs are allowlisted (`WARDEN_OAUTH_REDIRECT_ALLOW`; default `https://claude.ai/api/mcp/auth_callback` and loopback `localhost`/`127.0.0.1`/`[::1]` on any port). Access tokens last 1 hour; refresh tokens 30 days, sliding (`WARDEN_OAUTH_REFRESH_DAYS`), rotated on every use. Revoke everything by deleting rows from `oauth_tokens` or removing the connector.

Optional hardening: Anthropic's outbound ranges are `160.79.104.0/21` and `153.61.208.0/20`. You may restrict `/mcp`, `/token`, `/register` and `/.well-known/*` at the proxy to them. Do not restrict `/authorize` the same way: that page is opened by your own browser, not by Anthropic, so an allowlist of Anthropic ranges would block you. Exempt `/authorize` (or limit it to your own IP / VPN instead).

Behind a reverse proxy, set `WARDEN_TRUSTED_PROXIES` (comma-separated IPs/CIDRs of the proxy as warden sees it). Without it all clients look like the proxy to the failed-login limiters.

## Planned design

- **Language:** Rust (axum, [rmcp](https://github.com/modelcontextprotocol/rust-sdk)), SQLite, one Docker container.
- **Data sources:**
  - CVE Program cvelistV5 delta files, for new records with CNA data.
  - NVD JSON 2.0 "modified" feed, for CPEs and NVD scores.
  - NVD API 2.0, only for single-CVE lookups.
  - CISA KEV.
  - FIRST EPSS.
- **Matching:** CPE vendor:product, CNA vendor/product, and keywords.
- **MCP tools:**
  - `get_new_cves`, `ack`, `cve_detail`
  - `list_tracked`, `add_tracked`, `update_tracked`, `remove_tracked`
- **Auth:** static API keys and/or the built-in OAuth server, served over streamable HTTP behind a reverse proxy.
