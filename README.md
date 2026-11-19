# warden

A small self-hosted monitor that tells an AI agent what changed in the software you run.

The first monitor is a **CVE feed**: it watches new and changed CVEs, CISA KEV and EPSS, filters them to the products you track, and hands back a short, ranked JSON list of what's new since the last time you asked. It's exposed as an **MCP server**, so Claude (or any MCP client) can read the feed and add or remove tracked products as it goes.

SSL certificate and HTTP uptime monitors are planned for later.

## Status

The CVE sync, matching, discovery and the MCP server (API-key auth) work. OAuth for claude.ai connectors is next.

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
- **Auth:** bearer token, served over streamable HTTP behind a reverse proxy.
