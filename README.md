# warden

A small self-hosted monitor that tells an AI agent what changed in the software you run.

The first monitor is a **CVE feed**: it watches new and changed CVEs, CISA KEV and EPSS, filters them to the products you track, and hands back a short, ranked JSON list of what's new since the last time you asked. It's exposed as an **MCP server**, so Claude (or any MCP client) can read the feed and add or remove tracked products as it goes.

SSL certificate and HTTP uptime monitors are planned for later.

## Status

Early planning. Nothing to run yet.

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
