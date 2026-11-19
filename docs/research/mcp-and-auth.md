# warden: MCP server + auth research (Phase 0)

Researched 2026-11-19. Items marked "verified" were compiled/run locally against rmcp 3.11.0 (Rust 1.94) in a scratch crate; the code in section 1 is that crate. Not tested against real claude.ai (no public URL available here).

## Summary and recommendation

1. **rmcp is now 3.11.0** (crates.io, 2026-11-17), not the 0.x series most blog posts show. It targets **axum 0.8** (tower 0.5, http 1). Needs Rust >= 1.88. Features needed: `server`, `macros`, `transport-streamable-http-server`. The `auth` feature is client-side OAuth only; do not enable it.
2. **claude.ai connectors do not generally support a static bearer token.** Supported: OAuth 2.x (DCR or CIMD, PKCE S256 mandatory), authless, and a *beta* "request headers" static credential visible only to a limited set of orgs. Do not rely on it. Transport: Streamable HTTP (legacy SSE also accepted). Anthropic egress: `160.79.104.0/21` and `153.61.208.0/20`, IPv4 only (hostname needs a public A record).
3. **Connectors added on claude.ai ARE available to routines / cloud sessions**, reached via Anthropic's servers (no cloud-environment allowlist change; OAuth handled by the session proxy using the authorization granted in claude.ai). Servers added with `claude mcp add` locally are NOT available to routines.
4. **Claude Code CLI**: `claude mcp add --transport http warden https://... --header "Authorization: Bearer ..."`; it also does OAuth (DCR/CIMD).
5. **Recommended auth: one `Authorization: Bearer` check in front of `/mcp` that accepts two kinds of token**: (a) a static long random API key from env (Claude Code `--header`, curl, tests), and (b) OAuth access tokens from a tiny built-in single-user authorization server (claude.ai + routines). That AS is about 5 endpoints (roughly 300-400 lines Rust), hand-written; rmcp has no server-side OAuth helper and `oxide-auth` is not worth it. Authorize step gated by one owner passphrase. Implement DCR, skip CIMD. See section 4.
6. **Proxy**: set `allowed_hosts` to the public hostname (default allows only loopback and returns 403), disable proxy buffering for `/mcp`, raise read timeouts. Recommended mode: **stateless** (`with_legacy_session_mode(false)` + `NeverSessionManager` + `with_json_response(true)`; verified working, no `Mcp-Session-Id`, plain JSON responses). warden's tools are request/response so nothing is lost.

---

## 1. rmcp (Rust MCP SDK)

### Version and features
- Latest stable **3.11.0**, published 2026-11-17 (3.10.0 11-12, 3.9.0 11-05, 3.8.0 10-26, 3.7.0 10-22, 3.6.0 10-20, 3.5.1 10-05). Sources: https://crates.io/api/v1/crates/rmcp ; workspace Cargo.toml in https://github.com/modelcontextprotocol/rust-sdk (`version = "3.11.0"`, `rust-version = "1.88"`).
- Feature graph (crates/rmcp/Cargo.toml): `default = [base64, macros, server]`; `transport-streamable-http-server = [transport-streamable-http-server-session, server-side-http, transport-worker]`; `auth = [oauth2, reqwest, ...]` is the client-side OAuth helper.
- Minimal Cargo.toml (verified to build):
```toml
rmcp = { version = "3.11", features = ["server", "macros", "transport-streamable-http-server"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
tokio-util = "0.7"
serde = { version = "1", features = ["derive"] }
schemars = "1"   # rmcp 3.x uses schemars 1.x; `rmcp::schemars` re-export also available
subtle = "2"     # constant-time compare
```
- **axum**: rmcp's dev-dependency and all examples use `axum = "0.8"`. rmcp does not depend on axum; `StreamableHttpService` is a tower service mounted via `Router::nest_service("/mcp", svc)`. Examples also use `tower-http = "0.7"` for CORS.
- **Protocol versions** (`ProtocolVersion::KNOWN_VERSIONS`): 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, **2026-07-28** (`LATEST`; no `initialize` handshake, always stateless per SEP-2567). Legacy clients take the legacy path. Verified: a 2025-06-18 `initialize` is answered with `protocolVersion":"2025-06-18"`. Anthropic follows the 2025-03-26 / 2025-06-18 / 2025-11-25 specs.

### Working example (verified: compiles; 401 without token; initialize, tools/list, tools/call OK in stateless JSON mode; stateful initialize returns SSE + Mcp-Session-Id)
```rust
use std::sync::Arc;
use axum::{Router, body::Body, extract::State,
    http::{Request, StatusCode, header}, middleware::{self, Next}, response::Response};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::{local::LocalSessionManager, never::NeverSessionManager},
    },
};
use subtle::ConstantTimeEq;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetNewCvesParams {
    /// Optional consumer name; each consumer has its own ack cursor
    consumer: Option<String>,
}
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct AckParams {
    /// CVE ids to acknowledge
    ids: Vec<String>,
}

#[derive(Clone)]
struct Warden { tool_router: ToolRouter<Warden> }

#[tool_router]
impl Warden {
    fn new() -> Self { Self { tool_router: Self::tool_router() } }

    #[tool(description = "Get CVEs not yet acknowledged by this consumer",
           annotations(read_only_hint = true))]
    async fn get_new_cves(&self, Parameters(p): Parameters<GetNewCvesParams>)
        -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("consumer={:?}", p.consumer))]))
    }

    #[tool(description = "Acknowledge CVE ids")]
    async fn ack(&self, Parameters(p): Parameters<AckParams>) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("acked {}", p.ids.len()))]))
    }
}

#[tool_handler]
impl ServerHandler for Warden {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())  // reports name "rmcp"; see notes
            .with_instructions("warden CVE tracker")
    }
}

async fn bearer(State(tok): State<Arc<String>>, req: Request<Body>, next: Next)
    -> Result<Response, Response> {
    let ok = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t.as_bytes().ct_eq(tok.as_bytes()).into());
    if ok { Ok(next.run(req).await) } else {
        Err(Response::builder().status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE,
              r#"Bearer resource_metadata="https://warden.example.com/.well-known/oauth-protected-resource""#)
            .body(Body::empty()).unwrap())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ct = tokio_util::sync::CancellationToken::new();
    let cfg = StreamableHttpServerConfig::default()
        .with_allowed_hosts(["warden.example.com", "localhost:18931"])
        .with_legacy_session_mode(false)   // stateless
        .with_json_response(true)          // plain application/json when possible
        .with_cancellation_token(ct.child_token());
    let svc = StreamableHttpService::new(
        || Ok(Warden::new()),                       // factory: capture Arc<Db> here
        NeverSessionManager::default().into(),      // stateless
        cfg);
    let tok = Arc::new("secret".to_string());
    // In real code, put the bearer layer on /mcp only; keep /.well-known, /register,
    // /authorize, /token outside it.
    let app = Router::new().nest_service("/mcp", svc)
        .layer(middleware::from_fn_with_state(tok, bearer));
    let l = tokio::net::TcpListener::bind("127.0.0.1:18931").await?;
    axum::serve(l, app).await?;
    Ok(())
}
```
Stateful alternative (default config; session per client, `Mcp-Session-Id`, SSE):
```rust
let cfg = StreamableHttpServerConfig::default()            // legacy_session_mode = true by default
    .with_allowed_hosts(["warden.example.com"]);
let svc = StreamableHttpService::new(|| Ok(Warden::new()),
    LocalSessionManager::default().into(), cfg);
```
Verified stateful `initialize` response headers: `200`, `content-type: text/event-stream`, `x-accel-buffering: no`, `mcp-session-id: <uuid>`. Verified stateless: `content-type: application/json`, tools/list schema includes doc-comments as descriptions, `Option<String>` becomes `["string","null"]` and is not in `required`.

Notes:
- Typed params = `Parameters<T>` with `T: Deserialize + JsonSchema`.
- Keep a `tool_router: ToolRouter<Self>` field; `#[tool_handler]` uses it. I got a harmless `field tool_router is never read` warning.
- `annotations(read_only_hint = true)` compiled; use it for `get_new_cves`, `cve_detail`, `list_tracked`. Mark `remove_tracked` `destructive_hint`.
- `Implementation::from_build_env()` reports name **"rmcp"** (verified in the initialize result). Use `Implementation::new("warden", env!("CARGO_PKG_VERSION"))` or similar.
- The handler factory runs per session (stateful) or per request (stateless); share state (SQLite pool) via `Arc` captured by the closure.
- Structured output is supported (`examples/servers/src/structured_output.rs`), but text content is the safest for claude.ai.

### Breaking / surprising changes (crates/rmcp/CHANGELOG.md, source)
- **3.0.0-beta.1**: `StreamableHttpServerConfig::stateful_mode` renamed **`legacy_session_mode`** (builder `with_stateful_mode` -> `with_legacy_session_mode`). Most tutorials use the old name. Also tasks extension (SEP-2663), discovery (SEP-2575), cache hints, `Annotations.lastModified` now a string.
- **3.0.0-beta.5**: removed deprecated v3 APIs. **3.0.0-beta.3**: OAuth client rejects AS metadata without `issuer`.
- **2.0.0**: model types aligned to MCP 2025-11-25.
- **1.0.0-alpha**: model structs `#[non_exhaustive]`; use `::new` / `with_*` builders, not struct literals. In 3.x `get_info` returns `ServerConfig` (`ServerConfig::new(caps).with_server_info(..).with_instructions(..)`), per repo `examples/servers/src/common/counter.rs`. Older code returning `ServerInfo { .. }` will not compile.
- **1.3.0**: `StreamableHttpService` lost its default type parameter.
- Host validation added 1.4.0, Origin validation 1.6.0, stricter Origin 3.4.0, default-port matching 3.5.0. **Host validation is on by default and permits only `localhost`, `127.0.0.1`, `::1`** (verified: `Host: evil.com` -> `403 Forbidden: Host header is not allowed`). Behind a reverse proxy call `.with_allowed_hosts([public hostname])`.
- `allowed_origins` defaults to empty = Origin validation off; entries need a scheme (`https://claude.ai`); requests without Origin still pass; portless entries match any port (deprecated, use `:*`).
- Other knobs: `sse_keep_alive` (15 s), `sse_retry` (3 s), `json_response`, `max_request_body_bytes`, `session_store`, `stateless_protocol_metadata_required` (leave false; true rejects legacy clients).
- Needs graceful shutdown via `with_cancellation_token(ct.child_token())` as in `counter_streamhttp.rs`.

### Bearer middleware
See the example: `middleware::from_fn_with_state` on the router. Must return `401` plus `WWW-Authenticate: Bearer resource_metadata="..."` (verified emitted) for claude.ai to start OAuth. rmcp's `simple_auth_streamhttp.rs` does the same with a `Vec<String>` token store. Compare in constant time; for stored OAuth tokens, look up by SHA-256 hash.

---

## 2. Claude custom connectors (claude.ai)

Sources: https://claude.com/docs/connectors/building/authentication.md , https://claude.com/docs/connectors/custom/add-unlisted.md , https://claude.com/docs/connectors/building/index.md , https://claude.com/docs/connectors/building/troubleshooting.md , https://claude.com/docs/connectors/building/lazy-authentication.md , https://platform.claude.com/docs/en/api/ip-addresses

### Auth methods ("Supported authentication types")
| Type | Notes |
|---|---|
| `oauth_dcr` | OAuth 2.0 + Dynamic Client Registration (RFC 7591). Default. Claude registers a new client on every fresh connection. |
| `oauth_cimd` | OAuth 2.0 + Client ID Metadata Document. Default. Used only if AS metadata has `client_id_metadata_document_supported: true` AND `"none"` in `token_endpoint_auth_methods_supported`; otherwise Claude falls back to DCR. |
| `oauth_anthropic_creds` | Anthropic-held client; directory listings only (a custom connector never uses it). |
| `custom_connection` | Customer-entered OAuth client; needs Anthropic approval for listings. For *custom connectors* the dialog's **Advanced** section lets you enter an OAuth client ID and optional secret yourself (public client if no secret). |
| `static_headers` | **Beta, limited set of organizations.** Owner enters headers (e.g. `authorization` = `Bearer ...`, max 4; `authorization`, `x-api-key`, `x-auth-token` pre-approved, other names need Anthropic approval). Value is sent verbatim, so include `Bearer `. Owners without access do not see the "Request headers" section. Cannot be edited after adding (remove and re-add). |
| `none` | Authless ("No sign-in"), supported by default. |

Conclusion: a static bearer is not a dependable path for claude.ai. Check Add custom connector > Advanced for a "Request headers" section; if present it works with warden's static key. Plans: Free (1 custom connector), Pro, Max, Ultra, Team/Enterprise (Owner adds).

### OAuth requirements Claude enforces
- Unauthenticated MCP call must return **401** with `WWW-Authenticate: Bearer resource_metadata="https://host/.well-known/oauth-protected-resource"` (header on a 200 is ignored). If missing, Claude probes `/.well-known/oauth-protected-resource/<mcp-path>` then `/.well-known/oauth-protected-resource`.
- PRM `resource` must equal the MCP URL exactly as typed (incl. path); only the first `authorization_servers` entry is used.
- AS metadata RFC 8414 (or OIDC discovery); advertise `code_challenge_methods_supported: ["S256"]`; PKCE S256 on every request. Claude adds `offline_access` if listed in `scopes_supported`.
- Redirects: `https://claude.ai/api/mcp/auth_callback` (claude.ai, Desktop, mobile, Cowork); Claude Code uses loopback `http://localhost:<ephemeral>/callback` and `127.0.0.1`; compare loopback ignoring port. Show the redirect host on the consent screen.
- `/token` must accept `application/x-www-form-urlencoded`; `/register` is JSON. 10 s limit on discovery/registration/token, 30 s on refresh. Return `invalid_grant` for dead refresh tokens; **rotate refresh tokens** for public clients and return the new one in the same response.
- `client_credentials` grant is not supported.

### Transport, limits, network
- **Streamable HTTP** recommended; legacy HTTP+SSE still supported (URL ending `/sse`, or Advanced > Transport).
- claude.ai limits: tool result ~150,000 chars, 240 s per tool call. Claude Code: 25,000 tokens (`MAX_MCP_OUTPUT_TOKENS`), `MCP_TOOL_TIMEOUT`. Cap and paginate `get_new_cves`.
- **Egress IPs** (outbound, tool calls to external servers): `160.79.104.0/21` and `153.61.208.0/20` (IPv4; old `34.162.*` are phased out). Allowlisting only matters if your proxy/firewall restricts by source. AS endpoints are called from the same range.
- Hostname needs a public **A record** (connectors are IPv4-only; AAAA-only fails), must not resolve to a private IP (split-horizon DNS works in Claude Code/curl but breaks claude.ai). A WAF 403ing `/.well-known/*` or a proxy stripping `WWW-Authenticate` produces "Couldn't reach the MCP server".

### Routines / cloud sessions
https://code.claude.com/docs/en/routines.md (cloud scheduled tasks, "formerly routines"): connectors are "the claude.ai integrations on your account"; MCP servers added with `claude mcp add` "do not appear in the connectors list". All connected connectors are included in a new task by default. "Connectors you add to the task reach their services through Anthropic's servers, so they don't need allowlist changes." https://code.claude.com/docs/en/mcp.md: in cloud sessions a connector "is authenticated by the session's proxy, using authorization you granted in claude.ai"; re-authorize at https://claude.ai/customize/connectors. Alternative for a single-repo task: committed `.mcp.json` (then the sandbox must reach your host via Allowed domains and the secret must come from environment variables, which are visible to anyone using that environment), so the connector route is preferred.
Implication: Anthropic holds and refreshes the OAuth tokens unattended, so warden's refresh handling must be solid: long-lived sliding refresh tokens (e.g. 90 days), correct rotation, `invalid_grant` on failure.

---

## 3. Claude Code (CLI)

Source: https://code.claude.com/docs/en/mcp.md
```bash
claude mcp add --transport http warden https://warden.example.com/mcp \
  --header "Authorization: Bearer <WARDEN_API_KEY>"       # -H short form; --scope user|project|local
```
- JSON form: `"type": "http"` (alias `"streamable-http"`), `"headers": {"Authorization": "Bearer ${WARDEN_TOKEN}"}`; `${VAR}` expansion works in `.mcp.json`. A `url` with no `type` is read as stdio and skipped. `claude mcp add` does not validate credentials.
- `headersHelper` (script emitting JSON headers; 10 s timeout) for rotating tokens.
- OAuth works too: 401/403 flags the server in `/mcp`; discovery RFC 9728 then RFC 8414; DCR or CIMD auto-detected; `claude mcp login <name>` (`--no-browser`); `--client-id/--client-secret/--callback-port` for pre-registered clients. Claude Code's CIMD is https://claude.ai/oauth/claude-code-client-metadata. A configured `Authorization` header disables OAuth.
- Routines do not read `claude mcp add` servers; they use claude.ai connectors or committed `.mcp.json`.
- Claude Code tries HTTP first then falls back to SSE (v2.1.265+); SSE is deprecated.

---

## 4. Recommended auth design for warden

| Option | claude.ai + routines | Claude Code | Effort | Notes |
|---|---|---|---|---|
| A. Static bearer only | Only with beta Request headers; not dependable | Works | trivial | Fails the primary requirement. |
| B. Authless + secret path `/mcp/<random>` | Works ("No sign-in") | Works | trivial | Secret in URL: appears in proxy/access logs, Anthropic's connector config, screenshots; cannot rotate without re-adding; Anthropic and the MCP spec say not to put credentials in URLs. Stopgap only; scrub logs. |
| **C. Built-in minimal OAuth AS + static bearer** | Works, unattended refresh | Works (OAuth or `--header`) | about 5 endpoints | **Recommended.** |
| D. External IdP (Authelia, Keycloak, Authentik) | Works | Works | another service | Fine if the user already runs one. |

### Design C
`/mcp` accepts `Authorization: Bearer <t>` where `t` equals `WARDEN_API_KEY` (constant time) OR SHA-256(t) matches a non-expired row in `oauth_tokens` (SQLite). rmcp has **no server-side OAuth helper**: the `auth` feature is a client state machine (`AuthorizationManager`, `OAuthState`, DCR/CIMD client). The repo examples `complex_auth_streamhttp.rs` and `cimd_auth_streamhttp.rs` are hand-rolled demo servers (axum, in-memory maps, login form) worth cribbing from. `oxide-auth` is built around its own request/response abstractions and has no RFC 7591 / 9728 / CIMD support; hand-rolling is smaller.

Endpoints (same host as `/mcp`):
1. `GET /.well-known/oauth-protected-resource` (also serve `/.well-known/oauth-protected-resource/mcp`):
   `{"resource":"https://warden.example.com/mcp","authorization_servers":["https://warden.example.com"],"bearer_methods_supported":["header"],"scopes_supported":["warden"]}`
2. `GET /.well-known/oauth-authorization-server`:
   `{"issuer":"https://warden.example.com","authorization_endpoint":"https://warden.example.com/authorize","token_endpoint":"https://warden.example.com/token","registration_endpoint":"https://warden.example.com/register","response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"scopes_supported":["warden","offline_access"]}`
   `issuer` is mandatory. **Omit `client_id_metadata_document_supported`**: advertising it together with `"none"` makes Claude choose CIMD, which obliges you to fetch and validate client_id URLs (SSRF surface). Without it Claude uses DCR.
3. `POST /register` (JSON, RFC 7591): accept `redirect_uris`, `client_name`; require each URI to be exactly `https://claude.ai/api/mcp/auth_callback` or loopback (`http://localhost|127.0.0.1[:port]/...`); return 201 with `client_id` (random), `token_endpoint_auth_method:"none"`, `grant_types`, `response_types`. Rate-limit; prune stale clients (a new one per connection).
4. `GET/POST /authorize`: validate `client_id`, exact `redirect_uri` (loopback port-agnostic), `response_type=code`, `code_challenge` with `S256` required, `resource` (if present) equals the MCP URL. GET renders a small HTML form showing the redirect host and asking for the **owner passphrase** (`WARDEN_ADMIN_PASSWORD`; constant-time compare or argon2). POST verifies it, stores a single-use code (60 s, bound to client_id, redirect_uri, challenge), then `302 redirect_uri?code=..&state=..`. Add CSRF token, attempt rate limit, `X-Frame-Options: DENY`.
5. `POST /token` (**form-urlencoded**): `authorization_code` (verify PKCE, client_id, redirect_uri, single use) and `refresh_token` (rotate; `invalid_grant` on failure). Respond `{access_token, token_type:"Bearer", expires_in, refresh_token, scope}` with `Cache-Control: no-store`. Access token about 1 h; refresh token about 90 days sliding. Store only hashes.
6. Optional `POST /revoke`. CORS only if you test with the browser-based MCP Inspector.
Plus the 401 + `WWW-Authenticate` challenge on `/mcp`.

Security tradeoffs: the passphrase page is the only human-facing attack surface (long random passphrase, rate limit; optionally restrict `/authorize` at the proxy to your LAN/VPN since only your own browser needs it). `/mcp`, `/token`, `/register`, `/.well-known/*` must stay reachable from Anthropic's ranges. Open DCR lets anyone register a client, but a client is useless without the passphrase at `/authorize`. The static API key is full power and long-lived: 32 random bytes, env/secret storage, support two keys for rotation. Skip scope enforcement, multi-user, JWT, CIMD.

Test order: MCP Inspector (`npx @modelcontextprotocol/inspector`) against the public URL, then claude.ai Settings > Connectors > Add custom connector, then a routine with the connector enabled, then `claude mcp add --transport http ... --header`.

---

## 5. Reverse proxy gotchas, sessions, Origin

- **Buffering**: responses may be `text/event-stream` (stateful, or stateless without `json_response`). rmcp sets `x-accel-buffering: no` and `cache-control: no-cache` (verified), which nginx honors; still configure the proxy explicitly. With stateless + `json_response(true)` simple calls return plain JSON with `content-length` (verified); SSE is used only if a handler emits notifications first.
- **nginx**
```nginx
location /mcp {
    proxy_pass http://warden:8080;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;            # must be in allowed_hosts
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 3600s;               # default 60 s kills idle SSE
    proxy_send_timeout 3600s;
    gzip off;
}
```
  Do not add `location` rules that block `/.well-known/` (and pass them through to warden).
- **Caddy**: `reverse_proxy warden:8080 { flush_interval -1 }`. Host is preserved by default.
- **Traefik**: does not buffer responses by default; remove any `buffering` middleware on the MCP router; raise `respondingTimeouts` (`readTimeout`, `idleTimeout`) on the entrypoint. (Written from general knowledge, not verified in this session.)
- **Cloudflare/CDN in front**: has idle/response timeouts and may buffer; prefer DNS-only or stateless JSON; allow `160.79.104.0/21` and `153.61.208.0/20` through any WAF/bot rules.
- **Host header**: rmcp returns 403 for hosts not in `allowed_hosts` (verified). Forward the original Host and list it (`host` or `host:port`), or add the internal name if the proxy rewrites it.
- **Origin**: the MCP spec requires servers to validate `Origin` against DNS rebinding. claude.ai's server-side calls carry no Origin; browsers always do. Set `.with_allowed_origins(["https://claude.ai"])` or leave empty and rely on bearer + Host allowlist. Requests without Origin pass. No wildcard CORS on `/mcp`.
- **Mcp-Session-Id** (stateful mode only): returned on `initialize`, must be echoed on every later request; in-memory in `LocalSessionManager`, so a container restart or a second replica invalidates sessions (404, client must re-initialize). Proxies must forward `Mcp-Session-Id`, `MCP-Protocol-Version`, `Last-Event-ID`, `Authorization` and must not drop `WWW-Authenticate`. Stateless mode removes all of this; trade-off: no server-initiated messages (sampling, elicitation, progress, subscriptions), which warden does not need. In stateless mode GET and DELETE on `/mcp` are not allowed (405).
- `MCP-Protocol-Version` header: sent by clients after initialize from 2025-06-18 on; rmcp treats a missing header as 2025-03-26.
- SSE keep-alive ping every 15 s (`sse_keep_alive`), well under proxy idle timeouts.
- TLS: real cert and an A record (Anthropic connects over IPv4 only).

## Open items / caveats
- Whether the user's org has the beta "Request headers" section could not be determined from docs; check Add custom connector > Advanced. If present, the static key works there directly, but keep OAuth as the portable path.
- The DCR/PKCE flow details come from Anthropic's docs, not from a live claude.ai test.
- rmcp ships fast (3.5 to 3.11 in about 7 weeks); pin `rmcp = "~3.11"` and read the CHANGELOG on upgrades. Traefik and Cloudflare notes are from general knowledge.
- Scratch probe crate (not part of the repo): C:\Users\jacob\AppData\Local\Temp\claude\3bb8977541efb7ef\db4e442c-6b91-464c-8de5-87430ee70eeb\scratchpad\research-mcp\probe
